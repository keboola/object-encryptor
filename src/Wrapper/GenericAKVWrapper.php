<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Keboola\AzureKeyVaultClient\Authentication\AuthenticatorFactory;
use Keboola\AzureKeyVaultClient\Client;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Keboola\AzureKeyVaultClient\Requests\SecretAttributes;
use Keboola\AzureKeyVaultClient\Requests\SetSecretRequest;
use Keboola\AzureKeyVaultClient\Responses\SecretBundle;
use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Temporary\CallbackRetryPolicy;
use Keboola\ObjectEncryptor\Temporary\TransClient;
use Keboola\ObjectEncryptor\Temporary\TransClientNotAvailableException;
use Psr\Log\NullLogger;
use Retry\BackOff\ExponentialBackOffPolicy;
use Retry\Policy\RetryPolicyInterface;
use Retry\Policy\SimpleRetryPolicy;
use Retry\RetryProxy;
use Throwable;

/**
 * @internal Use ObjectEncryptor
 */
class GenericAKVWrapper implements CryptoWrapperInterface
{
    // internal indexes in cipher structures
    private const METADATA_INDEX = 0;
    private const KEY_INDEX = 1;
    private const PAYLOAD_INDEX = 2;
    private const SECRET_NAME = 3;
    private const SECRET_VERSION = 4;

    private array $metadata = [];
    private string $keyVaultURL;
    private ?Client $client = null;

    private TransClient|false|null $transClient = null;
    private ?string $encryptorId = null;

    public function __construct(EncryptorOptions $encryptorOptions)
    {
        // there is no way to pass backOffMaxTries option to the Azure Key Vault client. Yet.
        $this->keyVaultURL = (string) $encryptorOptions->getAkvUrl();
        if (empty($this->keyVaultURL)) {
            throw new ApplicationException('Cipher key settings are invalid.');
        }

        $this->encryptorId = $encryptorOptions->getEncryptorId();
    }

    public function getClient(): Client
    {
        if ($this->client === null) {
            $this->client = new Client(
                new GuzzleClientFactory(new NullLogger()),
                new AuthenticatorFactory(),
                $this->keyVaultURL,
            );
        }
        return $this->client;
    }

    public function getTransClient(): ?TransClient
    {
        if ($this->transClient === null) {
            try {
                $this->transClient = new TransClient(
                    new GuzzleClientFactory(new NullLogger()),
                    $this->encryptorId,
                );
            } catch (TransClientNotAvailableException) {
                $this->transClient = false;
            }
        }

        return $this->transClient ?: null;
    }

    private static function getTransStackId(): ?string
    {
        return (string) getenv('TRANS_ENCRYPTOR_STACK_ID') ?: null;
    }

    private function getRetryProxy(?RetryPolicyInterface $retryPolicy = null): RetryProxy
    {
        $retryPolicy ??= new SimpleRetryPolicy(3);
        $backOffPolicy = new ExponentialBackOffPolicy(1000);
        return new RetryProxy($retryPolicy, $backOffPolicy);
    }

    public function setMetadataValue(string $key, string $value): void
    {
        $this->metadata[$key] = $value;
    }

    protected function getMetadataValue(string $key): ?string
    {
        return $this->metadata[$key] ?? null;
    }

    /**
     * @param mixed $data
     */
    private function encode($data): string
    {
        return base64_encode((string) gzcompress(serialize($data)));
    }

    /**
     * @return mixed
     * @throws UserException
     */
    private function decode(string $data)
    {
        try {
            return @unserialize((string) gzuncompress((string) base64_decode($data)));
        } catch (Throwable $e) {
            throw new UserException('Deciphering failed.', 0, $e);
        }
    }

    /**
     * Validate internal state
     * @throws ApplicationException
     */
    protected function validateState(): void
    {
    }

    public function encrypt(?string $data): string
    {
        $this->validateState();
        try {
            $key = Key::createNewRandomKey();
            $context = $this->encode([
                self::METADATA_INDEX => $this->metadata,
                self::KEY_INDEX => $key->saveToAsciiSafeString(),
            ]);
            $secret = $this->getRetryProxy()->call(function () use ($context) {
                return $this->getClient()->setSecret(
                    new SetSecretRequest($context, new SecretAttributes()),
                    uniqid('gen-encryptor'),
                );
            });
            /** @var SecretBundle $secret */
            return $this->encode([
                self::PAYLOAD_INDEX => Crypto::encrypt((string) $data, $key, true),
                self::SECRET_NAME => $secret->getName(),
                self::SECRET_VERSION => $secret->getVersion(),
            ]);
        } catch (Throwable $e) {
            throw new ApplicationException('Ciphering failed: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }

    private function verifyMetadata(array $cipherMetadata, array $localMetadata): void
    {
        foreach ($cipherMetadata as $key => $value) {
            if (empty($localMetadata[$key]) || ($value !== $localMetadata[$key])) {
                throw new UserException('Deciphering failed.');
            }
        }
    }

    public function decrypt(string $encryptedData): string
    {
        $this->validateState();
        $encrypted = $this->decode($encryptedData);
        if (!is_array($encrypted) || count($encrypted) !== 3 || empty($encrypted[self::PAYLOAD_INDEX]) ||
            empty($encrypted[self::SECRET_NAME]) || empty($encrypted[self::SECRET_VERSION])
        ) {
            throw new UserException('Deciphering failed.');
        }

        $metadata = $this->metadata;
        $doBackfill = false;

        // try retrieve secret from trans AKV
        if ($this->getTransClient() !== null) {
            // do not retry if trans AKV response is 404
            $retryDecider = fn($e) => !$e instanceof ClientException || $e->getCode() !== 404;
            $retryPolicy = new CallbackRetryPolicy($retryDecider);
            try {
                $decryptedContext = $this->getRetryProxy($retryPolicy)->call(function () use ($encrypted) {
                    return $this->getTransClient()
                        ?->getSecret($encrypted[self::SECRET_NAME])
                        ->getValue();
                });
                if ($decryptedContext !== null && isset($this->metadata['stackId']) && self::getTransStackId()) {
                    $metadata['stackId'] = self::getTransStackId();
                }
            } catch (ClientException $e) {
                if ($e->getCode() === 404) {
                    $doBackfill = true;
                }
            } catch (Throwable) {
                // intentionally suppress all errors to prevent decrypt() from failing
            }
        }

        try {
            // retrieve only if not found at trans AKV
            $decryptedContext ??= $this->getRetryProxy()->call(function () use ($encrypted) {
                return $this->getClient()
                    ->getSecret($encrypted[self::SECRET_NAME])
                    ->getValue();
            });
            assert(is_string($decryptedContext));
            $decryptedContext = $this->decode($decryptedContext);
            if (!is_array($decryptedContext) || (count($decryptedContext) !== 2) ||
                empty($decryptedContext[self::KEY_INDEX]) || !isset($decryptedContext[self::METADATA_INDEX]) ||
                !is_array($decryptedContext[self::METADATA_INDEX])
            ) {
                throw new ApplicationException('Deciphering failed.');
            }
        } catch (Throwable $e) {
            throw new ApplicationException('Deciphering failed.', $e->getCode(), $e);
        }
        $this->verifyMetadata($decryptedContext[self::METADATA_INDEX], $metadata);
        try {
            $key = Key::loadFromAsciiSafeString($decryptedContext[self::KEY_INDEX]);
            return Crypto::decrypt($encrypted[self::PAYLOAD_INDEX], $key, true);
        } catch (Throwable $e) {
            $doBackfill = false;
            throw new ApplicationException('Deciphering failed.', $e->getCode(), $e);
        } finally {
            if ($doBackfill) {
                if (isset($this->metadata['stackId']) && self::getTransStackId()) {
                    $decryptedContext[self::METADATA_INDEX]['stackId'] = self::getTransStackId();
                }
                try {
                    $this->getRetryProxy()->call(function () use ($encrypted, $decryptedContext) {
                        $context = $this->encode($decryptedContext);
                        $this->getTransClient()?->setSecret(
                            new SetSecretRequest($context, new SecretAttributes()),
                            $encrypted[self::SECRET_NAME],
                        );
                    });
                } catch (Throwable) {
                    // intentionally suppress all errors to prevent decrypt() from failing
                }
            }
        }
    }

    public static function getPrefix(): string
    {
        return 'KBC::SecureKV::';
    }
}
