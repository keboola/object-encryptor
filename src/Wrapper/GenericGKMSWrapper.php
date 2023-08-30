<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Aws\Kms\Exception\KmsException;
use Aws\Kms\KmsClient;
use Aws\Result;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Encoding;
use Defuse\Crypto\Key;
use Google\ApiCore\ApiException;
use Google\Cloud\Kms\V1\KeyManagementServiceClient;
use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Retry\BackOff\ExponentialBackOffPolicy;
use Retry\Policy\SimpleRetryPolicy;
use Retry\RetryProxy;
use Throwable;

/**
 * @internal Use ObjectEncryptor
 */
class GenericGKMSWrapper implements CryptoWrapperInterface
{
    // internal indexes in cipher structures
    private const KEY_INDEX = 0;
    private const PAYLOAD_INDEX = 1;

    private array $metadata = [];
    private string $gkmsKeyId;
    private RetryProxy $retryProxy;

    public function __construct(private readonly KeyManagementServiceClient $client, EncryptorOptions $encryptorOptions)
    {
        $this->gkmsKeyId = (string) $encryptorOptions->getGkmsKeyId();

        if (empty($this->gkmsKeyId)) {
            throw new ApplicationException('Cipher key settings are invalid.');
        }

        $retryPolicy = new SimpleRetryPolicy($encryptorOptions->getBackoffMaxTries());
        $backOffPolicy = new ExponentialBackOffPolicy(1000);
        $this->retryProxy = new RetryProxy($retryPolicy, $backOffPolicy);
    }

    public function setMetadataValue(string $key, string $value): void
    {
        $this->metadata[$key] = $value;
    }

    protected function getMetadataValue(string $key): ?string
    {
        return $this->metadata[$key] ?? null;
    }

    private function encode(array $data): string
    {
        return base64_encode((string) gzcompress(serialize($data)));
    }

    private function decode(string $data): array
    {
        try {
            return (array) @unserialize((string) gzuncompress((string) base64_decode($data)));
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
            $encryptedKey = $this->retryProxy->call(function () use ($key) {
                ksort($this->metadata);
                $response = $this->client->encrypt(
                    $this->gkmsKeyId,
                    $key->saveToAsciiSafeString(),
                    ['additionalAuthenticatedData' => $this->encode($this->metadata)]
                );
                return $response->getCiphertext();
            });
            return $this->encode([
                self::PAYLOAD_INDEX => Crypto::encrypt((string) $data, $key, true),
                self::KEY_INDEX => $encryptedKey,
            ]);
        } catch (Throwable $e) {
            throw new ApplicationException('Ciphering failed: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }

    public function decrypt(string $encryptedData): string
    {
        $this->validateState();
        $encrypted = $this->decode($encryptedData);
        if (count($encrypted) !== 2 || empty($encrypted[self::PAYLOAD_INDEX]) || empty($encrypted[self::KEY_INDEX])) {
            throw new UserException('Deciphering failed.');
        }

        try {
            $decryptedKey = $this->retryProxy->call(function () use ($encrypted) {
                ksort($this->metadata);
                $response = $this->client->decrypt(
                    $this->gkmsKeyId,
                    $encrypted[self::KEY_INDEX],
                    ['additionalAuthenticatedData' => $this->encode($this->metadata)]
                );
                return $response->getPlaintext();
            });
            assert(is_string($decryptedKey));
        } catch (ApiException $e) {
            throw new UserException('Deciphering failed.', $e->getCode(), $e);
        } catch (Throwable $e) {
            throw new ApplicationException('Deciphering failed.', $e->getCode(), $e);
        }

        try {
            $key = Key::loadFromAsciiSafeString($decryptedKey);
            return Crypto::decrypt($encrypted[self::PAYLOAD_INDEX], $key, true);
        } catch (Throwable $e) {
            throw new ApplicationException('Deciphering failed.', $e->getCode(), $e);
        }
    }

    public static function getPrefix(): string
    {
        return 'KBC::SecureGKMS::';
    }
}
