<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Aws\Kms\Exception\KmsException;
use Aws\Kms\KmsClient;
use Aws\Result;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Encoding;
use Defuse\Crypto\Key;
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
class GenericKMSWrapper implements CryptoWrapperInterface
{
    private array $metadata = [];
    private array $metadataCache = [];
    private ?Result $keyCache = null;
    private string $keyId;
    private int $backoffMaxTries;

    public function __construct(
        private readonly KmsClient $kmsClient,
        EncryptorOptions $encryptorOptions,
    ) {
        $this->backoffMaxTries = $encryptorOptions->getBackoffMaxTries();
        $this->keyId = (string) $encryptorOptions->getKmsKeyId();
        if (empty($this->keyId)) {
            throw new ApplicationException('Cipher key settings are missing.');
        }
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
     * Get key for encryption
     * @throws ApplicationException
     */
    private function getEncryptKey(): array
    {
        try {
            if (($this->metadata !== $this->metadataCache) || empty($this->keyCache)) {
                $retryPolicy = new SimpleRetryPolicy($this->backoffMaxTries);
                $backOffPolicy = new ExponentialBackOffPolicy(1000);
                $proxy = new RetryProxy($retryPolicy, $backOffPolicy);
                $proxy->call(function () use (&$result) {
                    $result = $this->kmsClient->generateDataKey([
                        'KeyId' => $this->keyId,
                        'KeySpec' => 'AES_256',
                        'EncryptionContext' => $this->metadata,
                    ]);
                });
                $this->keyCache = $result;
                $this->metadataCache = $this->metadata;
            }
            if (empty($this->keyCache['Plaintext']) || empty($this->keyCache['CiphertextBlob'])) {
                throw new ApplicationException('Invalid KMS response.');
            }
            $plainKey = $this->keyCache['Plaintext'];
            $encryptedKey = $this->keyCache['CiphertextBlob'];
            assert(is_string($plainKey));
            $safeKey = Encoding::saveBytesToChecksummedAsciiSafeString(Key::KEY_CURRENT_VERSION, $plainKey);
            return ['kms' => $encryptedKey, 'local' => Key::loadFromAsciiSafeString($safeKey)];
        } catch (Throwable $e) {
            throw new ApplicationException('Failed to obtain encryption key.', $e->getCode(), $e);
        }
    }

    /**
     * Validate internal state
     * @throws ApplicationException
     */
    protected function validateState(): void
    {
    }

    public static function getPrefix(): string
    {
        return 'KBC::Secure::';
    }

    public function encrypt(?string $data): string
    {
        $this->validateState();
        try {
            $key = $this->getEncryptKey();
            $payload = Crypto::encrypt((string) $data, $key['local'], true);
            $resultBinary = [$payload, $key['kms']];
            return base64_encode((string) gzcompress(serialize($resultBinary)));
        } catch (Throwable $e) {
            throw new ApplicationException('Ciphering failed: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }

    public function decrypt(string $encryptedData): string
    {
        $this->validateState();
        try {
            $encrypted = @unserialize((string) gzuncompress(base64_decode($encryptedData)));
        } catch (Throwable $e) {
            throw new UserException('Deciphering failed.', 0, $e);
        }
        if (!is_array($encrypted) || count($encrypted) !== 2) {
            throw new UserException('Deciphering failed.');
        }
        try {
            $retryPolicy = new SimpleRetryPolicy($this->backoffMaxTries);
            $backOffPolicy = new ExponentialBackOffPolicy(1000);
            $proxy = new RetryProxy($retryPolicy, $backOffPolicy);
            $metadata = $this->metadata;
            $proxy->call(function () use ($encrypted, $metadata, &$result) {
                $result = $this->kmsClient->decrypt([
                    'CiphertextBlob' => $encrypted[1],
                    'EncryptionContext' => $metadata,
                ]);
            });
        } catch (KmsException $e) {
            throw new UserException('Deciphering failed.', 0, $e);
        } catch (Throwable $e) {
            throw new ApplicationException('Deciphering failed.', $e->getCode(), $e);
        }
        if (empty($result['Plaintext'])) {
            throw new ApplicationException('Invalid KMS response.');
        }
        try {
            $decryptedKey = $result['Plaintext'];
            assert(is_string($decryptedKey));
            $safeKey = Encoding::saveBytesToChecksummedAsciiSafeString(
                Key::KEY_CURRENT_VERSION,
                $decryptedKey
            );
            $key = Key::loadFromAsciiSafeString($safeKey);
            return Crypto::decrypt($encrypted[0], $key, true);
        } catch (Throwable $e) {
            throw new UserException('Deciphering failed.', 0, $e);
        }
    }
}
