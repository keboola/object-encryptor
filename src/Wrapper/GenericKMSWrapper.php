<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Aws\Kms\Exception\KmsException;
use Aws\Kms\KmsClient;
use Aws\Result;
use Aws\Sts\StsClient;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Encoding;
use Defuse\Crypto\Key;
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
    private string $region;
    private ?string $role = null;

    public function setMetadataValue(string $key, string $value): void
    {
        $this->metadata[$key] = $value;
    }

    protected function getMetadataValue(string $key): ?string
    {
        return $this->metadata[$key] ?? null;
    }

    protected function getClient(?array $credentials): KmsClient
    {
        $options = [
            'region' => $this->region,
            'version' => '2014-11-01',
            'retries' => 5,
            'connect_timeout' => 10,
            'timeout' => 120,
        ];
        if ($credentials) {
            $options['credentials'] = $credentials;
        }
        return new KmsClient($options);
    }

    /**
     * Get key for encryption
     * @throws ApplicationException
     */
    private function getEncryptKey(): array
    {
        try {
            $client = $this->getClient($this->assumeRole());
            if (($this->metadata !== $this->metadataCache) || empty($this->keyCache)) {
                $retryPolicy = new SimpleRetryPolicy(3);
                $backOffPolicy = new ExponentialBackOffPolicy(1000);
                $proxy = new RetryProxy($retryPolicy, $backOffPolicy);
                $proxy->call(function () use ($client, &$result) {
                    $result = $client->generateDataKey([
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
        if (empty($this->region) || empty($this->keyId)) {
            throw new ApplicationException('Cipher key settings are missing.');
        }
    }

    public function setKMSKeyId(string $key): void
    {
        $this->keyId = $key;
    }

    public function setKMSRegion(string $region): void
    {
        $this->region = $region;
    }

    public function setKMSRole(?string $role): void
    {
        $this->role = $role;
    }

    public function getPrefix(): string
    {
        return 'KBC::Secure::';
    }

    public function encrypt(?string $data): string
    {
        $this->validateState();
        try {
            $this->assumeRole();
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
            $retryPolicy = new SimpleRetryPolicy(3);
            $backOffPolicy = new ExponentialBackOffPolicy(1000);
            $proxy = new RetryProxy($retryPolicy, $backOffPolicy);
            $client = $this->getClient($this->assumeRole());
            $metadata = $this->metadata;
            $proxy->call(function () use ($client, $encrypted, $metadata, &$result) {
                $result = $client->decrypt([
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

    private function assumeRole(): ?array
    {
        if (!$this->role) {
            return null;
        }
        $stsClient = new StsClient([
            'region' => $this->region,
            'version' => '2011-06-15',
            'retries' => 5,
            'connect_timeout' => 10,
            'timeout' => 120,
        ]);
        $result = $stsClient->assumeRole([
            'RoleArn' => $this->role,
            'RoleSessionName' => 'Encrypt-Decrypt',
        ]);
        assert(is_array($result['Credentials']));
        return [
            'key' => $result['Credentials']['AccessKeyId'],
            'secret' => $result['Credentials']['SecretAccessKey'],
            'token' => $result['Credentials']['SessionToken'],
        ];
    }
}
