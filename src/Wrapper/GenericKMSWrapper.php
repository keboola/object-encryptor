<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Aws\Kms\Exception\KmsException;
use Aws\Kms\KmsClient;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Encoding;
use Defuse\Crypto\Key;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Retry\BackOff\ExponentialBackOffPolicy;
use Retry\Policy\SimpleRetryPolicy;
use Retry\RetryProxy;
use Throwable;

class GenericKMSWrapper implements CryptoWrapperInterface
{
    /**
     * @var array Key value metadata.
     */
    private $metadata = [];

    /**
     * @var array Key value metadata cache.
     */
    private $metadataCache = [];

    /**
     * @var array Key cache.
     */
    private $keyCache = [];

    /**
     * @var string
     */
    private $keyId;

    /**
     * @var string
     */
    private $region;

    /**
     * Set cipher metadata.
     * @param string $key
     * @param string $value
     */
    public function setMetadataValue($key, $value)
    {
        $this->metadata[$key] = $value;
    }

    /**
     * Get metadata value
     * @param string $key
     * @return string|null Value or null if key does not exist.
     */
    protected function getMetadataValue($key)
    {
        if (isset($this->metadata[$key])) {
            return $this->metadata[$key];
        } else {
            return null;
        }
    }

    /**
     * Get KMS client
     * @return KmsClient
     */
    protected function getClient()
    {
        return new KmsClient([
            'region' => $this->region,
            'version' => '2014-11-01',
            'retries' => 5,
            'connect_timeout' => 10,
            'timeout' => 120,
        ]);
    }

    /**
     * Get key for encryption
     * @return array
     * @throws ApplicationException
     */
    private function getEncryptKey()
    {
        try {
            $client = $this->getClient();
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
    protected function validateState()
    {
        if (empty($this->region) || empty($this->keyId)) {
            throw new ApplicationException('Cipher key settings are missing.');
        }
        if (!is_string($this->region) || !is_string($this->keyId)) {
            throw new ApplicationException('Cipher key settings are invalid.');
        }
    }

    /**
     * @param string $key
     */
    public function setKMSKeyId($key)
    {
        $this->keyId = $key;
    }

    /**
     * @param string $region
     */
    public function setKMSRegion($region)
    {
        $this->region = $region;
    }

    /**
     * @inheritdoc
     */
    public function getPrefix(): string
    {
        return 'KBC::Secure::';
    }

    /**
     * @inheritdoc
     */
    public function encrypt(?string $data): string
    {
        $this->validateState();
        if (!is_scalar($data) && !is_null($data)) {
            throw new UserException('Cannot encrypt a non-scalar value.');
        }
        try {
            $key = $this->getEncryptKey();
            $payload = Crypto::encrypt((string) $data, $key['local'], true);
            $resultBinary = [$payload, $key['kms']];
            $result = base64_encode(gzcompress(serialize($resultBinary)));
            return $result;
        } catch (Throwable $e) {
            throw new ApplicationException('Ciphering failed: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * @inheritdoc
     */
    public function decrypt(string $encryptedData): string
    {
        $this->validateState();
        try {
            $encrypted = @unserialize(gzuncompress(base64_decode($encryptedData)));
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
            $client = $this->getClient();
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
            $safeKey = Encoding::saveBytesToChecksummedAsciiSafeString(Key::KEY_CURRENT_VERSION, $decryptedKey);
            $key = Key::loadFromAsciiSafeString($safeKey);
            $payload = Crypto::decrypt($encrypted[0], $key, true);
            return $payload;
        } catch (Throwable $e) {
            throw new UserException('Deciphering failed.', 0, $e);
        }
    }
}
