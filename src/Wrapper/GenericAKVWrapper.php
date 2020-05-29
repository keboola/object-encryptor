<?php

namespace Keboola\ObjectEncryptor\Wrapper;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Exception;
use Keboola\AzureKeyVaultClient\Authentication\AuthenticatorFactory;
use Keboola\AzureKeyVaultClient\Client;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Keboola\AzureKeyVaultClient\Requests\SecretAttributes;
use Keboola\AzureKeyVaultClient\Requests\SetSecretRequest;
use Keboola\AzureKeyVaultClient\Responses\SecretBundle;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Psr\Log\NullLogger;
use Retry\BackOff\ExponentialBackOffPolicy;
use Retry\Policy\SimpleRetryPolicy;
use Retry\RetryProxy;

class GenericAKVWrapper implements CryptoWrapperInterface
{
    // internal indexes in cipher structures
    const METADATA_INDEX = 0;
    const KEY_INDEX = 1;
    const PAYLOAD_INDEX = 2;
    const SECRET_NAME = 3;
    const SECRET_VERSION = 4;

    /**
     * @var array Key value metadata.
     */
    private $metadata = [];

    /**
     * @var string
     */
    private $keyVaultURL;

    /**
     * @var Client
     */
    private $client;

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
     * Validate internal state
     * @throws ApplicationException
     */
    protected function validateState()
    {
        if (empty($this->keyVaultURL) || !is_string($this->keyVaultURL)) {
            throw new ApplicationException('Cipher key settings are invalid.');
        }
    }

    /**
     * @param string $keyVaultURL
     */
    public function setKeyVaultUrl($keyVaultURL)
    {
        $this->keyVaultURL = $keyVaultURL;
    }

    /**
     * Get Azure Key Vault client
     * @return Client
     */
    protected function getClient()
    {
        if (!$this->client) {
            $this->client = new Client(
                new GuzzleClientFactory(new NullLogger()),
                new AuthenticatorFactory(),
                $this->keyVaultURL
            );
        }
        return $this->client;
    }

    /**
     * @return RetryProxy
     */
    private function getRetryProxy()
    {
        $retryPolicy = new SimpleRetryPolicy(3);
        $backOffPolicy = new ExponentialBackOffPolicy(1000);
        return new RetryProxy($retryPolicy, $backOffPolicy);
    }

    /**
     * @param mixed $data
     * @return string
     */
    private function encode($data)
    {
        return base64_encode(gzcompress(serialize($data)));
    }

    /**
     * @param string $data
     * @return mixed
     * @throws UserException
     */
    private function decode($data)
    {
        try {
            return @unserialize(gzuncompress(base64_decode($data)));
        } catch (Exception $e) {
            throw new UserException('Cipher is malformed.', $e);
        }
    }

    /**
     * @param string $data
     * @return string
     * @throws ApplicationException
     * @throws UserException
     */
    public function encrypt($data)
    {
        $this->validateState();
        if (!is_scalar($data) && !is_null($data)) {
            throw new UserException('Cannot encrypt a non-scalar value.');
        }
        try {
            $key = Key::createNewRandomKey();
            $context = $this->encode([
                self::METADATA_INDEX => $this->metadata,
                self::KEY_INDEX => $key->saveToAsciiSafeString()
            ]);
            $secret = $this->getRetryProxy()->call(function () use ($context) {
                return $this->getClient()->setSecret(
                    new SetSecretRequest($context, new SecretAttributes()),
                    uniqid('gen-encryptor')
                );
            });
            /** @var SecretBundle $secret */
            return $this->encode([
                self::PAYLOAD_INDEX => Crypto::encrypt((string) $data, $key, true),
                self::SECRET_NAME => $secret->getName(),
                self::SECRET_VERSION => $secret->getVersion(),
            ]);
        } catch (Exception $e) {
            throw new ApplicationException('Ciphering failed: ' . $e->getMessage(), $e);
        }
    }

    /**
     * @param $cipherMetadata
     * @param $localMetadata
     * @throws UserException
     */
    private function verifyMetadata($cipherMetadata, $localMetadata)
    {
        foreach ($cipherMetadata as $key => $value) {
            if (empty($localMetadata[$key]) || ($cipherMetadata[$key] !== $localMetadata[$key])) {
                throw new UserException('Deciphering failed.');
            }
        }
    }

    /**
     * @param string $encryptedData
     * @return string
     * @throws ApplicationException
     * @throws UserException
     */
    public function decrypt($encryptedData)
    {
        $this->validateState();
        $encrypted = $this->decode($encryptedData);
        if (!is_array($encrypted) || count($encrypted) !== 3 || empty($encrypted[self::PAYLOAD_INDEX]) ||
            empty($encrypted[self::SECRET_NAME]) || empty($encrypted[self::SECRET_VERSION])
        ) {
            throw new UserException('Deciphering failed.');
        }
        try {
            $decryptedContext = $this->getRetryProxy()->call(function () use ($encrypted) {
                return $this->getClient()->getSecret(
                    $encrypted[self::SECRET_NAME],
                    $encrypted[self::SECRET_VERSION]
                )->getValue();
            });
            $decryptedContext = $this->decode($decryptedContext);
            if (!is_array($decryptedContext) || (count($decryptedContext) !== 2) ||
                empty($decryptedContext[self::KEY_INDEX]) || !isset($decryptedContext[self::METADATA_INDEX]) ||
                !is_array($decryptedContext[self::METADATA_INDEX])
            ) {
                throw new ApplicationException('Deciphering failed.');
            }
        } catch (Exception $e) {
            throw new ApplicationException('Deciphering failed.', $e);
        }
        $this->verifyMetadata($decryptedContext[self::METADATA_INDEX], $this->metadata);
        try {
            $key = Key::loadFromAsciiSafeString($decryptedContext[self::KEY_INDEX]);
            return Crypto::decrypt($encrypted[self::PAYLOAD_INDEX], $key, true);
        } catch (Exception $e) {
            throw new ApplicationException('Deciphering failed.', $e);
        }
    }

    /**
     * @inheritdoc
     */
    public function getPrefix()
    {
        return 'KBC::SecureKV::';
    }
}
