<?php

namespace Keboola\ObjectEncryptor\Wrapper;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\CryptoException;
use Defuse\Crypto\Key;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;

class GenericWrapper implements CryptoWrapperInterface
{
    const KEY_METADATA = 'metadata';
    const KEY_VALUE = 'value';
    const KEY_STACK = 'stackId';

    /**
     * @var string
     */
    private $stackKey;

    /**
     * @var string
     */
    private $generalKey;

    /**
     * @var Key
     */
    private $keyStackKey;

    /**
     * @var Key
     */
    private $keyGeneralKey;

    /**
     * @var array Key value metadata
     */
    private $metadata = [];

    /**
     * @param string $key
     */
    public function setStackKey($key)
    {
        $this->stackKey = $key;
    }

    /**
     * @param string $key
     */
    public function setGeneralKey($key)
    {
        $this->generalKey = $key;
    }

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
     * @throws ApplicationException
     */
    protected function validateState()
    {
        if (empty($this->stackKey) || empty($this->generalKey)) {
            throw new ApplicationException('Cipher keys are missing.');
        }
        try {
            $this->keyStackKey = Key::loadFromAsciiSafeString($this->stackKey);
            $this->keyGeneralKey = Key::loadFromAsciiSafeString($this->generalKey);
        } catch (\Exception $e) {
            throw new ApplicationException('Cipher keys are invalid.');
        }
    }

    /**
     * @param $encryptedData string
     * @return string decrypted data
     * @throws UserException
     * @throws ApplicationException
     */
    public function decrypt($encryptedData)
    {
        $this->validateState();
        try {
            $jsonString = Crypto::Decrypt($encryptedData, $this->keyGeneralKey);
        } catch (\Exception $e) {
            throw new UserException('Value is not an encrypted value.');
        }
        $data = json_decode($jsonString, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new UserException('Deserialization of decrypted data failed: ' . json_last_error_msg());
        }
        // use array_key_exists on KEY_VALUE, because it might be null
        if (!isset($data[self::KEY_METADATA]) || !array_key_exists(self::KEY_VALUE, $data) || !is_array($data[self::KEY_METADATA])) {
            throw new UserException('Invalid cipher data.');
        }
        foreach ($data[self::KEY_METADATA] as $key => $value) {
            if (!empty($value) && (empty($this->metadata[$key]) || $value !== $this->metadata[$key])) {
                throw new UserException('Invalid metadata.');
            }
        }
        try {
            if (!empty($data[self::KEY_METADATA][self::KEY_STACK])) {
                return Crypto::Decrypt($data[self::KEY_VALUE], $this->keyStackKey);
            } else {
                return $data[self::KEY_VALUE];
            }
        } catch (CryptoException $e) {
            throw new UserException('Invalid cipher');
        }
    }

    /**
     * @param string $data string data to encrypt
     * @return string encrypted data
     * @throws ApplicationException
     * @throws UserException
     */
    public function encrypt($data)
    {
        if (!is_scalar($data) && !is_null($data)) {
            throw new UserException('Cannot encrypt a non-scalar value');
        }
        $this->validateState();
        if (!empty($this->metadata[self::KEY_STACK])) {
            try {
                $data = Crypto::Encrypt($data, $this->keyStackKey);
            } catch (\Exception $e) {
                throw new ApplicationException($e->getMessage());
            }
        }
        $result = [self::KEY_METADATA => []];
        foreach ($this->metadata as $key => $value) {
            $result[self::KEY_METADATA][$key] = $value;
        }
        $result[self::KEY_VALUE] = $data;
        $jsonString = json_encode($result);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new ApplicationException('Serialization of encrypted data failed: ' . json_last_error_msg());
        }
        try {
            return Crypto::Encrypt($jsonString, $this->keyGeneralKey);
        } catch (\Exception $e) {
            throw new ApplicationException("Ciphering failed " . $e->getMessage(), $e);
        }
    }

    /**
     * @inheritdoc
     */
    public function getPrefix()
    {
        return 'KBC::Secure::';
    }
}
