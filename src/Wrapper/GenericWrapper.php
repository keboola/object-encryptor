<?php

namespace Keboola\ObjectEncryptor\Wrapper;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\CryptoException;
use Defuse\Crypto\Key;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;

class GenericWrapper implements CryptoWrapperInterface
{
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
            throw new ApplicationException('Bad init');
        }
        try {
            $this->keyStackKey = Key::loadFromAsciiSafeString($this->stackKey);
            $this->keyGeneralKey = Key::loadFromAsciiSafeString($this->generalKey);
        } catch (\Exception $e) {
            throw new ApplicationException('Invalid Key');
        }
    }

    /**
     * @param string $encryptedData
     * @return string Inner cipher
     * @throws UserException
     */
    private function generalDecipher($encryptedData)
    {
        try {
            $jsonString = Crypto::Decrypt($encryptedData, $this->keyGeneralKey);
        } catch (\Exception $e) {
            throw new UserException('Invalid cipher');
        }
        $data = json_decode($jsonString, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new UserException('Deserialization of decrypted data failed: ' . json_last_error_msg());
        }
        if (!isset($data['metadata']) || !isset($data['value']) || !is_array($data['metadata'])) {
            throw new UserException('Invalid cipher data');
        }
        foreach ($data['metadata'] as $key => $value) {
            if (!empty($value) && (empty($this->metadata[$key]) || $value !== $this->metadata[$key])) {
                throw new UserException('Invalid metadata');
            }
        }
        return $data['value'];
    }

    /**
     * @param array $data Cipher data.
     * @return string Encrypted string.
     * @throws ApplicationException
     */
    private function generalCipher($data)
    {
        $jsonString = json_encode($data);
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
     * @param $encryptedData string
     * @return string decrypted data
     * @throws UserException
     * @throws ApplicationException
     */
    public function decrypt($encryptedData)
    {
        $this->validateState();
        try {
            return Crypto::Decrypt($this->generalDecipher($encryptedData), $this->keyStackKey);
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
        try {
            $encrypted = Crypto::Encrypt($data, $this->keyStackKey);
        } catch (\Exception $e) {
            throw new ApplicationException($e->getMessage());
        }
        $result = ['metadata' => []];
        foreach ($this->metadata as $key => $value) {
            $result['metadata'][$key] = $value;
        }
        $result['value'] = $encrypted;
        return $this->generalCipher($result);
    }

    /**
     * @inheritdoc
     */
    public function getPrefix()
    {
        return 'KBC::Secure::';
    }
}
