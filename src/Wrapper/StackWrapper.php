<?php

namespace Keboola\ObjectEncryptor\Wrapper;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\EncryptionException;

class StackWrapper implements CryptoWrapperInterface
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
     * @var string
     */
    private $stackId;

    /**
     * @var string
     */
    private $componentId = null;

    /**
     * @var string
     */
    private $projectId = null;

    /**
     * @var string
     */
    private $configurationId = null;

    /**
     * @var Key
     */
    private $keyStackKey;

    /**
     * @var Key
     */
    private $keyGeneralKey;

    /**
     * BaseWrapper constructor.
     */
    public function __construct()
    {
    }

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
     * @param string $stackId
     */
    public function setStackId($stackId)
    {
        $this->stackId = $stackId;
    }

    /**
     * @param string $componentId
     */
    public function setComponentId($componentId)
    {
        $this->componentId = $componentId;
    }

    /**
     * @param string $projectId
     */
    public function setProjectId($projectId)
    {
        $this->projectId = $projectId;
    }

    /**
     * @param string $configurationId
     */
    public function setConfigurationId($configurationId)
    {
        $this->configurationId = $configurationId;
    }

    /**
     * @throws ApplicationException
     */
    private function validateState()
    {
        if (empty($this->stackId) || empty($this->stackKey) || empty($this->generalKey)) {
            throw new ApplicationException("Bad init");
        }
        if (!is_string($this->stackId)) {
            throw new ApplicationException("Invalid Stack");
        }
        if (!is_null($this->projectId) && !is_string($this->projectId)) {
            throw new ApplicationException("Invalid Project Id.");
        }
        if (!is_null($this->componentId) && !is_string($this->componentId)) {
            throw new ApplicationException("Invalid Component Id.");
        }
        if (!is_null($this->configurationId) && !is_string($this->configurationId)) {
            throw new ApplicationException("Invalid Configuration Id.");
        }
        try {
            $this->keyStackKey = Key::loadFromAsciiSafeString($this->stackKey);
            $this->keyGeneralKey = Key::loadFromAsciiSafeString($this->generalKey);
        } catch (\Exception $e) {
            throw new ApplicationException("Invalid Key");
        }
    }

    private function addPrefix($value)
    {
        $result = '';
        if ($this->componentId) {
            $result .= 'C';
        }
        if ($this->projectId) {
            $result .= 'P';
        }
        if ($this->configurationId) {
            $result .= 'F';
        }
        $result .= '::' . $value;
        return $result;
    }

    private function stripPrefix($value)
    {
        $pos = strpos($value, '::');
        if ($pos !== false) {
            return substr($value, $pos + 2);
        } else {
            return $value;
        }
    }

    /**
     * @param string $encryptedData
     * @return array Cipher structure
     * @throws EncryptionException
     */
    private function generalDecipher($encryptedData)
    {
        try {
            $jsonString = Crypto::Decrypt($this->stripPrefix($encryptedData), $this->keyGeneralKey);
        } catch (\Exception $e) {
            throw new EncryptionException("Invalid cipher");
        }
        $data = json_decode($jsonString, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new EncryptionException("Deserialization of decrypted data failed: " . json_last_error_msg());
        }
        if (!empty($data['cfg']) && (empty($this->configurationId) || ($data['cfg'] !== $this->configurationId))) {
            throw new EncryptionException("Invalid configuration");
        }
        if (!empty($data['cmp']) && (empty($this->componentId) || ($data['cmp'] !== $this->componentId))) {
            throw new EncryptionException("Invalid component");
        }
        if (!empty($data['prj']) && (empty($this->projectId) || ($data['prj'] !== $this->projectId))) {
            throw new EncryptionException("Invalid project");
        }
        return $data;
    }

    /**
     * @param array $data Cipher data.
     * @return string Encrypted string.
     * @throws EncryptionException
     */
    private function generalCipher($data)
    {
        $jsonString = json_encode($data);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new EncryptionException("Serialization of encrypted data failed: " . json_last_error_msg());
        }
        return $this->addPrefix(Crypto::Encrypt($jsonString, $this->keyGeneralKey));
    }

    /**
     * @param $encryptedData string
     * @return string decrypted data
     * @throws EncryptionException
     */
    public function decrypt($encryptedData)
    {
        $this->validateState();
        $data = $this->generalDecipher($encryptedData);
        if (empty($data['stacks'][$this->stackId])) {
            throw new EncryptionException("Invalid stack");
        }
        try {
            return Crypto::Decrypt($data['stacks'][$this->stackId], $this->keyStackKey);
        } catch (\Exception $e) {
            throw new EncryptionException("Invalid cipher");
        }
    }

    /**
     * @param $data string data to encrypt
     * @return string encrypted data
     * @throws EncryptionException
     */
    public function encrypt($data)
    {
        $this->validateState();
        $encrypted = Crypto::Encrypt($data, $this->keyStackKey);
        $result = [];
        if ($this->configurationId) {
            $result['cfg'] = $this->configurationId;
        }
        if ($this->componentId) {
            $result['cmp'] = $this->componentId;
        }
        if ($this->projectId) {
            $result['prj'] = $this->projectId;
        }
        $result['stacks'][$this->stackId] = $encrypted;
        return $this->generalCipher($result);
    }

    /**
     * Add a new stack data to cipher.
     * @param string $encryptedData Encrypted data.
     * @param string $newData New encrypted data.
     * @return string
     * @throws EncryptionException
     */
    public function add($encryptedData, $newData)
    {
        $this->validateState();
        $data = $this->generalDecipher($encryptedData);
        if (isset($data['stacks'][$this->stackId])) {
            throw new EncryptionException("Stack is already used");
        }
        $encrypted = Crypto::Encrypt($newData, $this->keyStackKey);
        $data['stacks'][$this->stackId] = $encrypted;
        return $this->generalCipher($data);
    }

    /**
     * @inheritdoc
     */
    public function getPrefix()
    {
        return "KBC::SecureV3::";
    }
}
