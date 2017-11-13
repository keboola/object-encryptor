<?php

namespace Keboola\ObjectEncryptor\Wrapper;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Keboola\ObjectEncryptor\Exception\EncryptionException;

class StackWrapper implements CryptoWrapperInterface
{
    /**
     * @var Crypto
     */
    private $encryptor;

    /**
     * @var Key
     */
    private $stackKey;

    /**
     * @var Key
     */
    private $globalKey;

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
     * BaseWrapper constructor.
     */
    public function __construct()
    {
        $this->encryptor = new Crypto();
    }

    /**
     * @param string $key
     */
    public function setStackKey($key)
    {
        $this->stackKey = Key::loadFromAsciiSafeString($key);
    }

    /**
     * @param string $key
     */
    public function setGlobalKey($key)
    {
        $this->globalKey = Key::loadFromAsciiSafeString($key);
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
     * @param $encryptedData string
     * @return string decrypted data
     * @throws EncryptionException
     */
    public function decrypt($encryptedData)
    {
        if (empty($this->stackId) || empty($this->stackKey) || empty($this->globalKey)) {
            throw new EncryptionException("Bad init");
        }
        $jsonString = $this->encryptor->Decrypt(base64_decode($encryptedData), $this->globalKey);
        $data = json_decode($jsonString, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new EncryptionException("Deserialization of decrypted data failed: " . json_last_error_msg());
        }
        if ($this->configurationId && ($data['cfg'] !== $this->configurationId)) {
            throw new EncryptionException("Invalid configuration");
        }
        if ($this->componentId && ($data['cmp'] !== $this->componentId)) {
            throw new EncryptionException("Invalid component");
        }
        if ($this->projectId && ($data['prj'] !== $this->projectId)) {
            throw new EncryptionException("Invalid project");
        }
        if (empty($data['stacks'][$this->stackId])) {
            throw new EncryptionException("Invalid stack");
        }
        return $this->encryptor->Decrypt($data['stacks'][$this->stackId], $this->stackKey);
    }

    /**
     * @param $data string data to encrypt
     * @return string encrypted data
     * @throws EncryptionException
     */
    public function encrypt($data)
    {
        if (empty($this->stackId) || empty($this->stackKey) || empty($this->globalKey)) {
            throw new EncryptionException("Bad init");
        }
        $encrypted = $this->encryptor->Encrypt($data, $this->stackKey);
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
        $jsonString = json_encode($result);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new EncryptionException("Serialization of encrypted data failed: " . json_last_error_msg());
        }
        return base64_encode($this->encryptor->Encrypt($jsonString, $this->globalKey));
    }

    /**
     * @inheritdoc
     */
    public function getPrefix()
    {
        return "KBC::SecureV3==";
    }
}
