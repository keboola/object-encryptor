<?php

namespace Keboola\ObjectEncryptor;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Legacy\Encryptor;
use Keboola\ObjectEncryptor\Legacy\Wrapper\BaseWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentProjectWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentWrapper;
use Keboola\ObjectEncryptor\Wrapper\StackWrapper;

class ObjectEncryptorFactory
{
    /**
     * @var null|string Stack specific encryption key for KBC::SecureV3 ciphers.
     */
    private $stackKeyVersion2;

    /**
     * @var null|string Global encryption key for KBC::SecureV3 ciphers.
     */
    private $keyVersion2 = null;

    /**
     * @var null|string Encryption key for KBC::Encrypted ciphers.
     */
    private $keyVersion1 = null;

    /**
     * @var null|string Encryption key for legacy ciphers.
     */
    private $keyVersion0 = null;

    /**
     * @var null|string Id of KBC Stack.
     */
    private $stackId = null;

    /**
     * @var null|string Id of KBC Project.
     */
    private $projectId = null;

    /**
     * @var null|string Id of current component.
     */
    private $componentId = null;

    /**
     * @var null|string Id of current configuration.
     */
    private $configurationId = null;

    /**
     * ObjectEncryptorFactory constructor.
     * @param string $keyVersion2 Encryption key for KBC::SecureV3 ciphers.
     * @param string $keyVersion1 Encryption key for KBC::Encrypted ciphers.
     * @param string $keyVersion0 Encryption key for legacy ciphers.
     * @param string $stackKeyVersion2 Stack specific encryption key for KBC::SecureV3 ciphers.
     * @param string $stackId Id of KBC Stack.
     */
    public function __construct($keyVersion2, $keyVersion1, $keyVersion0, $stackKeyVersion2, $stackId)
    {
        // No logic here, this ctor is exception-less so as not to leak keys in stack trace
        $this->keyVersion2 = $keyVersion2;
        $this->keyVersion1 = $keyVersion1;
        $this->keyVersion0 = $keyVersion0;
        $this->stackKeyVersion2 = $stackKeyVersion2;
        $this->stackId = $stackId;
    }

    /**
     * @param string $componentId Id of current component.
     */
    public function setComponentId($componentId)
    {
        $this->componentId = $componentId;
    }

    /**
     * @param string $configurationId Id of current configuration.
     */
    public function setConfigurationId($configurationId)
    {
        $this->configurationId = $configurationId;
    }

    /**
     * @param string $projectId Id of KBC Project.
     */
    public function setProjectId($projectId)
    {
        $this->projectId = $projectId;
    }

    /**
     * @throws ApplicationException
     */
    private function validateState()
    {
        if (!is_null($this->keyVersion0) && !is_string($this->keyVersion0)) {
            throw new ApplicationException("Invalid key0.");
        }
        if (!is_null($this->keyVersion1) && !is_string($this->keyVersion1)) {
            throw new ApplicationException("Invalid key1.");
        }
        if (!is_null($this->keyVersion2) && !is_string($this->keyVersion2)) {
            throw new ApplicationException("Invalid key2.");
        }
        if (!is_null($this->stackKeyVersion2) && !is_string($this->stackKeyVersion2)) {
            throw new ApplicationException("Invalid stack key.");
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
    }

    /**
     * @return ObjectEncryptor Object encryptor instance.
     */
    public function getEncryptor()
    {
        $this->validateState();
        if ($this->keyVersion0) {
            $legacyEncryptor = new Encryptor($this->keyVersion0);
        } else {
            $legacyEncryptor = null;
        }

        $encryptor = new ObjectEncryptor($legacyEncryptor);
        if ($this->keyVersion1) {
            $wrapper = new BaseWrapper();
            $wrapper->setKey($this->keyVersion1);
            $encryptor->pushWrapper($wrapper);
            if ($this->componentId !== null) {
                $wrapper = new ComponentWrapper();
                $wrapper->setComponentId($this->componentId);
                $encryptor->pushWrapper($wrapper);
                if ($this->projectId !== null) {
                    $wrapper = new ComponentProjectWrapper();
                    $wrapper->setComponentId($this->componentId);
                    $wrapper->setProjectId($this->projectId);
                    $encryptor->pushWrapper($wrapper);
                }
            }
        }

        if ($this->keyVersion2 && $this->stackKeyVersion2 && $this->stackId) {
            $wrapper = new StackWrapper();
            $wrapper->setStackKey($this->keyVersion2);
            $wrapper->setGeneralKey($this->stackKeyVersion2);
            $wrapper->setStackId($this->stackId);
            $wrapper->setComponentId($this->componentId);
            $wrapper->setProjectId($this->projectId);
            $wrapper->setConfigurationId($this->configurationId);
            $encryptor->pushWrapper($wrapper);
        }
        return $encryptor;
    }
}
