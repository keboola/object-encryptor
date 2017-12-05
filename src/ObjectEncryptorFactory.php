<?php

namespace Keboola\ObjectEncryptor;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Legacy\Encryptor;
use Keboola\ObjectEncryptor\Legacy\Wrapper\BaseWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentProjectWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentDefinitionWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericWrapper;

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
     */
    public function __construct($keyVersion2, $keyVersion1, $keyVersion0, $stackKeyVersion2)
    {
        // No logic here, this constructor is exception-less so as not to leak keys in stack trace
        $this->keyVersion2 = $keyVersion2;
        $this->keyVersion1 = $keyVersion1;
        $this->keyVersion0 = $keyVersion0;
        $this->stackKeyVersion2 = $stackKeyVersion2;
    }

    /**
     * @param string $componentId Id of current component.
     * @throws ApplicationException
     */
    public function setComponentId($componentId)
    {
        if (!is_null($componentId) && !is_scalar($componentId)) {
            throw new ApplicationException('Invalid component id.');
        }
        $this->componentId = (string)$componentId;
    }

    /**
     * @param string $configurationId Id of current configuration.
     * @throws ApplicationException
     */
    public function setConfigurationId($configurationId)
    {
        if (!is_null($configurationId) && !is_scalar($configurationId)) {
            throw new ApplicationException('Invalid configuration id.');
        }
        $this->configurationId = (string)$configurationId;
    }

    /**
     * @param string $projectId Id of KBC Project.
     * @throws ApplicationException
     */
    public function setProjectId($projectId)
    {
        if (!is_null($projectId) && !is_scalar($projectId)) {
            throw new ApplicationException('Invalid project id.');
        }
        $this->projectId = (string)$projectId;
    }

    /**
     * @param string $stackId Id of KBC Stack.
     * @throws ApplicationException
     */
    public function setStackId($stackId)
    {
        if (!is_null($stackId) && !is_scalar($stackId)) {
            throw new ApplicationException('Invalid stack id.');
        }
        $this->stackId = (string)$stackId;
    }

    /**
     * @throws ApplicationException
     */
    private function validateState()
    {
        if (!is_null($this->keyVersion0) && !is_string($this->keyVersion0)) {
            throw new ApplicationException('Invalid key version 0.');
        }
        $this->keyVersion0 = substr($this->keyVersion0, 0, 32);
        if (!$this->keyVersion0) {
            // For php 5.6 compatibility
            $this->keyVersion0 = '';
        }
        if (!is_null($this->keyVersion1) && !is_string($this->keyVersion1)) {
            throw new ApplicationException('Invalid key version 1.');
        }
        if (!is_null($this->keyVersion2) && !is_string($this->keyVersion2)) {
            throw new ApplicationException('Invalid key version 2.');
        }
        if (!is_null($this->stackKeyVersion2) && !is_string($this->stackKeyVersion2)) {
            throw new ApplicationException('Invalid stack key.');
        }
    }

    /**
     * @param ObjectEncryptor $encryptor
     * @throws ApplicationException
     */
    private function addLegacyWrappers($encryptor)
    {
        $wrapper = new BaseWrapper();
        $wrapper->setKey($this->keyVersion1);
        $encryptor->pushWrapper($wrapper);
        if ($this->componentId !== null) {
            $wrapper = new ComponentWrapper();
            $wrapper->setKey($this->keyVersion1);
            $wrapper->setComponentId($this->componentId);
            $encryptor->pushWrapper($wrapper);
            if ($this->projectId !== null) {
                $wrapper = new ComponentProjectWrapper();
                $wrapper->setKey($this->keyVersion1);
                $wrapper->setComponentId($this->componentId);
                $wrapper->setProjectId($this->projectId);
                $encryptor->pushWrapper($wrapper);
            }
        }
    }

    /**
     * @param ObjectEncryptor $encryptor
     * @throws ApplicationException
     */
    private function addVersion2Wrappers($encryptor)
    {
        $wrapper = new GenericWrapper();
        $wrapper->setStackKey($this->stackKeyVersion2);
        $wrapper->setGeneralKey($this->keyVersion2);
        $encryptor->pushWrapper($wrapper);

        if ($this->componentId) {
            $wrapper = new ComponentDefinitionWrapper();
            $wrapper->setStackKey($this->stackKeyVersion2);
            $wrapper->setGeneralKey($this->keyVersion2);
            $wrapper->setComponentId($this->componentId);
            $wrapper->setStackId($this->stackId);
            $encryptor->pushWrapper($wrapper);
        }
        if ($this->componentId && $this->stackId) {
            $wrapper = new ConfigurationWrapper();
            $wrapper->setStackKey($this->stackKeyVersion2);
            $wrapper->setGeneralKey($this->keyVersion2);
            $wrapper->setComponentId($this->componentId);
            $wrapper->setStackId($this->stackId);
            $wrapper->setProjectId($this->projectId);
            $wrapper->setConfigurationId($this->configurationId);
            $encryptor->pushWrapper($wrapper);
        }
    }

    /**
     * @return ObjectEncryptor Object encryptor instance.
     * @throws ApplicationException
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
            $this->addLegacyWrappers($encryptor);
        }

        if ($this->keyVersion2 && $this->stackKeyVersion2) {
            $this->addVersion2Wrappers($encryptor);
        }
        return $encryptor;
    }
}
