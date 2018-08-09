<?php

namespace Keboola\ObjectEncryptor;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Legacy\Encryptor;
use Keboola\ObjectEncryptor\Legacy\Wrapper\BaseWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentProjectWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentWrapper as LegacyComponentWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;

class ObjectEncryptorFactory
{
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
     * @var string|null AWS KMS Key id (ARN) or alias (prefix with 'alias/').
     */
    private $kmsKeyId = null;

    /**
     * @var string|null AWS KMS region.
     */
    private $kmsKeyRegion = null;

    /**
     * ObjectEncryptorFactory constructor.
     * @param string $keyId KMS Key ID Encryption key for KBC::Secure ciphers.
     * @param string $region KMS Key Region.
     * @param string $keyVersion1 Encryption key for KBC::Encrypted ciphers.
     * @param string $keyVersion0 Encryption key for legacy ciphers.
     */
    public function __construct($keyId, $region, $keyVersion1, $keyVersion0)
    {
        // No logic here, this constructor is exception-less so as not to leak keys in stack trace
        $this->kmsKeyId = $keyId;
        $this->kmsKeyRegion = $region;
        $this->keyVersion1 = $keyVersion1;
        $this->keyVersion0 = $keyVersion0;
    }

    /**
     * @param string|null $componentId Id of current component.
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
     * @param string|null $configurationId Id of current configuration.
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
     * @param string|null $projectId Id of KBC Project.
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
     * @param string|null $stackId Id of KBC Stack.
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
        if (!is_null($this->kmsKeyId) && !is_string($this->kmsKeyId)) {
            throw new ApplicationException('Invalid KMS key Id.');
        }
        if (!is_null($this->kmsKeyRegion) && !is_string($this->kmsKeyRegion)) {
            throw new ApplicationException('Invalid KMS region.');
        }
    }

    /**
     * @param ObjectEncryptor $encryptor
     * @throws ApplicationException
     */
    private function addLegacyWrappers($encryptor)
    {
        $wrapper = new BaseWrapper();
        $wrapper->setKey((string)$this->keyVersion1);
        $encryptor->pushWrapper($wrapper);
        if ($this->componentId !== null) {
            $wrapper = new LegacyComponentWrapper();
            $wrapper->setKey((string)$this->keyVersion1);
            $wrapper->setComponentId($this->componentId);
            $encryptor->pushWrapper($wrapper);
            if ($this->projectId !== null) {
                $wrapper = new ComponentProjectWrapper();
                $wrapper->setKey((string)$this->keyVersion1);
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
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId((string)$this->kmsKeyId);
        $wrapper->setKMSRegion((string)$this->kmsKeyRegion);
        $encryptor->pushWrapper($wrapper);

        if ($this->componentId && $this->stackId) {
            $wrapper = new ComponentWrapper();
            $wrapper->setKMSKeyId((string)$this->kmsKeyId);
            $wrapper->setKMSRegion((string)$this->kmsKeyRegion);
            $wrapper->setComponentId($this->componentId);
            $wrapper->setStackId($this->stackId);
            $encryptor->pushWrapper($wrapper);
            if ($this->projectId) {
                $wrapper = new ProjectWrapper();
                $wrapper->setKMSKeyId((string)$this->kmsKeyId);
                $wrapper->setKMSRegion((string)$this->kmsKeyRegion);
                $wrapper->setComponentId($this->componentId);
                $wrapper->setStackId($this->stackId);
                $wrapper->setProjectId($this->projectId);
                $encryptor->pushWrapper($wrapper);
                if ($this->configurationId) {
                    $wrapper = new ConfigurationWrapper();
                    $wrapper->setKMSKeyId((string)$this->kmsKeyId);
                    $wrapper->setKMSRegion((string)$this->kmsKeyRegion);
                    $wrapper->setComponentId($this->componentId);
                    $wrapper->setStackId($this->stackId);
                    $wrapper->setProjectId($this->projectId);
                    $wrapper->setConfigurationId($this->configurationId);
                    $encryptor->pushWrapper($wrapper);
                }
            }
        }
    }

    /**
     * @return ObjectEncryptor Object encryptor instance.
     * @throws ApplicationException
     */
    public function getEncryptor()
    {
        $this->validateState();
        if ($this->keyVersion0 && extension_loaded('mcrypt')) {
            $legacyEncryptor = new Encryptor($this->keyVersion0);
        } else {
            $legacyEncryptor = null;
        }

        $encryptor = new ObjectEncryptor($legacyEncryptor);
        if ($this->keyVersion1) {
            $this->addLegacyWrappers($encryptor);
        }

        if ($this->kmsKeyRegion && $this->kmsKeyId) {
            $this->addVersion2Wrappers($encryptor);
        }
        return $encryptor;
    }
}
