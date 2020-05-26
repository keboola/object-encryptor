<?php

namespace Keboola\ObjectEncryptor;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Legacy\Encryptor;
use Keboola\ObjectEncryptor\Legacy\Wrapper\BaseWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentProjectWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentWrapper as LegacyComponentWrapper;
use Keboola\ObjectEncryptor\Tests\ComponentAKVWrapperTest;
use Keboola\ObjectEncryptor\Wrapper\ComponentAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectAKVWrapper;
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
     * @var string|null AKV Vault URL.
     */
    private $akvUrl;

    /**
     * @var string|null AKV Key name.
     */
    private $akvKeyName;

    /**
     * @var string|null AKV Key version.
     */
    private $akvKeyVersion;

    /**
     * ObjectEncryptorFactory constructor.
     * @param string $kmsKeyId KMS Key ID Encryption key for KBC::Secure ciphers.
     * @param string $kmsRegion KMS Key Region.
     * @param string $keyVersion1 Encryption key for KBC::Encrypted ciphers.
     * @param string $keyVersion0 Encryption key for legacy ciphers.
     * @param string $akvUrl Azure Key Vault URL.
     * @param string $akvKeyName Azure Key vault key name.
     * @param string $akvKeyVersion Azure Key vault key version.
     */
    public function __construct($kmsKeyId, $kmsRegion, $keyVersion1, $keyVersion0, $akvUrl, $akvKeyName, $akvKeyVersion)
    {
        // No logic here, this constructor is exception-less so as not to leak keys in stack trace
        $this->kmsKeyId = $kmsKeyId;
        $this->kmsKeyRegion = $kmsRegion;
        $this->keyVersion1 = $keyVersion1;
        $this->keyVersion0 = $keyVersion0;
        $this->akvUrl = $akvUrl;
        $this->akvKeyName = $akvKeyName;
        $this->akvKeyVersion = $akvKeyVersion;
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
        if (!is_null($this->akvUrl) && !is_string($this->akvUrl)) {
            throw new ApplicationException('Invalid AKV URL.');
        }
        if (!is_null($this->akvKeyName) && !is_string($this->akvKeyName)) {
            throw new ApplicationException('Invalid AKV key name.');
        }
        if (!is_null($this->akvKeyVersion) && !is_string($this->akvKeyVersion)) {
            throw new ApplicationException('Invalid AKV key version.');
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
    private function addKMSWrappers($encryptor)
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
     * @param ObjectEncryptor $encryptor
     * @throws ApplicationException
     */
    private function addAKVWrappers($encryptor)
    {
        $wrapper = new GenericAKVWrapper();
        $wrapper->setKeyVaultUrl((string) $this->akvUrl);
        $wrapper->setKeyName((string) $this->akvKeyName);
        $wrapper->setKeyVersion((string) $this->akvKeyVersion);
        $encryptor->pushWrapper($wrapper);

        if ($this->componentId && $this->stackId) {
            $wrapper = new ComponentAKVWrapper();
            $wrapper->setKeyVaultUrl((string) $this->akvUrl);
            $wrapper->setKeyName((string) $this->akvKeyName);
            $wrapper->setKeyVersion((string) $this->akvKeyVersion);
            $wrapper->setComponentId($this->componentId);
            $wrapper->setStackId($this->stackId);
            $encryptor->pushWrapper($wrapper);
            if ($this->projectId) {
                $wrapper = new ProjectAKVWrapper();
                $wrapper->setKeyVaultUrl((string) $this->akvUrl);
                $wrapper->setKeyName((string) $this->akvKeyName);
                $wrapper->setKeyVersion((string) $this->akvKeyVersion);
                $wrapper->setComponentId($this->componentId);
                $wrapper->setStackId($this->stackId);
                $wrapper->setProjectId($this->projectId);
                $encryptor->pushWrapper($wrapper);
                if ($this->configurationId) {
                    $wrapper = new ConfigurationAKVWrapper();
                    $wrapper->setKeyVaultUrl((string) $this->akvUrl);
                    $wrapper->setKeyName((string) $this->akvKeyName);
                    $wrapper->setKeyVersion((string) $this->akvKeyVersion);
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
     * @param bool $createLegacyEncryptorIfAvailable
     * @return ObjectEncryptor Object encryptor instance.
     * @throws ApplicationException
     */
    public function getEncryptor($createLegacyEncryptorIfAvailable = false)
    {
        $this->validateState();
        if ($this->keyVersion0 && function_exists('mcrypt_module_open') && $createLegacyEncryptorIfAvailable) {
            $legacyEncryptor = new Encryptor($this->keyVersion0);
        } else {
            $legacyEncryptor = null;
        }

        $encryptor = new ObjectEncryptor($legacyEncryptor);
        if ($this->keyVersion1) {
            $this->addLegacyWrappers($encryptor);
        }

        if ($this->kmsKeyRegion && $this->kmsKeyId) {
            $this->addKMSWrappers($encryptor);
        }

        if ($this->akvUrl && $this->akvKeyName && $this->akvKeyVersion) {
            $this->addAKVWrappers($encryptor);
        }
        return $encryptor;
    }
}
