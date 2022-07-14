<?php

namespace Keboola\ObjectEncryptor;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Wrapper\ComponentAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;

class ObjectEncryptorFactory
{
    private ?string $stackId = null;
    private ?string $projectId = null;
    private ?string $componentId = null;
    private ?string $configurationId = null;
    private ?string $kmsKeyId;
    private ?string $kmsKeyRegion;
    private ?string $akvUrl;

    /**
     * @param ?string $kmsKeyId KMS Key ID Encryption key for KBC::Secure ciphers.
     * @param ?string $kmsRegion KMS Key Region.
     * @param ?string $akvUrl Azure Key Vault URL.
     */
    public function __construct(?string $kmsKeyId, ?string $kmsRegion, ?string $akvUrl)
    {
        $this->kmsKeyId = $kmsKeyId;
        $this->kmsKeyRegion = $kmsRegion;
        $this->akvUrl = $akvUrl;
    }

    /**
     * @param string|null $componentId Id of current component.
     * @throws ApplicationException
     */
    public function setComponentId(?string $componentId): void
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
    public function setConfigurationId(?string $configurationId): void
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
    public function setProjectId(?string $projectId): void
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
    public function setStackId(?string $stackId): void
    {
        if (!is_null($stackId) && !is_scalar($stackId)) {
            throw new ApplicationException('Invalid stack id.');
        }
        $this->stackId = (string)$stackId;
    }

    /**
     * @throws ApplicationException
     */
    private function validateState(): void
    {
        if (!is_null($this->kmsKeyId) && !is_string($this->kmsKeyId)) {
            throw new ApplicationException('Invalid KMS key Id.');
        }
        if (!is_null($this->kmsKeyRegion) && !is_string($this->kmsKeyRegion)) {
            throw new ApplicationException('Invalid KMS region.');
        }
        if (!is_null($this->akvUrl) && !is_string($this->akvUrl)) {
            throw new ApplicationException('Invalid AKV URL.');
        }
    }

    /**
     * @param ObjectEncryptor $encryptor
     * @throws ApplicationException
     */
    private function addKMSWrappers(ObjectEncryptor $encryptor): void
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId((string)$this->kmsKeyId);
        $wrapper->setKMSRegion((string)$this->kmsKeyRegion);
        $encryptor->pushWrapper($wrapper);

        if ($this->componentId && $this->stackId) {
            $wrapper = new ComponentKMSWrapper();
            $wrapper->setKMSKeyId((string)$this->kmsKeyId);
            $wrapper->setKMSRegion((string)$this->kmsKeyRegion);
            $wrapper->setComponentId($this->componentId);
            $wrapper->setStackId($this->stackId);
            $encryptor->pushWrapper($wrapper);
            if ($this->projectId) {
                $wrapper = new ProjectKMSWrapper();
                $wrapper->setKMSKeyId((string)$this->kmsKeyId);
                $wrapper->setKMSRegion((string)$this->kmsKeyRegion);
                $wrapper->setComponentId($this->componentId);
                $wrapper->setStackId($this->stackId);
                $wrapper->setProjectId($this->projectId);
                $encryptor->pushWrapper($wrapper);
                if ($this->configurationId) {
                    $wrapper = new ConfigurationKMSWrapper();
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
    private function addAKVWrappers(ObjectEncryptor $encryptor): void
    {
        $wrapper = new GenericAKVWrapper();
        $wrapper->setKeyVaultUrl((string) $this->akvUrl);
        $encryptor->pushWrapper($wrapper);

        if ($this->componentId && $this->stackId) {
            $wrapper = new ComponentAKVWrapper();
            $wrapper->setKeyVaultUrl((string) $this->akvUrl);
            $wrapper->setComponentId($this->componentId);
            $wrapper->setStackId($this->stackId);
            $encryptor->pushWrapper($wrapper);
            if ($this->projectId) {
                $wrapper = new ProjectAKVWrapper();
                $wrapper->setKeyVaultUrl((string) $this->akvUrl);
                $wrapper->setComponentId($this->componentId);
                $wrapper->setStackId($this->stackId);
                $wrapper->setProjectId($this->projectId);
                $encryptor->pushWrapper($wrapper);
                if ($this->configurationId) {
                    $wrapper = new ConfigurationAKVWrapper();
                    $wrapper->setKeyVaultUrl((string) $this->akvUrl);
                    $wrapper->setComponentId($this->componentId);
                    $wrapper->setStackId($this->stackId);
                    $wrapper->setProjectId($this->projectId);
                    $wrapper->setConfigurationId($this->configurationId);
                    $encryptor->pushWrapper($wrapper);
                }
            }
        }
    }

    public function getEncryptor(): ObjectEncryptor
    {
        $this->validateState();

        $encryptor = new ObjectEncryptor();
        if ($this->akvUrl) {
            $this->addAKVWrappers($encryptor);
        }

        if ($this->kmsKeyRegion && $this->kmsKeyId) {
            $this->addKMSWrappers($encryptor);
        }
        return $encryptor;
    }
}
