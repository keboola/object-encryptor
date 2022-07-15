<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Wrapper\ComponentAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectKMSWrapper;

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
    PUBLIC function __construct(?string $kmsKeyId, ?string $kmsRegion, ?string $akvUrl, $stackId)
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
        $this->componentId = (string) $componentId;
    }

    /**
     * @param string|null $configurationId Id of current configuration.
     * @throws ApplicationException
     */
    private function setConfigurationId(?string $configurationId): void
    {
        // @todo to be deleted
        if (!is_null($configurationId) && !is_scalar($configurationId)) {
            throw new ApplicationException('Invalid configuration id.');
        }
        $this->configurationId = (string) $configurationId;
    }

    /**
     * @param string|null $projectId Id of KBC Project.
     * @throws ApplicationException
     */
    private function setProjectId(?string $projectId): void
    {
        // @todo to be deleted
        if (!is_null($projectId) && !is_scalar($projectId)) {
            throw new ApplicationException('Invalid project id.');
        }
        $this->projectId = (string) $projectId;
    }

    /**
     * @param string|null $stackId Id of KBC Stack.
     * @throws ApplicationException
     */
    private function setStackId(?string $stackId): void
    {
        // @todo to be deleted
        if (!is_null($stackId) && !is_scalar($stackId)) {
            throw new ApplicationException('Invalid stack id.');
        }
        $this->stackId = (string) $stackId;
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

    /*
{
    $dataPlaneId = 12;
    $dataPlane = getDataplane($dataPlaneId);

    if ($dataPlane['keyVault'] == 'azure') {
        $factory->getAzureEncryptor($dataPlane['kmsId'], $_ENV['AWS_REGION']);
    } else {
        $factory->getAWSEncryptor($dataPlane['kmsId'], $_ENV['AWS_REGION']);
    }



    $dataPlane = getDataplane($dataPlaneId);
    $options = new EncryptOptions($dataPlane['kmsId'], $_ENV['AWS_REGION']);
    $factory->getEncryptor($options);
}


    PUBLIC function getEncryptor(EncryptOptions): ObjectEncryptor
        PUBLIC function getAWSEncryptor($kmsKeyId, $kmsRegion): ObjectEncryptor
        PUBLIC function getAzureEncryptor($keyVaultUrl): ObjectEncryptor
*/
    public function getAwsEncryptor(string $kmsKeyId, string $kmsRegion): ObjectEncryptor
    {
    }

    public function getAzureEncryptor(string $keyVaultUrl): ObjectEncryptor
    {
    }

    public function getEncryptor(EncryptorOptions $encryptorOptions): ObjectEncryptor
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
