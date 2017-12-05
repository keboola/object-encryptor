<?php

namespace Keboola\ObjectEncryptor\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

class ConfigurationWrapper extends GenericWrapper
{
    /**
     * @param string $stackId
     */
    public function setStackId($stackId)
    {
        $this->setMetadataValue('stackId', $stackId);
    }

    /**
     * @param string $componentId
     */
    public function setComponentId($componentId)
    {
        $this->setMetadataValue('componentId', $componentId);
    }

    /**
     * @param string $projectId
     */
    public function setProjectId($projectId)
    {
        $this->setMetadataValue('projectId', $projectId);
    }

    /**
     * @param string $configurationId
     */
    public function setConfigurationId($configurationId)
    {
        $this->setMetadataValue('configurationId', $configurationId);
    }

    /**
     * Validate state of the wrapper before ciphering/deciphering
     * @throws ApplicationException
     */
    protected function validateState()
    {
        parent::validateState();
        if (empty($this->getMetadataValue('stackId')) || empty($this->getMetadataValue('componentId'))) {
            throw new ApplicationException('Bad init');
        }
        if (!is_string($this->getMetadataValue('stackId'))) {
            throw new ApplicationException('Invalid Stack');
        }
        if (!is_string($this->getMetadataValue('componentId'))) {
            throw new ApplicationException('Invalid Component Id.');
        }
        if (!is_null($this->getMetadataValue('projectId')) && !is_string($this->getMetadataValue('projectId'))) {
            throw new ApplicationException('Invalid Project Id.');
        }
        if (!is_null($this->getMetadataValue('configurationId')) && !is_string($this->getMetadataValue('configurationId'))) {
            throw new ApplicationException('Invalid Configuration Id.');
        }
    }

    /**
     * @inheritdoc
     */
    public function getPrefix()
    {
        return 'KBC::ConfigSecure::';
    }
}
