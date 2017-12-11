<?php

namespace Keboola\ObjectEncryptor\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

class ConfigurationWrapper extends GenericWrapper
{
    const KEY_COMPONENT = 'componentId';
    const KEY_PROJECT = 'projectId';
    const KEY_CONFIGURATION = 'configurationId';
    const KEY_STACK = 'stackId';

    /**
     * @param string $stackId
     */
    public function setStackId($stackId)
    {
        $this->setMetadataValue(self::KEY_STACK, $stackId);
    }

    /**
     * @param string $componentId
     */
    public function setComponentId($componentId)
    {
        $this->setMetadataValue(self::KEY_COMPONENT, $componentId);
    }

    /**
     * @param string $projectId
     */
    public function setProjectId($projectId)
    {
        $this->setMetadataValue(self::KEY_PROJECT, $projectId);
    }

    /**
     * @param string $configurationId
     */
    public function setConfigurationId($configurationId)
    {
        $this->setMetadataValue(self::KEY_CONFIGURATION, $configurationId);
    }

    /**
     * Validate state of the wrapper before ciphering/deciphering
     * @throws ApplicationException
     */
    protected function validateState()
    {
        parent::validateState();
        if (empty($this->getMetadataValue(self::KEY_STACK)) || empty($this->getMetadataValue(self::KEY_COMPONENT))) {
            throw new ApplicationException('No stack or component id provided.');
        }
        if (!is_string($this->getMetadataValue(self::KEY_STACK))) {
            throw new ApplicationException('Stack id is invalid.');
        }
        if (!is_string($this->getMetadataValue(self::KEY_COMPONENT))) {
            throw new ApplicationException('Component id is invalid.');
        }
        if (!is_null($this->getMetadataValue(self::KEY_PROJECT)) && !is_string($this->getMetadataValue(self::KEY_PROJECT))) {
            throw new ApplicationException('Project id is invalid.');
        }
        if (!is_null($this->getMetadataValue(self::KEY_CONFIGURATION)) && !is_string($this->getMetadataValue(self::KEY_CONFIGURATION))) {
            throw new ApplicationException('Configuration id is invalid.');
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
