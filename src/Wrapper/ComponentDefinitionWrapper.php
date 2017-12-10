<?php

namespace Keboola\ObjectEncryptor\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

class ComponentDefinitionWrapper extends GenericWrapper
{
    const KEY_COMPONENT = 'componentId';

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
     * Validate state of the wrapper before ciphering/deciphering
     * @throws ApplicationException
     */
    protected function validateState()
    {
        parent::validateState();
        if (empty($this->getMetadataValue(self::KEY_COMPONENT))) {
            throw new ApplicationException('No component id provided.');
        }
        if (!is_string($this->getMetadataValue(self::KEY_COMPONENT))) {
            throw new ApplicationException('Component id is invalid.');
        }
        if (!is_null($this->getMetadataValue(self::KEY_STACK)) && !is_string($this->getMetadataValue(self::KEY_STACK))) {
            throw new ApplicationException('Stack id is invalid.');
        }
    }

    /**
     * @inheritdoc
     */
    public function getPrefix()
    {
        return 'KBC::ComponentSecure::';
    }
}
