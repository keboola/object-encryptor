<?php

namespace Keboola\ObjectEncryptor\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

class ComponentDefinitionWrapper extends GenericWrapper
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
     * Validate state of the wrapper before ciphering/deciphering
     * @throws ApplicationException
     */
    protected function validateState()
    {
        parent::validateState();
        if (empty($this->getMetadataValue('componentId'))) {
            throw new ApplicationException('Bad init');
        }
        if (!is_string($this->getMetadataValue('componentId'))) {
            throw new ApplicationException('Invalid Component Id.');
        }
        if (!is_null($this->getMetadataValue('stackId')) && !is_string($this->getMetadataValue('stackId'))) {
            throw new ApplicationException('Invalid Stack');
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
