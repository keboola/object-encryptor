<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

class ConfigurationKMSWrapper extends ProjectKMSWrapper
{
    private const KEY_CONFIGURATION = 'configurationId';

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
        if (empty($this->getMetadataValue(self::KEY_CONFIGURATION))) {
            throw new ApplicationException('No configuration id provided.');
        }
        if (!is_string($this->getMetadataValue(self::KEY_CONFIGURATION))) {
            throw new ApplicationException('Configuration id is invalid.');
        }
    }

    /**
     * @inheritdoc
     */
    public function getPrefix(): string
    {
        return 'KBC::ConfigSecure::';
    }
}
