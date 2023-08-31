<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

/**
 * @internal Use ObjectEncryptor
 */
class ConfigurationGKMSWrapper extends ProjectGKMSWrapper
{
    private const KEY_CONFIGURATION = 'configurationId';

    public function setConfigurationId(string $configurationId): void
    {
        $this->setMetadataValue(self::KEY_CONFIGURATION, $configurationId);
    }

    protected function validateState(): void
    {
        parent::validateState();
        if (empty($this->getMetadataValue(self::KEY_CONFIGURATION))) {
            throw new ApplicationException('No configuration id provided.');
        }
    }

    public static function getPrefix(): string
    {
        return 'KBC::ConfigSecureGKMS::';
    }
}
