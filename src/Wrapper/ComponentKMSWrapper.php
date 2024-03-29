<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Aws\Kms\KmsClient;
use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;

/**
 * @internal Use ObjectEncryptor
 */
class ComponentKMSWrapper extends GenericKMSWrapper
{
    private const KEY_COMPONENT = 'componentId';
    private const KEY_STACK = 'stackId';

    public function setComponentId(string $componentId): void
    {
        $this->setMetadataValue(self::KEY_COMPONENT, $componentId);
    }

    public function __construct(KmsClient $kmsClient, EncryptorOptions $encryptorOptions)
    {
        parent::__construct($kmsClient, $encryptorOptions);
        $this->setMetadataValue(self::KEY_STACK, $encryptorOptions->getStackId());
    }

    protected function validateState(): void
    {
        parent::validateState();
        if (empty($this->getMetadataValue(self::KEY_COMPONENT))) {
            throw new ApplicationException('No component id provided.');
        }
    }

    public static function getPrefix(): string
    {
        return 'KBC::ComponentSecure::';
    }
}
