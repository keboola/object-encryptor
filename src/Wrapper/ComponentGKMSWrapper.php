<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Aws\Kms\KmsClient;
use Google\Cloud\Kms\V1\KeyManagementServiceClient;
use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;

/**
 * @internal Use ObjectEncryptor
 */
class ComponentGKMSWrapper extends GenericGKMSWrapper
{
    private const KEY_COMPONENT = 'componentId';
    private const KEY_STACK = 'stackId';

    public function setComponentId(string $componentId): void
    {
        $this->setMetadataValue(self::KEY_COMPONENT, $componentId);
    }

    public function __construct(KeyManagementServiceClient $gkmsClient, EncryptorOptions $encryptorOptions)
    {
        parent::__construct($gkmsClient, $encryptorOptions);
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
        return 'KBC::ComponentSecureGKMS::';
    }
}
