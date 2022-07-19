<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

/**
 * @internal Use ObjectEncryptor
 */
class ComponentAKVWrapper extends GenericAKVWrapper
{
    private const KEY_COMPONENT = 'componentId';
    private const KEY_STACK = 'stackId';

    public function setStackId(string $stackId): void
    {
        $this->setMetadataValue(self::KEY_STACK, $stackId);
    }

    public function setComponentId(string $componentId): void
    {
        $this->setMetadataValue(self::KEY_COMPONENT, $componentId);
    }

    protected function validateState(): void
    {
        parent::validateState();
        if (empty($this->getMetadataValue(self::KEY_STACK)) || empty($this->getMetadataValue(self::KEY_COMPONENT))) {
            throw new ApplicationException('No stack or component id provided.');
        }
    }

    public function getPrefix(): string
    {
        return 'KBC::ComponentSecureKV::';
    }
}
