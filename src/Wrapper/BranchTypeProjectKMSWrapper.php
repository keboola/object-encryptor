<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

/**
 * @internal Use ObjectEncryptor
 */
class BranchTypeProjectKMSWrapper extends ProjectKMSWrapper
{
    use BranchTypeWrapperTrait;

    protected function validateState(): void
    {
        parent::validateState();
        if (empty($this->getMetadataValue(self::KEY_BRANCH_TYPE))) {
            throw new ApplicationException('Branch type not provided.');
        }
    }

    public static function getPrefix(): string
    {
        return 'KBC::BranchTypeSecure::';
    }
}
