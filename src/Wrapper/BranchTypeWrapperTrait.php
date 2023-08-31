<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

/**
 * @internal Use ObjectEncryptor
 */
trait BranchTypeWrapperTrait
{
    abstract public function setMetadataValue(string $key, string $value): void;

    private const KEY_BRANCH_TYPE = 'branchType';

    public function setBranchType(string $branchType): void
    {
        $this->setMetadataValue(self::KEY_BRANCH_TYPE, $branchType);
    }
}
