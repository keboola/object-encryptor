<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

/**
 * @internal Use ObjectEncryptor
 */
class BranchTypeProjectKMSWrapper extends ProjectKMSWrapper
{
    private const KEY_BRANCH_TYPE = 'branchType';

    public function setBranchType(string $branchType): void
    {
        $this->setMetadataValue(self::KEY_BRANCH_TYPE, $branchType);
    }

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
