<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

/**
 * @internal Use ObjectEncryptor
 */
class ProjectWideKMSWrapper extends GenericKMSWrapper
{
    private const KEY_STACK = 'stackId';
    private const KEY_PROJECT = 'projectId';

    public function setStackId(string $stackId): void
    {
        $this->setMetadataValue(self::KEY_STACK, $stackId);
    }

    public function setProjectId(string $projectId): void
    {
        $this->setMetadataValue(self::KEY_PROJECT, $projectId);
    }

    protected function validateState(): void
    {
        parent::validateState();
        if (empty($this->getMetadataValue(self::KEY_STACK))) {
            throw new ApplicationException('No stack id provided.');
        }
        if (empty($this->getMetadataValue(self::KEY_PROJECT))) {
            throw new ApplicationException('No project id provided.');
        }
    }

    public function getPrefix(): string
    {
        return 'KBC::ProjectWideSecure::';
    }
}
