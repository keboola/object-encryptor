<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

/**
 * @internal Use ObjectEncryptor
 */
class ProjectKMSWrapper extends ComponentKMSWrapper
{
    private const KEY_PROJECT = 'projectId';

    public function setProjectId(string $projectId): void
    {
        $this->setMetadataValue(self::KEY_PROJECT, $projectId);
    }

    protected function validateState(): void
    {
        parent::validateState();
        if (empty($this->getMetadataValue(self::KEY_PROJECT))) {
            throw new ApplicationException('No project id provided.');
        }
        if (!is_string($this->getMetadataValue(self::KEY_PROJECT))) {
            throw new ApplicationException('Project id is invalid.');
        }
    }

    public function getPrefix(): string
    {
        return 'KBC::ProjectSecure::';
    }
}
