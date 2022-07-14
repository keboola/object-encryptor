<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

class ProjectAKVWrapper extends ComponentAKVWrapper
{
    private const KEY_PROJECT = 'projectId';

    /**
     * @param string $projectId
     */
    public function setProjectId($projectId)
    {
        $this->setMetadataValue(self::KEY_PROJECT, $projectId);
    }

    /**
     * Validate state of the wrapper before ciphering/deciphering
     * @throws ApplicationException
     */
    protected function validateState()
    {
        parent::validateState();
        if (empty($this->getMetadataValue(self::KEY_PROJECT))) {
            throw new ApplicationException('No project id provided.');
        }
        if (!is_string($this->getMetadataValue(self::KEY_PROJECT))) {
            throw new ApplicationException('Project id is invalid.');
        }
    }

    /**
     * @inheritdoc
     */
    public function getPrefix(): string
    {
        return 'KBC::ProjectSecureKV::';
    }
}
