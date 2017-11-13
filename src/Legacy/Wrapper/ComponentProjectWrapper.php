<?php

namespace Keboola\ObjectEncryptor\Legacy\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

class ComponentProjectWrapper extends ComponentWrapper
{
    /**
     * @var string
     */
    private $projectId;

    /**
     * @return string
     */
    public function getProjectId()
    {
        return $this->projectId;
    }

    /**
     * @param string $projectId
     */
    public function setProjectId($projectId)
    {
        $this->projectId = $projectId;
    }

    /**
     * @return string
     * @throws ApplicationException
     */
    protected function getKey()
    {
        if (!$this->getComponentId()) {
            throw new ApplicationException("ComponentId not set");
        }
        if (!$this->getProjectId()) {
            throw new ApplicationException("ProjectId not set");
        }
        $fullKey = $this->getComponentId() . "-" . $this->getProjectId() . "-" . parent::getKey();
        $key = substr(hash('sha256', $fullKey), 0, 16);
        return $key;
    }

    /**
     * @inheritdoc
     */
    public function getPrefix()
    {
        return "KBC::ComponentProjectEncrypted==";
    }
}
