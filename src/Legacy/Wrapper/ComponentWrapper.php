<?php

namespace Keboola\ObjectEncryptor\Legacy\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

class ComponentWrapper extends BaseWrapper
{
    /**
     * @var string
     */
    protected $componentId;

    /**
     * @return mixed
     */
    public function getComponentId()
    {
        return $this->componentId;
    }

    /**
     * @param mixed $componentId
     * @return $this
     */
    public function setComponentId($componentId)
    {
        $this->componentId = $componentId;

        return $this;
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
        $fullKey = $this->getComponentId() . "-" . parent::getKey();
        $key = substr(hash('sha256', $fullKey), 0, 16);
        return $key;
    }

    /**
     * @inheritdoc
     */
    public function getPrefix()
    {
        return "KBC::ComponentEncrypted==";
    }
}
