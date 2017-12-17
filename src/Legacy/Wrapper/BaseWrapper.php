<?php

namespace Keboola\ObjectEncryptor\Legacy\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Wrapper\CryptoWrapperInterface;

class BaseWrapper implements CryptoWrapperInterface
{
    /** @var \Crypto */
    private $encryptor;

    /**
     * @var string
     */
    private $key;

    /**
     * BaseWrapper constructor.
     */
    public function __construct()
    {
        $this->encryptor = new \Crypto();
    }

    /**
     * @param string $key
     * @throws ApplicationException
     */
    public function setKey($key)
    {
        if (strlen($key) >= 16) {
            $this->key = substr($key, 0, 16);
        } else {
            throw new ApplicationException("Encryption key too short. Minimum is 16 bytes.");
        }
    }

    /**
     * @return string
     */
    protected function getKey()
    {
        return $this->key;
    }

    /**
     * @inheritdoc
     * @throws \CannotPerformOperationException
     */
    public function encrypt($data)
    {
        return base64_encode($this->encryptor->Encrypt($data, $this->getKey()));
    }

    /**
     * @inheritdoc
     * @throws \CannotPerformOperationException
     * @throws \InvalidCiphertextException
     */
    public function decrypt($encryptedData)
    {
        return $this->encryptor->Decrypt(base64_decode($encryptedData), $this->getKey());
    }

    /**
     * @inheritdoc
     */
    public function getPrefix()
    {
        return 'KBC::Encrypted==';
    }
}
