<?php

namespace Keboola\ObjectEncryptor\Wrapper;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

class BaseWrapper implements CryptoWrapperInterface
{
    /** @var \Crypto */
    protected $encryptor;

    /**
     * @var
     */
    protected $key;


    public function __construct($key)
    {
        if (strlen($key) >= 16) {
            $this->setKey(substr($key, 0, 16));
        } else {
            throw new ApplicationException("Encryption key too short. Minimum is 16 bytes.");
        }

        $this->setEncryptor(new \Crypto());
    }


    /**
     * @return mixed
     */
    protected function getKey()
    {
        return $this->key;
    }

    /**
     * @param mixed $key
     * @return $this
     */
    protected function setKey($key)
    {
        $this->key = $key;

        return $this;
    }

    /**
     * @return \Crypto
     */
    protected function getEncryptor()
    {
        return $this->encryptor;
    }

    /**
     * @param \Crypto $encryptor
     * @return $this
     */
    protected function setEncryptor($encryptor)
    {
        $this->encryptor = $encryptor;

        return $this;
    }

    /**
     * @param $data string data to encrypt
     * @return string encrypted data
     */
    public function encrypt($data)
    {
        return base64_encode($this->getEncryptor()->Encrypt($data, $this->getKey()));
    }

    /**
     * @param $encryptedData string
     * @return string decrypted data
     */
    public function decrypt($encryptedData)
    {
        return $this->getEncryptor()->Decrypt(base64_decode($encryptedData), $this->getKey());
    }

    /**
     * @inheritdoc
     */
    public function getPrefix()
    {
        return 'KBC::Encrypted==';
    }
}
