<?php

namespace Keboola\ObjectEncryptor\Legacy;

use Keboola\Encryption\AesEncryptor;
use Keboola\Encryption\EncryptorInterface;

/**
 * Class Encryptor
 * @deprecated Use ObjectEncryptorFactory
 */
class Encryptor implements EncryptorInterface
{
    /** @var AesEncryptor */
    protected $encryptor;

    public function __construct($key)
    {
        $this->encryptor = new AesEncryptor($key);
    }

    /**
     * @inheritdoc
     * @deprecated
     */
    public function encrypt($data)
    {
        return base64_encode($this->encryptor->encrypt($data));
    }

    /**
     * @inheritdoc
     * @deprecated
     */
    public function decrypt($encryptedData)
    {
        return $this->encryptor->decrypt(base64_decode($encryptedData));
    }
}
