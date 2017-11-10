<?php

namespace Keboola\ObjectEncryptor\Legacy;

use Keboola\Encryption\AesEncryptor;
use Keboola\Encryption\EncryptorInterface;

/**
 * Class Encryptor
 * @package Keboola\Syrup\Encryption
 * @deprecated Use ObjectEncryptor service
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
     * @param $data string data to encrypt
     * @return string encrypted data
     * @deprecated
     */
    public function encrypt($data)
    {
        return base64_encode($this->encryptor->encrypt($data));
    }

    /**
     * @param $encryptedData string
     * @return string decrypted data
     * @deprecated
     */
    public function decrypt($encryptedData)
    {
        return $this->encryptor->decrypt(base64_decode($encryptedData));
    }
}
