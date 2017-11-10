<?php

namespace Keboola\ObjectEncryptor\Wrapper;

interface CryptoWrapperInterface
{
    /**
     * Return a prefix for the encrypted string identifying this wrapper.
     *  It is important that this prefix is different for each wrapper.
     * @return string Cipher text prefix.
     */
    public function getPrefix();

    /**
     * @param $data string data to encrypt
     * @return string encrypted data
     */
    public function encrypt($data);

    /**
     * @param $encryptedData string
     * @return string decrypted data
     */
    public function decrypt($encryptedData);
}
