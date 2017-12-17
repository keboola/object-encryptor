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
     * @param string $data Data to encrypt.
     * @return string Encrypted data.
     */
    public function encrypt($data);

    /**
     * @param string $encryptedData Encrypted data.
     * @return string Decrypted data.
     */
    public function decrypt($encryptedData);
}
