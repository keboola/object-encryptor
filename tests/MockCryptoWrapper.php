<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Wrapper\CryptoWrapperInterface;

class MockCryptoWrapper implements CryptoWrapperInterface
{
    /**
     * @inheritdoc
     */
    public function getPrefix()
    {
        return 'KBC::MockCryptoWrapper==';
    }

    /**
     * @inheritdoc
     */
    public function encrypt($data)
    {
        return $data;
    }


    /**
     * @inheritdoc
     */
    public function decrypt($encryptedData)
    {
        return $encryptedData;
    }
}
