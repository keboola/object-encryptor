<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Wrapper\CryptoWrapperInterface;

class MockCryptoWrapper implements CryptoWrapperInterface
{
    public function getPrefix(): string
    {
        return 'KBC::MockCryptoWrapper==';
    }

    public function encrypt(string $data): string
    {
        return $data;
    }

    public function decrypt(string $encryptedData): string
    {
        return $encryptedData;
    }
}
