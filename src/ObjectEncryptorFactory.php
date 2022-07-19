<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor;

class ObjectEncryptorFactory
{
    public static function getAwsEncryptor(string $stackId, string $kmsKeyId, string $kmsRegion): ObjectEncryptor
    {
        $encryptOptions = new EncryptorOptions($stackId, $kmsKeyId, $kmsRegion, null);
        return self::getEncryptor($encryptOptions);
    }

    public static function getAzureEncryptor(string $stackId, string $keyVaultUrl): ObjectEncryptor
    {
        $encryptOptions = new EncryptorOptions($stackId, null, null, $keyVaultUrl);
        return self::getEncryptor($encryptOptions);
    }

    public static function getEncryptor(EncryptorOptions $encryptorOptions): ObjectEncryptor
    {
        return new ObjectEncryptor($encryptorOptions);
    }
}
