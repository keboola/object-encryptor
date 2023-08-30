<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor;

class ObjectEncryptorFactory
{
    /**
     * @param non-empty-string $stackId
     * @param non-empty-string $kmsKeyId
     * @param non-empty-string $kmsRegion
     * @param non-empty-string|null $kmsRole
     * @return ObjectEncryptor
     */
    public static function getAwsEncryptor(
        string $stackId,
        string $kmsKeyId,
        string $kmsRegion,
        ?string $kmsRole
    ): ObjectEncryptor {
        $encryptOptions = new EncryptorOptions($stackId, $kmsKeyId, $kmsRegion, $kmsRole, null);
        return self::getEncryptor($encryptOptions);
    }

    /**
     * @param non-empty-string $stackId
     * @param non-empty-string $keyVaultUrl
     * @return ObjectEncryptor
     */
    public static function getAzureEncryptor(string $stackId, string $keyVaultUrl): ObjectEncryptor
    {
        $encryptOptions = new EncryptorOptions($stackId, null, null, null, $keyVaultUrl);
        return self::getEncryptor($encryptOptions);
    }

    /**
     * @param non-empty-string $stackId
     * @param non-empty-string $gkmsKeyId
     * @return ObjectEncryptor
     */
    public static function getGcpEncryptor(string $stackId, string $gkmsKeyId): ObjectEncryptor
    {
        $encryptOptions = new EncryptorOptions(stackId: $stackId, gkmsKeyId: $gkmsKeyId);
        return self::getEncryptor($encryptOptions);
    }

    public static function getEncryptor(EncryptorOptions $encryptorOptions): ObjectEncryptor
    {
        return new ObjectEncryptor($encryptorOptions);
    }
}
