<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\ComponentAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentKMSWrapper;
use PHPUnit\Framework\TestCase;

class AbstractTestCase extends TestCase
{
    /**
     * @return non-empty-string
     */
    protected static function getKmsKeyId(): string
    {
        $kmsKeyId = (string) getenv('TEST_AWS_KMS_KEY_ID');
        self::assertNotEmpty($kmsKeyId);
        return $kmsKeyId;
    }

    /**
     * @return non-empty-string
     */
    protected static function getKmsRegion(): string
    {
        $kmsRegion = (string) getenv('TEST_AWS_REGION');
        self::assertNotEmpty($kmsRegion);
        return $kmsRegion;
    }

    /**
     * @return non-empty-string
     */
    protected static function getAkvUrl(): string
    {
        $akvUrl = (string) getenv('TEST_KEY_VAULT_URL');
        self::assertNotEmpty($akvUrl);
        return $akvUrl;
    }

    /**
     * @return non-empty-string
     */
    protected static function getKmsRoleId(): string
    {
        $kmsRoleId = (string) getenv('TEST_AWS_KMS_ROLE_ID');
        // @phpstan-ignore-next-line
        return $kmsRoleId;
    }
}
