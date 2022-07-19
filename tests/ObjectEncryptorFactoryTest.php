<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\ObjectEncryptorFactory;
use PHPUnit\Framework\TestCase;

class ObjectEncryptorFactoryTest extends TestCase
{
    public function setUp(): void
    {
        parent::setUp();
        putenv('AWS_ACCESS_KEY_ID=' . getenv('TEST_AWS_ACCESS_KEY_ID'));
        putenv('AWS_SECRET_ACCESS_KEY='. getenv('TEST_AWS_SECRET_ACCESS_KEY'));
        putenv('AZURE_TENANT_ID=' . getenv('TEST_TENANT_ID'));
        putenv('AZURE_CLIENT_ID=' . getenv('TEST_CLIENT_ID'));
        putenv('AZURE_CLIENT_SECRET=' . getenv('TEST_CLIENT_SECRET'));
    }

    public function testGetAwsEncryptor(): void
    {
        $encryptor = ObjectEncryptorFactory::getAwsEncryptor(
            'my-stack',
            (string) getenv('TEST_AWS_KMS_KEY_ID'),
            (string) getenv('TEST_AWS_REGION')
        );
        $encrypted = $encryptor->encryptForComponent('secret', 'my-component');
        self::assertIsString($encrypted);
        self::assertStringStartsWith('KBC::ComponentSecure::', (string) $encrypted);
    }

    public function testGetAzureEncryptor(): void
    {
        $encryptor = ObjectEncryptorFactory::getAzureEncryptor(
            'my-stack',
            (string) getenv('TEST_KEY_VAULT_URL')
        );
        $encrypted = $encryptor->encryptForComponent('secret', 'my-component');
        self::assertIsString($encrypted);
        self::assertStringStartsWith('KBC::ComponentSecureKV::', (string) $encrypted);
    }

    public function testGetEncryptor(): void
    {
        $encryptor = ObjectEncryptorFactory::getEncryptor(
            new EncryptorOptions(
                'my-stack',
                (string) getenv('TEST_AWS_KMS_KEY_ID'),
                (string) getenv('TEST_AWS_REGION'),
                (string) getenv('TEST_KEY_VAULT_URL')
            )
        );
        $encrypted = $encryptor->encryptForComponent('secret', 'my-component');
        self::assertIsString($encrypted);
        // keyvault is used as default
        self::assertStringStartsWith('KBC::ComponentSecureKV::', (string) $encrypted);

        $awsEncryptor = ObjectEncryptorFactory::getAwsEncryptor(
            'my-stack',
            (string) getenv('TEST_AWS_KMS_KEY_ID'),
            (string) getenv('TEST_AWS_REGION')
        );
        $awsEncrypted = $awsEncryptor->encryptForComponent('secret', 'my-component');
        self::assertIsString($awsEncrypted);
        // AWS ciphers can be decrypted as well
        self::assertStringStartsWith('KBC::ComponentSecure::', (string) $awsEncrypted);
        self::assertEquals(
            'secret',
            $encryptor->decryptForComponent($awsEncrypted, 'my-component')
        );
    }
}
