<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectWideAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectWideKMSWrapper;
use PHPUnit\Framework\TestCase;

class ProjectWideWrapperTest extends TestCase
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

    /**
     * @return ProjectWideAKVWrapper[][]|ProjectWideKMSWrapper[][]
     */
    public function wrapperProvider(): array
    {
        $projectWrapperKMS = self::createPartialMock(ProjectWideKMSWrapper::class, ['getRetries']);
        $projectWrapperKMS->method('getRetries')->willReturn(1);

        $projectWrapperKMS->setKMSRegion((string) getenv('TEST_AWS_REGION'));
        $projectWrapperKMS->setKMSKeyId((string) getenv('TEST_AWS_KMS_KEY_ID'));

        $projectWrapperAKV = new ProjectWideAKVWrapper();
        $projectWrapperAKV->setKeyVaultUrl((string) getenv('TEST_KEY_VAULT_URL'));

        return [
            'KMS' => [
                $projectWrapperKMS,
            ],
            'AKV' => [
                $projectWrapperAKV,
            ],
        ];
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectWideKMSWrapper|ProjectWideAKVWrapper $wrapper
     */
    public function testEncrypt($wrapper): void
    {
        $secret = 'mySecretValue';
        $wrapper->setStackId('my-stack');
        $wrapper->setProjectId('my-project');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectWideKMSWrapper|ProjectWideAKVWrapper $wrapper
     */
    public function testEncryptDifferentProject($wrapper): void
    {
        $wrapper->setStackId('my-stack');
        $wrapper->setProjectId('my-project');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setStackId('my-stack');
        $wrapper->setProjectId('some-other-project');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    public function testInvalidSetupEncryptKMS(): void
    {
        $wrapper = new ProjectKMSWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupEncryptAKV(): void
    {
        $wrapper = new ProjectAKVWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectWideKMSWrapper|ProjectWideAKVWrapper $wrapper
     */
    public function testInvalidSetupEncryptStack($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectWideKMSWrapper|ProjectWideAKVWrapper $wrapper
     */
    public function testInvalidSetupEncryptProjectId($wrapper): void
    {
        $wrapper->setStackId('my-stack');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No project id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupDecryptKMS(): void
    {
        $wrapper = new ProjectKMSWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidSetupDecryptAKV(): void
    {
        $wrapper = new ProjectAKVWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectWideKMSWrapper|ProjectWideAKVWrapper $wrapper
     */
    public function testInvalidSetupDecryptStack($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectWideKMSWrapper|ProjectWideAKVWrapper $wrapper
     */
    public function testInvalidSetupDecryptProjectId($wrapper): void
    {
        $wrapper->setStackId('my-stack');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No project id provided.');
        $wrapper->decrypt('mySecretValue');
    }
}
