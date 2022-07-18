<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\CryptoWrapperInterface;
use Keboola\ObjectEncryptor\Wrapper\ProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectKMSWrapper;
use PHPUnit\Framework\TestCase;

class ProjectWrapperTest extends TestCase
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
     * @return CryptoWrapperInterface[][]
     */
    public function wrapperProvider(): array
    {
        $projectWrapperKMS = new ProjectKMSWrapper();
        $projectWrapperKMS->setKMSRegion(getenv('TEST_AWS_REGION'));
        $projectWrapperKMS->setKMSKeyId(getenv('TEST_AWS_KMS_KEY_ID'));

        $projectWrapperAKV = new ProjectAKVWrapper();
        $projectWrapperAKV->setKeyVaultUrl(getenv('TEST_KEY_VAULT_URL'));

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
     */
    public function testEncrypt(CryptoWrapperInterface $wrapper): void
    {
        $secret = 'mySecretValue';
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @dataProvider wrapperProvider
     */
    public function testEncryptDifferentProject(CryptoWrapperInterface $wrapper): void
    {
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('some-other-project');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    /**
     * @dataProvider wrapperProvider
     */
    public function testEncryptDifferentComponent(CryptoWrapperInterface $wrapper): void
    {
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setStackId('my-stack');
        $wrapper->setProjectId('my-project');
        $wrapper->setComponentId('some-other-component');
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
     */
    public function testInvalidSetupEncryptStackAndComponent(CryptoWrapperInterface $wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptProjectId(CryptoWrapperInterface $wrapper): void
    {
        $wrapper->setComponentId('component-id');
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
     */
    public function testInvalidSetupDecryptStackAndComponent(CryptoWrapperInterface $wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptProjectId(CryptoWrapperInterface $wrapper): void
    {
        $wrapper->setComponentId('component-id');
        $wrapper->setStackId('my-stack');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No project id provided.');
        $wrapper->decrypt('mySecretValue');
    }
}
