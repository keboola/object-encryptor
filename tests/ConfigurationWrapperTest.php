<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\CryptoWrapperInterface;
use PHPUnit\Framework\TestCase;

class ConfigurationWrapperTest extends TestCase
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
        $configurationWrapperKMS = new ConfigurationKMSWrapper();
        $configurationWrapperKMS->setKMSRegion(getenv('TEST_AWS_REGION'));
        $configurationWrapperKMS->setKMSKeyId(getenv('TEST_AWS_KMS_KEY_ID'));

        $configurationWrapperAKV = new ConfigurationAKVWrapper();
        $configurationWrapperAKV->setKeyVaultUrl(getenv('TEST_KEY_VAULT_URL'));

        return [
            'KMS' => [
                $configurationWrapperKMS,
            ],
            'AKV' => [
                $configurationWrapperAKV,
            ],
        ];
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncrypt(CryptoWrapperInterface $wrapper): void
    {
        $secret = 'mySecretValue';
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('my-configuration');
        $wrapper->setProjectId('my-project');

        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('my-configuration');
        $wrapper->setProjectId('my-project');
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncryptDifferentConfiguration(CryptoWrapperInterface $wrapper): void
    {
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('my-configuration');
        $wrapper->setProjectId('my-project');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $wrapper->setConfigurationId('some-other-configuration');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncryptDifferentProject(CryptoWrapperInterface $wrapper): void
    {
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('my-configuration');
        $wrapper->setProjectId('my-project');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('my-configuration');
        $wrapper->setProjectId('some-other-project');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    public function testInvalidSetupEncryptKMS(): void
    {
        $wrapper = new ConfigurationKMSWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupEncryptAKV(): void
    {
        $wrapper = new ConfigurationAKVWrapper();
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

    /**
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptConfigurationId(CryptoWrapperInterface $wrapper): void
    {
        $wrapper->setComponentId('component-id');
        $wrapper->setStackId('my-stack');
        $wrapper->setProjectId('my-project');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No configuration id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupDecryptKMS(): void
    {
        $wrapper = new ConfigurationKMSWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidSetupDecryptAKV(): void
    {
        $wrapper = new ConfigurationAKVWrapper();
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

    /**
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptConfigurationId(CryptoWrapperInterface $wrapper): void
    {
        $wrapper->setComponentId('component-id');
        $wrapper->setStackId('my-stack');
        $wrapper->setProjectId('my-project');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No configuration id provided.');
        $wrapper->decrypt('mySecretValue');
    }
}
