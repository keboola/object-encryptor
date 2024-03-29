<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\GkmsClientFactory;
use Keboola\ObjectEncryptor\Wrapper\KmsClientFactory;

class ConfigurationWrapperTest extends AbstractTestCase
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
     * @return ConfigurationAKVWrapper[][]|ConfigurationGKMSWrapper[][]|ConfigurationKMSWrapper[][]
     */
    public function wrapperProvider(): array
    {
        putenv('GOOGLE_APPLICATION_CREDENTIALS=' . getenv('TEST_GOOGLE_APPLICATION_CREDENTIALS'));

        $kmsOptions = new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: self::getKmsKeyId(),
            kmsRegion: self::getKmsRegion(),
            backoffMaxTries: 1,
        );
        $gkmsOptions = new EncryptorOptions(
            stackId: 'some-stack',
            gkmsKeyId: self::getGkmsKeyId(),
            backoffMaxTries: 1,
        );

        $configurationWrapperAKV = new ConfigurationAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: self::getAkvUrl(),
        ));
        $configurationWrapperGKMS = new ConfigurationGKMSWrapper(
            (new GkmsClientFactory())->createClient($gkmsOptions),
            $gkmsOptions,
        );
        $configurationWrapperKMS = new ConfigurationKMSWrapper(
            (new KmsClientFactory())->createClient($kmsOptions),
            $kmsOptions,
        );

        return [
            'AKV' => [
                $configurationWrapperAKV,
            ],
            'GKMS' => [
                $configurationWrapperGKMS,
            ],
            'KMS' => [
                $configurationWrapperKMS,
            ],
        ];
    }

    /**
     * @param ConfigurationAKVWrapper|ConfigurationGKMSWrapper|ConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncrypt($wrapper): void
    {
        $secret = 'mySecretValue';
        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('my-configuration');
        $wrapper->setProjectId('my-project');

        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @param ConfigurationAKVWrapper|ConfigurationGKMSWrapper|ConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncryptDifferentConfiguration($wrapper): void
    {
        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('my-configuration');
        $wrapper->setProjectId('my-project');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $wrapper->setConfigurationId('some-other-configuration');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    /**
     * @param ConfigurationAKVWrapper|ConfigurationGKMSWrapper|ConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncryptDifferentProject($wrapper): void
    {
        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('my-configuration');
        $wrapper->setProjectId('my-project');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('my-configuration');
        $wrapper->setProjectId('some-other-project');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    public function testInvalidSetupAKV(): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        new ConfigurationAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: 'some-key-id',
            kmsRegion: 'some-region',
        ));
    }

    public function testInvalidSetupGKMS(): void
    {
        $options = new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'some-url',
        );

        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        new ConfigurationGKMSWrapper(
            (new GkmsClientFactory())->createClient($options),
            $options,
        );
    }

    public function testInvalidSetupKMS(): void
    {
        $options = new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'some-url',
        );

        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        new ConfigurationKMSWrapper(
            (new KmsClientFactory())->createClient($options),
            $options,
        );
    }

    /**
     * @param ConfigurationAKVWrapper|ConfigurationGKMSWrapper|ConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptComponentId($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @param ConfigurationAKVWrapper|ConfigurationGKMSWrapper|ConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptProjectId($wrapper): void
    {
        $wrapper->setComponentId('component-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No project id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @param ConfigurationAKVWrapper|ConfigurationGKMSWrapper|ConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptConfigurationId($wrapper): void
    {
        $wrapper->setComponentId('component-id');
        $wrapper->setProjectId('my-project');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No configuration id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @param ConfigurationAKVWrapper|ConfigurationGKMSWrapper|ConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptComponentId($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No component id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @param ConfigurationAKVWrapper|ConfigurationGKMSWrapper|ConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptProjectId($wrapper): void
    {
        $wrapper->setComponentId('component-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No project id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @param ConfigurationAKVWrapper|ConfigurationGKMSWrapper|ConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptConfigurationId($wrapper): void
    {
        $wrapper->setComponentId('component-id');
        $wrapper->setProjectId('my-project');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No configuration id provided.');
        $wrapper->decrypt('mySecretValue');
    }
}
