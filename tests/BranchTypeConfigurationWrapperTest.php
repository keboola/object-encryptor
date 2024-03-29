<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\ObjectEncryptor;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeConfigurationGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeConfigurationKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeProjectKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\GkmsClientFactory;
use Keboola\ObjectEncryptor\Wrapper\KmsClientFactory;

class BranchTypeConfigurationWrapperTest extends AbstractTestCase
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
     * @return BranchTypeConfigurationAKVWrapper[][]|BranchTypeConfigurationKMSWrapper[][]|BranchTypeConfigurationGKMSWrapper[][]
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

        $branchTypeConfigurationWrapperKMS = new BranchTypeConfigurationKMSWrapper(
            (new KmsClientFactory())->createClient($kmsOptions),
            $kmsOptions,
        );

        $branchTypeConfigurationWrapperAKV = new BranchTypeConfigurationAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: self::getAkvUrl(),
        ));

        $branchTypeConfigurationWrapperGKMS = new BranchTypeConfigurationGKMSWrapper(
            (new GkmsClientFactory())->createClient($gkmsOptions),
            $gkmsOptions,
        );

        return [
            'AKV' => [
                $branchTypeConfigurationWrapperAKV,
            ],
            'GKMS' => [
                $branchTypeConfigurationWrapperGKMS,
            ],
            'KMS' => [
                $branchTypeConfigurationWrapperKMS,
            ],
        ];
    }

    /**
     * // phpcs:ignore Generic.Files.LineLength
     * @param BranchTypeConfigurationAKVWrapper|BranchTypeConfigurationGKMSWrapper|BranchTypeConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncrypt($wrapper): void
    {
        $secret = 'mySecretValue';
        $wrapper->setComponentId('dummy-component');
        $wrapper->setBranchType(ObjectEncryptor::BRANCH_TYPE_DEFAULT);
        $wrapper->setProjectId('my-project');
        $wrapper->setConfigurationId('my-configuration');

        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * // phpcs:ignore Generic.Files.LineLength
     * @param BranchTypeConfigurationAKVWrapper|BranchTypeConfigurationGKMSWrapper|BranchTypeConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncryptDifferentBranchType($wrapper): void
    {
        // this is the important test
        $wrapper->setComponentId('dummy-component');
        $wrapper->setBranchType(ObjectEncryptor::BRANCH_TYPE_DEFAULT);
        $wrapper->setProjectId('my-project');
        $wrapper->setConfigurationId('my-configuration');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $wrapper->setConfigurationId('my-configuration');
        $wrapper->setBranchType(ObjectEncryptor::BRANCH_TYPE_DEV);
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    /**
     * // phpcs:ignore Generic.Files.LineLength
     * @param BranchTypeConfigurationAKVWrapper|BranchTypeConfigurationGKMSWrapper|BranchTypeConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncryptDifferentConfiguration($wrapper): void
    {
        // this is the important test
        $wrapper->setComponentId('dummy-component');
        $wrapper->setBranchType(ObjectEncryptor::BRANCH_TYPE_DEFAULT);
        $wrapper->setProjectId('my-project');
        $wrapper->setConfigurationId('my-configuration');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $wrapper->setConfigurationId('my-other-configuration');
        $wrapper->setBranchType(ObjectEncryptor::BRANCH_TYPE_DEFAULT);
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    /**
     * // phpcs:ignore Generic.Files.LineLength
     * @param BranchTypeConfigurationAKVWrapper|BranchTypeConfigurationGKMSWrapper|BranchTypeConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncryptDifferentProject($wrapper): void
    {
        $wrapper->setComponentId('dummy-component');
        $wrapper->setBranchType(ObjectEncryptor::BRANCH_TYPE_DEFAULT);
        $wrapper->setProjectId('my-project');
        $wrapper->setConfigurationId('my-configuration');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setComponentId('dummy-component');
        $wrapper->setBranchType(ObjectEncryptor::BRANCH_TYPE_DEFAULT);
        $wrapper->setProjectId('some-other-project');
        $wrapper->setConfigurationId('my-configuration');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    public function testInvalidSetupKMS(): void
    {
        $options = new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'some-url',
        );

        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        new BranchTypeConfigurationKMSWrapper(
            (new KmsClientFactory())->createClient($options),
            $options,
        );
    }

    public function testInvalidSetupAKV(): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        new BranchTypeConfigurationAKVWrapper(new EncryptorOptions(
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
        new BranchTypeConfigurationGKMSWrapper(
            (new GkmsClientFactory())->createClient($options),
            $options,
        );
    }

    /**
     * // phpcs:ignore Generic.Files.LineLength
     * @param BranchTypeConfigurationAKVWrapper|BranchTypeConfigurationGKMSWrapper|BranchTypeConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptComponentId($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * // phpcs:ignore Generic.Files.LineLength
     * @param BranchTypeConfigurationAKVWrapper|BranchTypeConfigurationGKMSWrapper|BranchTypeConfigurationKMSWrapper $wrapper
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
     * // phpcs:ignore Generic.Files.LineLength
     * @param BranchTypeConfigurationAKVWrapper|BranchTypeConfigurationGKMSWrapper|BranchTypeConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptConfigurationId($wrapper): void
    {
        $wrapper->setComponentId('component-id');
        $wrapper->setProjectId('my-project');
        $wrapper->setConfigurationId('my-configuration');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Branch type not provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * // phpcs:ignore Generic.Files.LineLength
     * @param BranchTypeConfigurationAKVWrapper|BranchTypeConfigurationGKMSWrapper|BranchTypeConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptBranchType($wrapper): void
    {
        $wrapper->setComponentId('component-id');
        $wrapper->setProjectId('my-project');
        $wrapper->setConfigurationId('my-configuration');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Branch type not provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * // phpcs:ignore Generic.Files.LineLength
     * @param BranchTypeConfigurationAKVWrapper|BranchTypeConfigurationGKMSWrapper|BranchTypeConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptComponentId($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No component id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * // phpcs:ignore Generic.Files.LineLength
     * @param BranchTypeConfigurationAKVWrapper|BranchTypeConfigurationGKMSWrapper|BranchTypeConfigurationKMSWrapper $wrapper
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
     * // phpcs:ignore Generic.Files.LineLength
     * @param BranchTypeConfigurationAKVWrapper|BranchTypeConfigurationGKMSWrapper|BranchTypeConfigurationKMSWrapper $wrapper
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

    /**
     * // phpcs:ignore Generic.Files.LineLength
     * @param BranchTypeConfigurationAKVWrapper|BranchTypeConfigurationGKMSWrapper|BranchTypeConfigurationKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptBranchType($wrapper): void
    {
        $wrapper->setComponentId('component-id');
        $wrapper->setProjectId('my-project');
        $wrapper->setConfigurationId('my-configuration');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Branch type not provided.');
        $wrapper->decrypt('mySecretValue');
    }
}
