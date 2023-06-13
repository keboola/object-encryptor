<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\ObjectEncryptor;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationKMSWrapper;

class BranchTypeWrapperTest extends AbstractTestCase
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
     * @return BranchTypeAKVWrapper[][]|BranchTypeKMSWrapper[][]
     */
    public function wrapperProvider(): array
    {
        $branchTypeWrapperKMS = new BranchTypeKMSWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: self::getKmsKeyId(),
            kmsRegion: self::getKmsRegion(),
            backoffMaxTries: 1,
        ));

        $branchTypeWrapperAKV = new BranchTypeAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: self::getAkvUrl(),
        ));

        return [
            'KMS' => [
                $branchTypeWrapperKMS,
            ],
            'AKV' => [
                $branchTypeWrapperAKV,
            ],
        ];
    }

    /**
     * @param BranchTypeAKVWrapper|BranchTypeKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncrypt($wrapper): void
    {
        $secret = 'mySecretValue';
        $wrapper->setComponentId('dummy-component');
        $wrapper->setBranchType(ObjectEncryptor::BRANCH_TYPE_DEFAULT);
        $wrapper->setProjectId('my-project');

        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @param BranchTypeAKVWrapper|BranchTypeKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncryptDifferentBranchType($wrapper): void
    {
        // this is the important test
        $wrapper->setComponentId('dummy-component');
        $wrapper->setBranchType(ObjectEncryptor::BRANCH_TYPE_DEFAULT);
        $wrapper->setProjectId('my-project');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $wrapper->setBranchType(ObjectEncryptor::BRANCH_TYPE_DEV);
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    /**
     * @param BranchTypeAKVWrapper|BranchTypeKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncryptDifferentProject($wrapper): void
    {
        $wrapper->setComponentId('dummy-component');
        $wrapper->setBranchType(ObjectEncryptor::BRANCH_TYPE_DEFAULT);
        $wrapper->setProjectId('my-project');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setComponentId('dummy-component');
        $wrapper->setBranchType(ObjectEncryptor::BRANCH_TYPE_DEFAULT);
        $wrapper->setProjectId('some-other-project');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    public function testInvalidSetupKMS(): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        new ConfigurationKMSWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'some-url',
        ));
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

    /**
     * @param BranchTypeAKVWrapper|BranchTypeKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptComponentId($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @param BranchTypeAKVWrapper|BranchTypeKMSWrapper $wrapper
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
     * @param BranchTypeAKVWrapper|BranchTypeKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptConfigurationId($wrapper): void
    {
        $wrapper->setComponentId('component-id');
        $wrapper->setProjectId('my-project');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Branch type not provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @param BranchTypeAKVWrapper|BranchTypeKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptComponentId($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No component id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @param BranchTypeAKVWrapper|BranchTypeKMSWrapper $wrapper
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
     * @param BranchTypeAKVWrapper|BranchTypeKMSWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptConfigurationId($wrapper): void
    {
        $wrapper->setComponentId('component-id');
        $wrapper->setProjectId('my-project');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Branch type not provided.');
        $wrapper->decrypt('mySecretValue');
    }
}
