<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\ObjectEncryptor;
use Keboola\ObjectEncryptor\Wrapper\ProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectWideBranchTypeAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectWideBranchTypeKMSWrapper;

class ProjectWideBranchTypeWrapperTest extends AbstractTestCase
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
     * @return ProjectWideBranchTypeAKVWrapper[][]|ProjectWideBranchTypeKMSWrapper[][]
     */
    public function wrapperProvider(): array
    {
        $projectWrapperKMS = new ProjectWideBranchTypeKMSWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: self::getKmsKeyId(),
            kmsRegion: self::getKmsRegion(),
            backoffMaxTries: 1,
        ));

        $projectWrapperAKV = new ProjectWideBranchTypeAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: self::getAkvUrl(),
        ));

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
     * @param ProjectWideBranchTypeAKVWrapper|ProjectWideBranchTypeKMSWrapper $wrapper
     */
    public function testEncrypt($wrapper): void
    {
        $secret = 'mySecretValue';
        $wrapper->setProjectId('my-project');
        $wrapper->setBranchType(ObjectEncryptor::BRANCH_TYPE_DEV);
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectWideBranchTypeAKVWrapper|ProjectWideBranchTypeKMSWrapper $wrapper
     */
    public function testEncryptDifferentProject($wrapper): void
    {
        $wrapper->setProjectId('my-project');
        $wrapper->setBranchType(ObjectEncryptor::BRANCH_TYPE_DEV);
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setProjectId('some-other-project');
        $wrapper->setBranchType(ObjectEncryptor::BRANCH_TYPE_DEFAULT);
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    public function testInvalidSetupKMS(): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        new ProjectKMSWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'some-url'
        ));
    }

    public function testInvalidSetupAKV(): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        new ProjectAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: 'some-key',
            kmsRegion: 'some-region',
        ));
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectWideBranchTypeAKVWrapper|ProjectWideBranchTypeKMSWrapper $wrapper
     */
    public function testInvalidSetupEncryptProjectId($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No project id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectWideBranchTypeAKVWrapper|ProjectWideBranchTypeKMSWrapper $wrapper
     */
    public function testInvalidSetupDecryptProjectId($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No project id provided.');
        $wrapper->decrypt('mySecretValue');
    }
}