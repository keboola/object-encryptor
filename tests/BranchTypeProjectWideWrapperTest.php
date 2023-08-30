<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\ObjectEncryptor;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeConfigurationGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeProjectWideAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeProjectWideGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeProjectWideKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\GkmsClientFactory;
use Keboola\ObjectEncryptor\Wrapper\KmsClientFactory;

class BranchTypeProjectWideWrapperTest extends AbstractTestCase
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
     * @return BranchTypeProjectWideAKVWrapper[][]|BranchTypeProjectWideGKMSWrapper[][]|BranchTypeProjectWideKMSWrapper[][]
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

        $branchTypeProjectWideWrapperAKV = new BranchTypeProjectWideAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: self::getAkvUrl(),
        ));

        $branchTypeProjectWideWrapperGKMS = new BranchTypeProjectWideGKMSWrapper(
            (new GkmsClientFactory())->createClient($gkmsOptions),
            $gkmsOptions,
        );

        $branchTypeProjectWideWrapperKMS = new BranchTypeProjectWideKMSWrapper(
            (new KmsClientFactory())->createClient($kmsOptions),
            $kmsOptions,
        );

        return [
            'AKV' => [
                $branchTypeProjectWideWrapperAKV,
            ],
            'GKMS' => [
                $branchTypeProjectWideWrapperGKMS,
            ],
            'KMS' => [
                $branchTypeProjectWideWrapperKMS,
            ],
        ];
    }

    /**
     * @dataProvider wrapperProvider
     * @param BranchTypeProjectWideAKVWrapper|BranchTypeProjectWideGKMSWrapper|BranchTypeProjectWideKMSWrapper $wrapper
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
     * @param BranchTypeProjectWideAKVWrapper|BranchTypeProjectWideGKMSWrapper|BranchTypeProjectWideKMSWrapper $wrapper
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

    public function testInvalidSetupAKV(): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        new BranchTypeProjectWideAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: 'some-key',
            kmsRegion: 'some-region',
        ));
    }

    public function testInvalidSetupGKMS(): void
    {
        $options = new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'some-url'
        );

        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        new BranchTypeProjectWideGKMSWrapper(
            (new GkmsClientFactory())->createClient($options),
            $options,
        );
    }

    public function testInvalidSetupKMS(): void
    {
        $options = new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'some-url'
        );

        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        new BranchTypeProjectWideKMSWrapper(
            (new KmsClientFactory())->createClient($options),
            $options,
        );
    }

    /**
     * @dataProvider wrapperProvider
     * @param BranchTypeProjectWideAKVWrapper|BranchTypeProjectWideGKMSWrapper|BranchTypeProjectWideKMSWrapper $wrapper
     */
    public function testInvalidSetupEncryptProjectId($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No project id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @dataProvider wrapperProvider
     * @param BranchTypeProjectWideAKVWrapper|BranchTypeProjectWideGKMSWrapper|BranchTypeProjectWideKMSWrapper $wrapper
     */
    public function testInvalidSetupDecryptProjectId($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No project id provided.');
        $wrapper->decrypt('mySecretValue');
    }
}
