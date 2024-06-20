<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\GkmsClientFactory;
use Keboola\ObjectEncryptor\Wrapper\KmsClientFactory;
use Keboola\ObjectEncryptor\Wrapper\ProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectWideAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectWideGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectWideKMSWrapper;

class ProjectWideWrapperTest extends AbstractTestCase
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
     * @return ProjectWideAKVWrapper[][]|ProjectWideGKMSWrapper[][]|ProjectWideKMSWrapper[][]
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

        $projectWrapperAKV = new ProjectWideAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: self::getAkvUrl(),
        ));
        $projectWrapperKMS = new ProjectWideGKMSWrapper(
            (new GkmsClientFactory())->createClient($gkmsOptions),
            $gkmsOptions,
        );
        $projectWrapperGKMS = new ProjectWideKMSWrapper(
            (new KmsClientFactory())->createClient($kmsOptions),
            $kmsOptions,
        );

        return [
            'AKV' => [
                $projectWrapperAKV,
            ],
            'GKMS' => [
                $projectWrapperGKMS,
            ],
            'KMS' => [
                $projectWrapperKMS,
            ],
        ];
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectWideAKVWrapper|ProjectWideGKMSWrapper|ProjectWideKMSWrapper $wrapper
     */
    public function testEncrypt($wrapper): void
    {
        $secret = 'mySecretValue';
        $wrapper->setProjectId('my-project');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectWideAKVWrapper|ProjectWideGKMSWrapper|ProjectWideKMSWrapper $wrapper
     */
    public function testEncryptDifferentProject($wrapper): void
    {
        $wrapper->setProjectId('my-project');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setProjectId('some-other-project');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    public function testInvalidSetupAKV(): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        new ProjectWideAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: 'some-key',
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
        new ProjectWideGKMSWrapper(
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
        new ProjectWideKMSWrapper(
            (new KmsClientFactory())->createClient($options),
            $options,
        );
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectWideAKVWrapper|ProjectWideGKMSWrapper|ProjectWideKMSWrapper $wrapper
     */
    public function testInvalidSetupEncryptProjectId($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No project id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectWideAKVWrapper|ProjectWideGKMSWrapper|ProjectWideKMSWrapper $wrapper
     */
    public function testInvalidSetupDecryptProjectId($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No project id provided.');
        $wrapper->decrypt('mySecretValue');
    }
}
