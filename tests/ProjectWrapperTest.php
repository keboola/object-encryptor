<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\GkmsClientFactory;
use Keboola\ObjectEncryptor\Wrapper\KmsClientFactory;
use Keboola\ObjectEncryptor\Wrapper\ProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectKMSWrapper;

class ProjectWrapperTest extends AbstractTestCase
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
     * @return ProjectAKVWrapper[][]|ProjectGKMSWrapper[][]|ProjectKMSWrapper[][]
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

        $projectWrapperAKV = new ProjectAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: self::getAkvUrl(),
        ));
        $projectWrapperGKMS = new ProjectGKMSWrapper(
            (new GkmsClientFactory())->createClient($gkmsOptions),
            $gkmsOptions,
        );
        $projectWrapperKMS = new ProjectKMSWrapper(
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
     * @param ProjectAKVWrapper|ProjectGKMSWrapper|ProjectKMSWrapper $wrapper
     */
    public function testEncrypt($wrapper): void
    {
        $secret = 'mySecretValue';
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectAKVWrapper|ProjectGKMSWrapper|ProjectKMSWrapper $wrapper
     */
    public function testEncryptDifferentProject($wrapper): void
    {
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('some-other-project');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectAKVWrapper|ProjectGKMSWrapper|ProjectKMSWrapper $wrapper
     */
    public function testEncryptDifferentComponent($wrapper): void
    {
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setProjectId('my-project');
        $wrapper->setComponentId('some-other-component');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
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

    public function testInvalidSetupGKMS(): void
    {
        $options = new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'some-url',
        );

        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        new ProjectGKMSWrapper(
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
        new ProjectKMSWrapper(
            (new KmsClientFactory())->createClient($options),
            $options,
        );
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectAKVWrapper|ProjectGKMSWrapper|ProjectKMSWrapper $wrapper
     */
    public function testInvalidSetupEncryptComponent($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectAKVWrapper|ProjectGKMSWrapper|ProjectKMSWrapper $wrapper
     */
    public function testInvalidSetupEncryptProjectId($wrapper): void
    {
        $wrapper->setComponentId('component-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No project id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectAKVWrapper|ProjectGKMSWrapper|ProjectKMSWrapper $wrapper
     */
    public function testInvalidSetupDecryptComponentId($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No component id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @dataProvider wrapperProvider
     * @param ProjectAKVWrapper|ProjectGKMSWrapper|ProjectKMSWrapper $wrapper
     */
    public function testInvalidSetupDecryptProjectId($wrapper): void
    {
        $wrapper->setComponentId('component-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No project id provided.');
        $wrapper->decrypt('mySecretValue');
    }
}
