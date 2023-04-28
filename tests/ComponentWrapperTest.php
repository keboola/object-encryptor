<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\ComponentAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentKMSWrapper;

class ComponentWrapperTest extends AbstractTestCase
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
     * @return ComponentKMSWrapper[][]|ComponentAKVWrapper[][]
     */
    public function wrapperProvider(): array
    {
        $componentWrapperKMS = new ComponentKMSWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: self::getkmsKeyId(),
            kmsRegion: self::getkmsRegion(),
            backoffMaxTries: 1,
        ));

        $componentWrapperAKV = new ComponentAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: self::getAkvUrl(),
            backoffMaxTries: 1,
        ));

        return [
            'KMS' => [
                $componentWrapperKMS,
            ],
            'AKV' => [
                $componentWrapperAKV,
            ],
        ];
    }

    /**
     * @param ComponentKMSWrapper|ComponentAKVWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncrypt($wrapper): void
    {
        $wrapper->setComponentId('dummy-component');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptDifferentStackKMS(): void
    {
        $wrapper = new ComponentKMSWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: self::getKmsKeyId(),
            kmsRegion: self::getKmsRegion(),
            backoffMaxTries: 1,
        ));
        $wrapper->setComponentId('dummy-component');
        $secret = 'mySecretValue';

        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = new ComponentKMSWrapper(new EncryptorOptions(
            stackId: 'some-other-stack',
            kmsKeyId: self::getKmsKeyId(),
            kmsRegion: self::getKmsRegion(),
            backoffMaxTries: 1,
        ));
        $wrapper->setComponentId('dummy-component');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    public function testEncryptDifferentStackAKV(): void
    {
        $wrapper = new ComponentAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: self::getAkvUrl(),
            backoffMaxTries: 1,
        ));
        $wrapper->setComponentId('dummy-component');
        $secret = 'mySecretValue';

        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = new ComponentAKVWrapper(new EncryptorOptions(
            stackId: 'some-other-stack',
            akvUrl: self::getAkvUrl(),
            backoffMaxTries: 1,
        ));
        $wrapper->setComponentId('dummy-component');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    /**
     * @param ComponentKMSWrapper|ComponentAKVWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncryptDifferentComponent($wrapper): void
    {
        $wrapper->setComponentId('dummy-component');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setComponentId('some-other-component');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    public function testInvalidSetupKMS(): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        new ComponentKMSWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: 'some-key',
            kmsRegion: null,
        ));
    }

    public function testInvalidSetupAKV(): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        new ComponentAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: 'some-key',
            kmsRegion: 'some-region',
        ));
    }

    /**
     * @param ComponentKMSWrapper|ComponentAKVWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptComponent($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @param ComponentKMSWrapper|ComponentAKVWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptComponent($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No component id provided.');
        $wrapper->decrypt('mySecretValue');
    }
}
