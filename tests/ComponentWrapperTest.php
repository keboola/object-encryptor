<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\ComponentAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;
use PHPUnit\Framework\TestCase;

class ComponentWrapperTest extends TestCase
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
        $componentWrapperKMS = self::createPartialMock(ComponentKMSWrapper::class, ['getRetries']);
        $componentWrapperKMS->method('getRetries')->willReturn(1);
        $componentWrapperKMS->setKMSRegion((string) getenv('TEST_AWS_REGION'));
        $componentWrapperKMS->setKMSKeyId((string) getenv('TEST_AWS_KMS_KEY_ID'));

        $componentWrapperAKV = new ComponentAKVWrapper();
        $componentWrapperAKV->setKeyVaultUrl((string) getenv('TEST_KEY_VAULT_URL'));

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
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @param ComponentKMSWrapper|ComponentAKVWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncryptDifferentStack($wrapper): void
    {
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setStackId('some-other-stack');
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
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('some-other-component');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    public function testInvalidSetupEncryptKMS(): void
    {
        $wrapper = new ComponentKMSWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupEncryptAKV(): void
    {
        $wrapper = new ComponentAKVWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @param ComponentKMSWrapper|ComponentAKVWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptStackAndComponent($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @param ComponentKMSWrapper|ComponentAKVWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptStack($wrapper): void
    {
        $wrapper->setComponentId('component-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @param ComponentKMSWrapper|ComponentAKVWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptComponent($wrapper): void
    {
        $wrapper->setStackId('stack-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupDecryptKMS(): void
    {
        $wrapper = new ComponentKMSWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidSetupDecryptAKV(): void
    {
        $wrapper = new ComponentAKVWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @param ComponentKMSWrapper|ComponentAKVWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptStackAndComponent($wrapper): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @param ComponentKMSWrapper|ComponentAKVWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptStack($wrapper): void
    {
        $wrapper->setComponentId('component-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @param ComponentKMSWrapper|ComponentAKVWrapper $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptComponent($wrapper): void
    {
        $wrapper->setComponentId('stack-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->decrypt('mySecretValue');
    }
}
