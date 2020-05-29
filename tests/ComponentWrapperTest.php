<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\ComponentAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentWrapper;
use Keboola\ObjectEncryptor\Wrapper\CryptoWrapperInterface;
use PHPUnit\Framework\TestCase;

class ComponentWrapperTest extends TestCase
{
    public function setUp()
    {
        parent::setUp();
        putenv('AWS_ACCESS_KEY_ID=' . AWS_ACCESS_KEY_ID);
        putenv('AWS_SECRET_ACCESS_KEY='. AWS_SECRET_ACCESS_KEY);
        putenv('AZURE_TENANT_ID=' . getenv('TEST_TENANT_ID'));
        putenv('AZURE_CLIENT_ID=' . getenv('TEST_CLIENT_ID'));
        putenv('AZURE_CLIENT_SECRET=' . getenv('TEST_CLIENT_SECRET'));
    }

    /**
     * @return CryptoWrapperInterface[][]
     */
    public function wrapperProvider()
    {
        $componentWrapperKMS = new ComponentWrapper();
        $componentWrapperKMS->setKMSRegion(AWS_DEFAULT_REGION);
        $componentWrapperKMS->setKMSKeyId(KMS_TEST_KEY);
        $componentWrapperAKV = new ComponentAKVWrapper();
        $componentWrapperAKV->setKeyVaultUrl(getenv('TEST_KEY_VAULT_URL'));

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
     * @param CryptoWrapperInterface $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncrypt(CryptoWrapperInterface $wrapper)
    {
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncryptDifferentStack(CryptoWrapperInterface $wrapper)
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
     * @param CryptoWrapperInterface $wrapper
     * @dataProvider wrapperProvider
     */
    public function testEncryptDifferentComponent(CryptoWrapperInterface $wrapper)
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

    public function testInvalidSetupEncryptKMS()
    {
        $wrapper = new ComponentWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupEncryptAKV()
    {
        $wrapper = new ComponentAKVWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptStackAndComponent(CryptoWrapperInterface $wrapper)
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptStack(CryptoWrapperInterface $wrapper)
    {
        $wrapper->setComponentId('component-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupEncryptComponent(CryptoWrapperInterface $wrapper)
    {
        $wrapper->setStackId('stack-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupDecryptKMS()
    {
        $wrapper = new ComponentWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidSetupDecryptAKV()
    {
        $wrapper = new ComponentAKVWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptStackAndComponent(CryptoWrapperInterface $wrapper)
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptStack(CryptoWrapperInterface $wrapper)
    {
        $wrapper->setComponentId('component-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidSetupDecryptComponent(CryptoWrapperInterface $wrapper)
    {
        $wrapper->setComponentId('stack-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidComponent(CryptoWrapperInterface $wrapper)
    {
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId(new \stdClass());
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Component id is invalid.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @dataProvider wrapperProvider
     */
    public function testInvalidStack(CryptoWrapperInterface $wrapper)
    {
        $wrapper->setStackId(new \stdClass());
        $wrapper->setComponentId('dummy-component');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Stack id is invalid.');
        $wrapper->encrypt('mySecretValue');
    }
}
