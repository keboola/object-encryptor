<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Legacy\Wrapper\BaseWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentProjectWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentWrapper as LegacyComponentWrapper;
use Keboola\ObjectEncryptor\ObjectEncryptorFactory;
use Keboola\ObjectEncryptor\Wrapper\ComponentAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\CryptoWrapperInterface;
use Keboola\ObjectEncryptor\Wrapper\GenericAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectKMSWrapper;
use PHPUnit\Framework\TestCase;

class ObjectEncryptorFactoryTest extends TestCase
{
    public function setUp()
    {
        parent::setUp();
        putenv('AWS_ACCESS_KEY_ID=' . getenv('TEST_AWS_ACCESS_KEY_ID'));
        putenv('AWS_SECRET_ACCESS_KEY='. getenv('TEST_AWS_SECRET_ACCESS_KEY'));
        putenv('AZURE_TENANT_ID=' . getenv('TEST_TENANT_ID'));
        putenv('AZURE_CLIENT_ID=' . getenv('TEST_CLIENT_ID'));
        putenv('AZURE_CLIENT_SECRET=' . getenv('TEST_CLIENT_SECRET'));
    }

    public function testFactoryLegacyComponentProject()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, $aesKey, getenv('TEST_KEY_VAULT_URL'));
        $factory->setComponentId('dummy-component');
        $factory->setConfigurationId('123456');
        $factory->setProjectId('123');
        $wrapper = new ComponentProjectWrapper();
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('123');
        $wrapper->setKey($legacyKey);
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $encrypted = $factory->getEncryptor()->encrypt($secret, ComponentProjectWrapper::class);
        self::assertStringStartsWith('KBC::ComponentProjectEncrypted==', $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }

    public function testFactoryLegacyComponent()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, $aesKey, getenv('TEST_KEY_VAULT_URL'));
        $factory->setComponentId('dummy-component');
        $factory->setConfigurationId('123456');
        $factory->setProjectId('123');
        $wrapper = new LegacyComponentWrapper();
        $wrapper->setComponentId('dummy-component');
        $wrapper->setKey($legacyKey);
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $encrypted = $factory->getEncryptor()->encrypt($secret, LegacyComponentWrapper::class);
        self::assertStringStartsWith('KBC::ComponentEncrypted==', $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }

    public function testFactoryLegacyBase()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, $aesKey, getenv('TEST_KEY_VAULT_URL'));
        $factory->setComponentId('dummy-component');
        $factory->setConfigurationId('123456');
        $factory->setProjectId('123');
        $wrapper = new BaseWrapper();
        $wrapper->setKey($legacyKey);
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $encrypted = $factory->getEncryptor()->encrypt($secret, BaseWrapper::class);
        self::assertStringStartsWith('KBC::Encrypted==', $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }

    /**
     * @return CryptoWrapperInterface[][]
     */
    public function configurationWrapperProvider()
    {
        $configurationKMSWrapper = new ConfigurationKMSWrapper();
        $configurationKMSWrapper->setKMSRegion(getenv('TEST_AWS_REGION'));
        $configurationKMSWrapper->setKMSKeyId(getenv('TEST_AWS_KMS_KEY_ID'));
        $configurationAKVWrapper = new ConfigurationAKVWrapper();
        $configurationAKVWrapper->setKeyVaultUrl(getenv('TEST_KEY_VAULT_URL'));

        return [
            'KMS' => [
                $configurationKMSWrapper,
            ],
            'AKV' => [
                $configurationAKVWrapper,
            ],
        ];
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @throws ApplicationException
     * @dataProvider configurationWrapperProvider
     */
    public function testConfigurationWrapper(CryptoWrapperInterface $wrapper)
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, $aesKey, getenv('TEST_KEY_VAULT_URL'));
        $factory->setStackId('my-stack');
        $factory->setComponentId('dummy-component');
        $factory->setConfigurationId('123456');
        $factory->setProjectId('123');
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('123456');
        $wrapper->setProjectId('123');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $encrypted = $factory->getEncryptor()->encrypt($secret, get_class($wrapper));
        self::assertStringStartsWith($wrapper->getPrefix(), $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }

    /**
     * @return CryptoWrapperInterface[][]
     */
    public function projectWrapperProvider()
    {
        $projectKMSWrapper = new ProjectKMSWrapper();
        $projectKMSWrapper->setKMSRegion(getenv('TEST_AWS_REGION'));
        $projectKMSWrapper->setKMSKeyId(getenv('TEST_AWS_KMS_KEY_ID'));
        $projectAKVWrapper = new ProjectAKVWrapper();
        $projectAKVWrapper->setKeyVaultUrl(getenv('TEST_KEY_VAULT_URL'));

        return [
            'KMS' => [
                $projectKMSWrapper,
            ],
            'AKV' => [
                $projectAKVWrapper,
            ],
        ];
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @throws ApplicationException
     * @dataProvider projectWrapperProvider
     */
    public function testProjectWrapper(CryptoWrapperInterface $wrapper)
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, $aesKey, getenv('TEST_KEY_VAULT_URL'));
        $factory->setComponentId('dummy-component');
        $factory->setStackId('my-stack');
        $factory->setProjectId('my-project');
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $encrypted = $factory->getEncryptor()->encrypt($secret, get_class($wrapper));
        self::assertStringStartsWith($wrapper->getPrefix(), $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }

    /**
     * @return CryptoWrapperInterface[][]
     */
    public function componentWrapperProvider()
    {
        $componentKMSWrapper = new ComponentKMSWrapper();
        $componentKMSWrapper->setKMSRegion(getenv('TEST_AWS_REGION'));
        $componentKMSWrapper->setKMSKeyId(getenv('TEST_AWS_KMS_KEY_ID'));
        $componentAKVWrapper = new ComponentAKVWrapper();
        $componentAKVWrapper->setKeyVaultUrl(getenv('TEST_KEY_VAULT_URL'));

        return [
            'KMS' => [
                $componentKMSWrapper,
            ],
            'AKV' => [
                $componentAKVWrapper,
            ],
        ];
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @throws ApplicationException
     * @dataProvider componentWrapperProvider
     */
    public function testComponentWrapper(CryptoWrapperInterface $wrapper)
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, $aesKey, getenv('TEST_KEY_VAULT_URL'));
        $factory->setComponentId('dummy-component');
        $factory->setStackId('my-stack');

        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $encrypted = $factory->getEncryptor()->encrypt($secret, get_class($wrapper));
        self::assertStringStartsWith($wrapper->getPrefix(), $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }

    /**
     * @return CryptoWrapperInterface[][]
     */
    public function genericWrapperProvider()
    {
        $genericKMSWrapper = new GenericKMSWrapper();
        $genericKMSWrapper->setKMSRegion(getenv('TEST_AWS_REGION'));
        $genericKMSWrapper->setKMSKeyId(getenv('TEST_AWS_KMS_KEY_ID'));
        $genericAKVWrapper = new GenericAKVWrapper();
        $genericAKVWrapper->setKeyVaultUrl(getenv('TEST_KEY_VAULT_URL'));

        return [
            'KMS' => [
                $genericKMSWrapper,
            ],
            'AKV' => [
                $genericAKVWrapper,
            ],
        ];
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @throws ApplicationException
     * @dataProvider genericWrapperProvider
     */
    public function testGenericWrapper(CryptoWrapperInterface $wrapper)
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, $aesKey, getenv('TEST_KEY_VAULT_URL'));
        $encrypted = $factory->getEncryptor()->encrypt($secret, get_class($wrapper));
        self::assertStringStartsWith($wrapper->getPrefix(), $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }

    /**
     * @return string[][]
     */
    public function genericWrapperClassProvider()
    {
        return [
            [
                GenericKMSWrapper::class,
            ],
            [
                GenericAKVWrapper::class,
            ],
        ];
    }

    /**
     * @param $wrapperClass
     * @throws ApplicationException
     * @dataProvider genericWrapperClassProvider
     */
    public function testGenericWrapperInvalidCredentials($wrapperClass)
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory('non-existent', getenv('TEST_AWS_REGION'), $legacyKey, $aesKey, 'non-existent');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Ciphering failed:');
        $factory->getEncryptor()->encrypt($secret, $wrapperClass);
    }

    /**
     * @return string[][]
     */
    public function configurationWrapperClassProvider()
    {
        return [
            [
                ConfigurationKMSWrapper::class,
            ],
            [
                ConfigurationAKVWrapper::class,
            ],
        ];
    }

    /**
     * @param $wrapperClass
     * @throws ApplicationException
     * @dataProvider configurationWrapperClassProvider
     */
    public function testConfigurationWrapperInvalidEncrypt($wrapperClass)
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, $aesKey, getenv('TEST_KEY_VAULT_URL'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid crypto wrapper');
        $factory->getEncryptor()->encrypt($secret, $wrapperClass);
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @throws ApplicationException
     * @throws UserException
     * @dataProvider configurationWrapperProvider
     */
    public function testConfigurationWrapperInvalidDecrypt(CryptoWrapperInterface $wrapper)
    {
        $legacyKey = '1234567890123456';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, '', getenv('TEST_KEY_VAULT_URL'));
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('123456');
        $wrapper->setProjectId('123');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        self::expectException(UserException::class);
        self::expectExceptionMessage('Value is not an encrypted value.');
        $factory->getEncryptor()->decrypt($encrypted);
    }

    /**
     * @return string[][]
     */
    public function projectWrapperClassProvider()
    {
        return [
            [
                ProjectKMSWrapper::class,
            ],
            [
                ProjectAKVWrapper::class,
            ],
        ];
    }

    /**
     * @param string $wrapperClassName
     * @throws ApplicationException
     * @dataProvider projectWrapperClassProvider
     */
    public function testProjectWrapperInvalidEncrypt($wrapperClassName)
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, $aesKey, getenv('TEST_KEY_VAULT_URL'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid crypto wrapper');
        $factory->getEncryptor()->encrypt($secret, $wrapperClassName);
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @throws ApplicationException
     * @throws UserException
     * @dataProvider projectWrapperProvider
     */
    public function testProjectWrapperInvalidDecrypt(CryptoWrapperInterface $wrapper)
    {
        $legacyKey = '1234567890123456';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, '', getenv('TEST_KEY_VAULT_URL'));
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        self::expectException(UserException::class);
        self::expectExceptionMessage('Value is not an encrypted value.');
        $factory->getEncryptor()->decrypt($encrypted);
    }

    /**
     * @return string[][]
     */
    public function componentWrapperClassProvider()
    {
        return [
            [
                ComponentKMSWrapper::class,
            ],
            [
                ComponentAKVWrapper::class,
            ],
        ];
    }

    /**
     * @param string $wrapperClassName
     * @throws ApplicationException
     * @dataProvider projectWrapperClassProvider
     */
    public function testComponentWrapperInvalidEncrypt($wrapperClassName)
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, $aesKey, getenv('TEST_KEY_VAULT_URL'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid crypto wrapper');
        $factory->getEncryptor()->encrypt($secret, $wrapperClassName);
    }

    /**
     * @param CryptoWrapperInterface $wrapper
     * @throws ApplicationException
     * @throws UserException
     * @dataProvider componentWrapperProvider
     */
    public function testComponentWrapperInvalidDecrypt(CryptoWrapperInterface $wrapper)
    {
        $legacyKey = '1234567890123456';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, '', getenv('TEST_KEY_VAULT_URL'));
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        self::expectException(UserException::class);
        self::expectExceptionMessage('Value is not an encrypted value.');
        $factory->getEncryptor()->decrypt($encrypted);
    }

    public function testCipherError()
    {
        $legacyKey = '1234567890123456';
        $secret = [
            'a' => 'b',
            'c' => [
                '#d' => 'secret'
            ]
        ];
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, '', getenv('TEST_KEY_VAULT_URL'));
        $factory->setStackId('my-stack');
        $factory->setComponentId('dummy-component');
        $secret = $factory->getEncryptor()->encrypt($secret, ComponentKMSWrapper::class);
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, '', getenv('TEST_KEY_VAULT_URL'));
        $factory->setStackId('my-stack');
        $factory->setComponentId('different-dummy-component');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Invalid cipher text for key #d Value KBC::ComponentSecure::');
        $factory->getEncryptor()->decrypt($secret);
    }

    public function testInvalidKeysLegacyEncryption()
    {
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), 'short', '', getenv('TEST_KEY_VAULT_URL'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Encryption key too short. Minimum is 16 bytes.');
        $factory->getEncryptor();
    }

    public function testInvalidKeysKmsId()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory(new \stdClass(), getenv('TEST_AWS_REGION'), $legacyKey, '', getenv('TEST_KEY_VAULT_URL'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid KMS key Id.');
        $factory->getEncryptor();
    }

    public function testInvalidKeysVaultUrl()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory('', getenv('TEST_AWS_REGION'), $legacyKey, '', new \stdClass());
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid AKV URL.');
        $factory->getEncryptor();
    }

    public function testInvalidKeysVersion1()
    {
        /** @noinspection PhpParamsInspection */
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), ['a' => 'b'], '', getenv('TEST_KEY_VAULT_URL'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid key version 1.');
        $factory->getEncryptor();
    }

    public function testInvalidKeysVersion0()
    {
        $legacyKey = '1234567890123456';
        /** @noinspection PhpParamsInspection */
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, ['a' => 'b'], getenv('TEST_KEY_VAULT_URL'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid key version 0.');
        $factory->getEncryptor();
    }

    public function testInvalidParamsStackId()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, '', getenv('TEST_KEY_VAULT_URL'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid stack id.');
        /** @noinspection PhpParamsInspection */
        $factory->setStackId(['a' => 'b']);
    }

    public function testInvalidParamsComponentId()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, '', getenv('TEST_KEY_VAULT_URL'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid component id.');
        /** @noinspection PhpParamsInspection */
        $factory->setComponentId(['a' => 'b']);
    }

    public function testInvalidParamsProjectId()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, '', getenv('TEST_KEY_VAULT_URL'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid project id.');
        /** @noinspection PhpParamsInspection */
        $factory->setProjectId(['a' => 'b']);
    }

    public function testInvalidParamsConfigurationId()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), $legacyKey, '', getenv('TEST_KEY_VAULT_URL'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid configuration id.');
        /** @noinspection PhpParamsInspection */
        $factory->setConfigurationId(['a' => 'b']);
    }
}
