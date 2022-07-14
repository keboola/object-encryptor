<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
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
     * @return CryptoWrapperInterface[][]
     */
    public function configurationWrapperProvider(): array
    {
        $configurationKMSWrapper = new ConfigurationKMSWrapper();
        $configurationKMSWrapper->setKMSRegion((string) getenv('TEST_AWS_REGION'));
        $configurationKMSWrapper->setKMSKeyId((string) getenv('TEST_AWS_KMS_KEY_ID'));
        $configurationAKVWrapper = new ConfigurationAKVWrapper();
        $configurationAKVWrapper->setKeyVaultUrl((string) getenv('TEST_KEY_VAULT_URL'));

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
    public function testConfigurationWrapper(CryptoWrapperInterface $wrapper): void
    {
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), getenv('TEST_KEY_VAULT_URL'));
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
    public function projectWrapperProvider(): array
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
    public function testProjectWrapper(CryptoWrapperInterface $wrapper): void
    {
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), getenv('TEST_KEY_VAULT_URL'));
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
    public function componentWrapperProvider(): array
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
     * @dataProvider componentWrapperProvider
     */
    public function testComponentWrapper(CryptoWrapperInterface $wrapper): void
    {
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), getenv('TEST_KEY_VAULT_URL'));
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
    public function genericWrapperProvider(): array
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
     * @dataProvider genericWrapperProvider
     */
    public function testGenericWrapper(CryptoWrapperInterface $wrapper): void
    {
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), getenv('TEST_KEY_VAULT_URL'));
        $encrypted = $factory->getEncryptor()->encrypt($secret, get_class($wrapper));
        self::assertStringStartsWith($wrapper->getPrefix(), $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }

    /**
     * @return string[][]
     */
    public function genericWrapperClassProvider(): array
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
     * @dataProvider genericWrapperClassProvider
     */
    public function testGenericWrapperInvalidCredentials(string $wrapperClass): void
    {
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory('non-existent', getenv('TEST_AWS_REGION'), 'non-existent');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Ciphering failed:');
        $factory->getEncryptor()->encrypt($secret, $wrapperClass);
    }

    /**
     * @return string[][]
     */
    public function configurationWrapperClassProvider(): array
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
     * @dataProvider configurationWrapperClassProvider
     */
    public function testConfigurationWrapperInvalidEncrypt(string $wrapperClass): void
    {
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), getenv('TEST_KEY_VAULT_URL'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid crypto wrapper');
        $factory->getEncryptor()->encrypt($secret, $wrapperClass);
    }

    /**
     * @dataProvider configurationWrapperProvider
     */
    public function testConfigurationWrapperInvalidDecrypt(CryptoWrapperInterface $wrapper): void
    {
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), getenv('TEST_KEY_VAULT_URL'));
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('123456');
        $wrapper->setProjectId('123');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        self::expectException(UserException::class);
        self::expectExceptionMessage('is not an encrypted value.');
        $factory->getEncryptor()->decrypt($encrypted);
    }

    /**
     * @return string[][]
     */
    public function projectWrapperClassProvider(): array
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
     * @dataProvider projectWrapperClassProvider
     */
    public function testProjectWrapperInvalidEncrypt(string $wrapperClassName): void
    {
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), getenv('TEST_KEY_VAULT_URL'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid crypto wrapper');
        $factory->getEncryptor()->encrypt($secret, $wrapperClassName);
    }

    /**
     * @dataProvider projectWrapperProvider
     */
    public function testProjectWrapperInvalidDecrypt(CryptoWrapperInterface $wrapper): void
    {
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(
            (string) getenv('TEST_AWS_KMS_KEY_ID'),
            (string) getenv('TEST_AWS_REGION'),
            (string) getenv('TEST_KEY_VAULT_URL')
        );
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        self::expectException(UserException::class);
        self::expectExceptionMessage('is not an encrypted value.');
        $factory->setStackId('my-stack');
        $factory->setComponentId('dummy-component');
        $factory->getEncryptor()->decrypt($encrypted);
    }

    /**
     * @return string[][]
     */
    public function componentWrapperClassProvider(): array
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
     * @dataProvider projectWrapperClassProvider
     */
    public function testComponentWrapperInvalidEncrypt(string $wrapperClassName): void
    {
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), getenv('TEST_KEY_VAULT_URL'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid crypto wrapper');
        $factory->getEncryptor()->encrypt($secret, $wrapperClassName);
    }

    /**
     * @dataProvider componentWrapperProvider
     */
    public function testComponentWrapperInvalidDecrypt(CryptoWrapperInterface $wrapper): void
    {
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), getenv('TEST_KEY_VAULT_URL'));
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        self::expectException(UserException::class);
        self::expectExceptionMessage('is not an encrypted value.');
        $factory->getEncryptor()->decrypt($encrypted);
    }

    public function testCipherError(): void
    {
        $secret = [
            'a' => 'b',
            'c' => [
                '#d' => 'secret'
            ]
        ];
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), getenv('TEST_KEY_VAULT_URL'));
        $factory->setStackId('my-stack');
        $factory->setComponentId('dummy-component');
        $secret = $factory->getEncryptor()->encrypt($secret, ComponentKMSWrapper::class);
        $factory = new ObjectEncryptorFactory(getenv('TEST_AWS_KMS_KEY_ID'), getenv('TEST_AWS_REGION'), getenv('TEST_KEY_VAULT_URL'));
        $factory->setStackId('my-stack');
        $factory->setComponentId('different-dummy-component');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Invalid cipher text for key #d Value "KBC::ComponentSecure::');
        $factory->getEncryptor()->decrypt($secret);
    }
}
