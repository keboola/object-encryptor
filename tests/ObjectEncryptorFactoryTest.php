<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Legacy\Wrapper\BaseWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentProjectWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentWrapper as LegacyComponentWrapper;
use Keboola\ObjectEncryptor\ObjectEncryptorFactory;
use Keboola\ObjectEncryptor\Wrapper\ComponentWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectWrapper;
use PHPUnit\Framework\TestCase;

class ObjectEncryptorFactoryTest extends TestCase
{
    public function testFactoryLegacyComponentProject()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, $aesKey);
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
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, $aesKey);
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
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, $aesKey);
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

    public function testConfigurationWrapper()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, $aesKey);
        $factory->setStackId('my-stack');
        $factory->setComponentId('dummy-component');
        $factory->setConfigurationId('123456');
        $factory->setProjectId('123');
        $wrapper = new ConfigurationWrapper();
        $wrapper->setStackId('my-stack');
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('123456');
        $wrapper->setProjectId('123');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $encrypted = $factory->getEncryptor()->encrypt($secret, ConfigurationWrapper::class);
        self::assertStringStartsWith($wrapper->getPrefix(), $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }

    public function testProjectWrapper()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, $aesKey);
        $factory->setComponentId('dummy-component');
        $factory->setStackId('my-stack');
        $factory->setProjectId('my-project');
        $wrapper = new ProjectWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $encrypted = $factory->getEncryptor()->encrypt($secret, ProjectWrapper::class);
        self::assertStringStartsWith($wrapper->getPrefix(), $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }

    public function testComponentWrapper()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, $aesKey);
        $factory->setComponentId('dummy-component');
        $factory->setStackId('my-stack');
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $encrypted = $factory->getEncryptor()->encrypt($secret, ComponentWrapper::class);
        self::assertStringStartsWith($wrapper->getPrefix(), $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }

    public function testGenericWrapper()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, $aesKey);
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $encrypted = $factory->getEncryptor()->encrypt($secret, GenericKMSWrapper::class);
        self::assertStringStartsWith($wrapper->getPrefix(), $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }

    public function testGenericWrapperInvalidCredentials()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory('non-existent', AWS_DEFAULT_REGION, $legacyKey, $aesKey);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Ciphering failed: Failed to obtain encryption key.');
        $factory->getEncryptor()->encrypt($secret, GenericKMSWrapper::class);
    }

    public function testConfigurationWrapperInvalidEncrypt()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, $aesKey);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid crypto wrapper');
        $factory->getEncryptor()->encrypt($secret, ConfigurationWrapper::class);
    }

    public function testConfigurationWrapperInvalidDecrypt()
    {
        $legacyKey = '1234567890123456';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, '');
        $wrapper = new ConfigurationWrapper();
        $wrapper->setStackId('my-stack');
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('123456');
        $wrapper->setProjectId('123');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        self::expectException(UserException::class);
        self::expectExceptionMessage('Value is not an encrypted value.');
        $factory->getEncryptor()->decrypt($encrypted);
    }

    public function testProjectWrapperInvalidEncrypt()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, $aesKey);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid crypto wrapper');
        $factory->getEncryptor()->encrypt($secret, ProjectWrapper::class);
    }

    public function testProjectWrapperInvalidDecrypt()
    {
        $legacyKey = '1234567890123456';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, '');
        $wrapper = new ProjectWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        self::expectException(UserException::class);
        self::expectExceptionMessage('Value is not an encrypted value.');
        $factory->getEncryptor()->decrypt($encrypted);
    }

    public function testComponentWrapperInvalidEncrypt()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, $aesKey);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid crypto wrapper');
        $factory->getEncryptor()->encrypt($secret, ComponentWrapper::class);
    }

    public function testComponentWrapperInvalidDecrypt()
    {
        $legacyKey = '1234567890123456';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, '');
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
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
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, '');
        $factory->setStackId('my-stack');
        $factory->setComponentId('dummy-component');
        $secret = $factory->getEncryptor()->encrypt($secret, ComponentWrapper::class);
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, '');
        $factory->setStackId('my-stack');
        $factory->setComponentId('different-dummy-component');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Invalid cipher text for key #d Value KBC::ComponentSecure::');
        $factory->getEncryptor()->decrypt($secret);
    }

    public function testInvalidKeysLegacyEncryption()
    {
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, 'short', '');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Encryption key too short. Minimum is 16 bytes.');
        $factory->getEncryptor();
    }

    public function testInvalidKeysKmsId()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory(new \stdClass(), AWS_DEFAULT_REGION, $legacyKey, '');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid KMS key Id.');
        $factory->getEncryptor();
    }

    public function testInvalidKeysVersion1()
    {
        /** @noinspection PhpParamsInspection */
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, ['a' => 'b'], '');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid key version 1.');
        $factory->getEncryptor();
    }

    public function testInvalidKeysVersion0()
    {
        $legacyKey = '1234567890123456';
        /** @noinspection PhpParamsInspection */
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, ['a' => 'b']);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid key version 0.');
        $factory->getEncryptor();
    }

    public function testInvalidParamsStackId()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, '');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid stack id.');
        /** @noinspection PhpParamsInspection */
        $factory->setStackId(['a' => 'b']);
    }

    public function testInvalidParamsComponentId()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, '');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid component id.');
        /** @noinspection PhpParamsInspection */
        $factory->setComponentId(['a' => 'b']);
    }

    public function testInvalidParamsProjectId()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, '');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid project id.');
        /** @noinspection PhpParamsInspection */
        $factory->setProjectId(['a' => 'b']);
    }

    public function testInvalidParamsConfigurationId()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, '');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid configuration id.');
        /** @noinspection PhpParamsInspection */
        $factory->setConfigurationId(['a' => 'b']);
    }
}
