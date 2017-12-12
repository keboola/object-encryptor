<?php

namespace Keboola\ObjectEncryptor\Tests;

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

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Ciphering failed: Failed to obtain encryption key.
     */
    public function testGenericWrapperInvalidCredentials()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory('non-existent', AWS_DEFAULT_REGION, $legacyKey, $aesKey);
        $factory->getEncryptor()->encrypt($secret, GenericKMSWrapper::class);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid crypto wrapper
     */
    public function testConfigurationWrapperInvalid1()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, $aesKey);
        $factory->getEncryptor()->encrypt($secret, ConfigurationWrapper::class);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Value is not an encrypted value.
     */
    public function testConfigurationWrapperInvalid2()
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
        $factory->getEncryptor()->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid crypto wrapper
     */
    public function testProjectWrapperInvalid1()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, $aesKey);
        $factory->getEncryptor()->encrypt($secret, ProjectWrapper::class);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Value is not an encrypted value.
     */
    public function testProjectWrapperInvalid2()
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
        $factory->getEncryptor()->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid crypto wrapper
     */
    public function testComponentWrapperInvalid1()
    {
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, $aesKey);
        $factory->getEncryptor()->encrypt($secret, ComponentWrapper::class);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Value is not an encrypted value.
     */
    public function testComponentWrapperInvalid2()
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
        $factory->getEncryptor()->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Encryption key too short. Minimum is 16 bytes.
     */
    public function testInvalidKeys1()
    {
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, 'short', '');
        $factory->getEncryptor();
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid KMS key Id.
     */
    public function testInvalidKeys2()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory(new \stdClass(), AWS_DEFAULT_REGION, $legacyKey, '');
        $factory->getEncryptor();
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid key version 1.
     */
    public function testInvalidKeys4()
    {
        /** @noinspection PhpParamsInspection */
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, ['a' => 'b'], '');
        $factory->getEncryptor();
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid key version 0.
     */
    public function testInvalidKeys5()
    {
        $legacyKey = '1234567890123456';
        /** @noinspection PhpParamsInspection */
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, ['a' => 'b']);
        $factory->getEncryptor();
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid stack id.
     */
    public function testInvalidParams4()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, '');
        /** @noinspection PhpParamsInspection */
        $factory->setStackId(['a' => 'b']);
        $factory->getEncryptor();
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid component id.
     */
    public function testInvalidParams5()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, '');
        /** @noinspection PhpParamsInspection */
        $factory->setComponentId(['a' => 'b']);
        $factory->getEncryptor();
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid project id.
     */
    public function testInvalidParams6()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, '');
        /** @noinspection PhpParamsInspection */
        $factory->setProjectId(['a' => 'b']);
        $factory->getEncryptor();
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid configuration id.
     */
    public function testInvalidParams7()
    {
        $legacyKey = '1234567890123456';
        $factory = new ObjectEncryptorFactory(KMS_TEST_KEY, AWS_DEFAULT_REGION, $legacyKey, '');
        /** @noinspection PhpParamsInspection */
        $factory->setConfigurationId(['a' => 'b']);
        $factory->getEncryptor();
    }
}
