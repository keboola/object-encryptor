<?php

namespace Keboola\ObjectEncryptor\Tests;

use Defuse\Crypto\Key;
use Keboola\ObjectEncryptor\Legacy\Wrapper\BaseWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentProjectWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentWrapper;
use Keboola\ObjectEncryptor\ObjectEncryptorFactory;
use Keboola\ObjectEncryptor\Wrapper\ComponentDefinitionWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericWrapper;
use PHPUnit\Framework\TestCase;

class ObjectEncryptorFactoryTest extends TestCase
{
    public function testFactoryLegacyComponentProject()
    {
        $globalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory($globalKey, $legacyKey, $aesKey, $stackKey);
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
        $globalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory($globalKey, $legacyKey, $aesKey, $stackKey);
        $factory->setComponentId('dummy-component');
        $factory->setConfigurationId('123456');
        $factory->setProjectId('123');
        $wrapper = new ComponentWrapper();
        $wrapper->setComponentId('dummy-component');
        $wrapper->setKey($legacyKey);
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $encrypted = $factory->getEncryptor()->encrypt($secret, ComponentWrapper::class);
        self::assertStringStartsWith('KBC::ComponentEncrypted==', $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }

    public function testFactoryLegacyBase()
    {
        $globalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory($globalKey, $legacyKey, $aesKey, $stackKey);
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
        $globalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory($globalKey, $legacyKey, $aesKey, $stackKey);
        $factory->setStackId('my-stack');
        $factory->setComponentId('dummy-component');
        $factory->setConfigurationId('123456');
        $factory->setProjectId('123');
        $wrapper = new ConfigurationWrapper();
        $wrapper->setStackId('my-stack');
        $wrapper->setStackKey($stackKey);
        $wrapper->setGeneralKey($globalKey);
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

    public function testComponentWrapper()
    {
        $globalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory($globalKey, $legacyKey, $aesKey, $stackKey);
        $factory->setComponentId('dummy-component');
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setStackKey($stackKey);
        $wrapper->setGeneralKey($globalKey);
        $wrapper->setComponentId('dummy-component');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $encrypted = $factory->getEncryptor()->encrypt($secret, ComponentDefinitionWrapper::class);
        self::assertStringStartsWith($wrapper->getPrefix(), $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }

    public function testGenericWrapper()
    {
        $globalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory($globalKey, $legacyKey, $aesKey, $stackKey);
        $wrapper = new GenericWrapper();
        $wrapper->setStackKey($stackKey);
        $wrapper->setGeneralKey($globalKey);
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $encrypted = $factory->getEncryptor()->encrypt($secret, GenericWrapper::class);
        self::assertStringStartsWith($wrapper->getPrefix(), $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid crypto wrapper
     */
    public function testConfigurationWrapperInvalid1()
    {
        $globalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory($globalKey, $legacyKey, $aesKey, $stackKey);
        $wrapper = new ConfigurationWrapper();
        $wrapper->setStackKey($stackKey);
        $wrapper->setStackId('my-stack');
        $wrapper->setGeneralKey($globalKey);
        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('123456');
        $wrapper->setProjectId('123');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $factory->getEncryptor()->encrypt($secret, ConfigurationWrapper::class);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Value is not an encrypted value.
     */
    public function testConfigurationWrapperInvalid2()
    {
        $globalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $legacyKey = '1234567890123456';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory($globalKey, $legacyKey, '', $stackKey);
        $wrapper = new ConfigurationWrapper();
        $wrapper->setStackId('my-stack');
        $wrapper->setStackKey($stackKey);
        $wrapper->setGeneralKey($globalKey);
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
    public function testComponentWrapperInvalid1()
    {
        $globalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory($globalKey, $legacyKey, $aesKey, $stackKey);
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setStackKey($stackKey);
        $wrapper->setGeneralKey($globalKey);
        $wrapper->setComponentId('dummy-component');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $factory->getEncryptor()->encrypt($secret, ComponentDefinitionWrapper::class);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Value is not an encrypted value.
     */
    public function testComponentWrapperInvalid2()
    {
        $globalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $legacyKey = '1234567890123456';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory($globalKey, $legacyKey, '', $stackKey);
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setStackKey($stackKey);
        $wrapper->setGeneralKey($globalKey);
        $wrapper->setComponentId('dummy-component');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $factory->getEncryptor()->decrypt($encrypted);
    }
}
