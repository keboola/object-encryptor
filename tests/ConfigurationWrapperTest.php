<?php

namespace Keboola\ObjectEncryptor\Tests;

use Defuse\Crypto\Key;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationWrapper;
use PHPUnit\Framework\TestCase;

class ConfigurationWrapperTest extends TestCase
{
    /**
     * @return ConfigurationWrapper
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     */
    private function getConfigWrapper()
    {
        $generalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey($generalKey);
        $wrapper->setStackKey($stackKey);
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        return $wrapper;
    }

    public function testEncrypt()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getConfigWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals('mySecretValue', $wrapper->decrypt($encrypted));
    }

    public function testEncryptConfiguration()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getConfigWrapper();
        $wrapper->setConfigurationId('123456');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals('mySecretValue', $wrapper->decrypt($encrypted));
    }

    public function testEncryptProject()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getConfigWrapper();
        $wrapper->setProjectId('123');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals('mySecretValue', $wrapper->decrypt($encrypted));
    }

    public function testEncryptConfigurationProject()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getConfigWrapper();
        $wrapper->setConfigurationId('123456');
        $wrapper->setProjectId('123');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals('mySecretValue', $wrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad init
     */
    public function testInvalidSetupEncrypt1()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad init
     */
    public function testInvalidSetupEncrypt2()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad init
     */
    public function testInvalidSetupEncrypt3()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad init
     */
    public function testInvalidSetupEncrypt4()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackId('my-stack');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad init
     */
    public function testInvalidSetupEncrypt5()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setComponentId('dummy-component');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad init
     */
    public function testInvalidSetupDecrypt1()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad init
     */
    public function testInvalidSetupDecrypt2()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad init
     */
    public function testInvalidSetupDecrypt3()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad init
     */
    public function testInvalidSetupDecrypt4()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackId('my-stack');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad init
     */
    public function testInvalidSetupDecrypt5()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setComponentId('dummy-component');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid Key
     */
    public function testInvalidKey1()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey('foobar');
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackId('my-stack');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid Key
     */
    public function testInvalidKey2()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey('foobar');
        $wrapper->setStackId('my-stack');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid Stack
     */
    public function testInvalidStack()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackId(new \stdClass());
        $wrapper->setComponentId('dummy-component');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid Project Id
     */
    public function testInvalidProject()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setComponentId('dummy-component');
        $wrapper->setStackId('my-stack');
        $wrapper->setProjectId(new \stdClass());
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid Component Id
     */
    public function testInvalidComponent()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId(new \stdClass());
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid Configuration Id
     */
    public function testInvalidConfiguration()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setComponentId('dummy-component');
        $wrapper->setStackId('my-stack');
        $wrapper->setConfigurationId(new \stdClass());
        $wrapper->encrypt('mySecretValue');
    }
}
