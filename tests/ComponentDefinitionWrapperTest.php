<?php

namespace Keboola\ObjectEncryptor\Tests;

use Defuse\Crypto\Key;
use Keboola\ObjectEncryptor\Wrapper\ComponentDefinitionWrapper;
use PHPUnit\Framework\TestCase;

class ComponentDefinitionWrapperTest extends TestCase
{
    /**
     * @return ComponentDefinitionWrapper
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     */
    private function getComponentWrapper()
    {
        $generalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey($generalKey);
        $wrapper->setStackKey($stackKey);
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        return $wrapper;
    }

    public function testEncrypt()
    {
        $wrapper = $this->getComponentWrapper();
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid cipher
     */
    public function testEncryptDifferentStack()
    {
        $generalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey($generalKey);
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setComponentId('dummy-component');
        $wrapper->setStackId('my-stack');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey($generalKey);
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setComponentId('dummy-component');
        $wrapper->setStackId('my-stack');
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid metadata.
     */
    public function testEncryptDifferentStack2()
    {
        $generalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey($generalKey);
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setComponentId('dummy-component');
        $wrapper->setStackId('my-stack');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey($generalKey);
        $wrapper->setStackId('some-stack');
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setComponentId('dummy-component');
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptStack()
    {
        $wrapper = $this->getComponentWrapper();
        $wrapper->setStackId('my-stack');
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher keys are missing.
     */
    public function testInvalidSetupEncrypt1()
    {
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher keys are missing.
     */
    public function testInvalidSetupEncrypt2()
    {
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage No stack or component id provided.
     */
    public function testInvalidSetupEncrypt3()
    {
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage No stack or component id provided.
     */
    public function testInvalidSetupEncrypt4()
    {
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackId('my-stack');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher keys are missing.
     */
    public function testInvalidSetupDecrypt1()
    {
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher keys are missing.
     */
    public function testInvalidSetupDecrypt2()
    {
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage No stack or component id provided.
     */
    public function testInvalidSetupDecrypt3()
    {
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage No stack or component id provided.
     */
    public function testInvalidSetupDecrypt4()
    {
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackId('my-stack');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher keys are invalid.
     */
    public function testInvalidKey1()
    {
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey('foobar');
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackId('my-stack');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher keys are invalid.
     */
    public function testInvalidKey2()
    {
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey('foobar');
        $wrapper->setStackId('my-stack');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Component id is invalid.
     */
    public function testInvalidComponent()
    {
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId(new \stdClass());
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Stack id is invalid.
     */
    public function testInvalidStack()
    {
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackId(new \stdClass());
        $wrapper->setComponentId('dummy-component');
        $wrapper->encrypt('mySecretValue');
    }
}
