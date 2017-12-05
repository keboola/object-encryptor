<?php

namespace Keboola\ObjectEncryptor\Tests;

use Defuse\Crypto\Key;
use Keboola\ObjectEncryptor\Wrapper\GenericWrapper;

class GenericWrapperTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @return GenericWrapper
     * @throws \Defuse\Crypto\Exception\EnvironmentIsBrokenException
     */
    private function getStackWrapper()
    {
        $generalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($generalKey);
        $wrapper->setStackKey($stackKey);
        return $wrapper;
    }

    public function testEncrypt()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getStackWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptEmptyValue1()
    {
        $secret = '';
        $wrapper = $this->getStackWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptEmptyValue2()
    {
        $secret = '0';
        $wrapper = $this->getStackWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptEmptyValue3()
    {
        $secret = null;
        $wrapper = $this->getStackWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Cannot encrypt a non-scalar value
     */
    public function testEncryptNonScalar()
    {
        $secret = ['a' => 'b'];
        $wrapper = $this->getStackWrapper();
        /** @noinspection PhpParamsInspection */
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptMetadata()
    {
        $generalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($generalKey);
        $wrapper->setStackKey($stackKey);

        $secret = 'mySecretValue';
        $wrapper->setMetadataValue('key', 'value');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($generalKey);
        $wrapper->setStackKey($stackKey);
        $wrapper->setMetadataValue('key', 'value');
        $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid metadata
     */
    public function testEncryptMetadataMismatch()
    {
        $generalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($generalKey);
        $wrapper->setStackKey($stackKey);

        $secret = 'mySecretValue';
        $wrapper->setMetadataValue('key', 'value');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($generalKey);
        $wrapper->setStackKey($stackKey);
        $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher keys are missing.
     */
    public function testInvalidSetupEncrypt1()
    {
        $wrapper = new GenericWrapper();
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher keys are missing.
     */
    public function testInvalidSetupEncrypt2()
    {
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher keys are missing.
     */
    public function testInvalidSetupDecrypt1()
    {
        $wrapper = new GenericWrapper();
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher keys are missing.
     */
    public function testInvalidSetupDecrypt2()
    {
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher keys are invalid.
     */
    public function testInvalidValue1()
    {
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey(new \stdClass());
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher keys are invalid.
     */
    public function testInvalidValue2()
    {
        $wrapper = new GenericWrapper();
        /** @noinspection PhpParamsInspection */
        $wrapper->setGeneralKey(['a' => 'b']);
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher keys are invalid.
     */
    public function testInvalidKey1()
    {
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey('foobar');
        $wrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher keys are invalid.
     */
    public function testInvalidKey2()
    {
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey('foobar');
        $wrapper->encrypt('mySecretValue');
    }
}
