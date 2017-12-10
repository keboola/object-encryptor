<?php

namespace Keboola\ObjectEncryptor\Tests;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Keboola\ObjectEncryptor\Wrapper\ComponentDefinitionWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericWrapper;
use PHPUnit\Framework\TestCase;

class CipherDataTest extends TestCase
{

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Value is not an encrypted value.
     */
    public function testDecryptInvalidKey()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $encrypted = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyGeneral));
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $wrapper->setStackKey($keyStack);
        $wrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Deserialization of decrypted data failed: Syntax error
     */
    public function testDecryptInvalidJson()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $encrypted = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyGeneral));
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid cipher data
     */
    public function testDecryptInvalidJson2()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $encrypted = Crypto::encrypt(
            json_encode(['foo' => 'bar']),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid cipher data
     */
    public function testDecryptInvalidJson3()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $encrypted = Crypto::encrypt(
            json_encode(['value' => 'foo']),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->decrypt($encrypted);
    }

    public function testDecryptValidJson()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = Crypto::encrypt(
            json_encode([
                GenericWrapper::KEY_METADATA => [
                    GenericWrapper::KEY_STACK => 'my-stack'
                ],
                GenericWrapper::KEY_VALUE => $inCipher
            ]),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->setMetadataValue(GenericWrapper::KEY_STACK, 'my-stack');
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals('fooBar', $decrypted);
    }

    public function testDecryptWrongStackKeyNoStack()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $encrypted = Crypto::encrypt(
            json_encode([
                GenericWrapper::KEY_METADATA => [],
                GenericWrapper::KEY_VALUE => 'fooBar'
            ]),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        self::assertEquals('fooBar', $wrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid cipher
     */
    public function testDecryptWrongStackKey()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::createNewRandomKey());
        $encrypted = Crypto::encrypt(
            json_encode([
                GenericWrapper::KEY_METADATA => [
                    GenericWrapper::KEY_STACK => 'some-stack'
                ],
                GenericWrapper::KEY_VALUE => $inCipher
            ]),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->setMetadataValue(GenericWrapper::KEY_STACK, 'some-stack');
        $wrapper->decrypt($encrypted);
    }

    public function testCorrectStack()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = Crypto::encrypt(
            json_encode([
                GenericWrapper::KEY_METADATA => ['stackId' => 'my-stack'],
                GenericWrapper::KEY_VALUE => $inCipher
            ]),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new GenericWrapper();
        $wrapper->setMetadataValue('stackId', 'my-stack');
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid metadata
     */
    public function testWrongStack()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = Crypto::encrypt(
            json_encode([
                GenericWrapper::KEY_METADATA => ['stackId' => 'my-stack'],
                GenericWrapper::KEY_VALUE => $inCipher
            ]),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new GenericWrapper();
        $wrapper->setMetadataValue('stackId', 'not-my-stack');
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->decrypt($encrypted);
    }

    public function testComponentWrapperNoStack()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = Crypto::encrypt(
            json_encode([
                GenericWrapper::KEY_METADATA => [ComponentDefinitionWrapper::KEY_COMPONENT => 'dummy-component'],
                GenericWrapper::KEY_VALUE => $inCipher
            ]),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->setComponentId('dummy-component');
        $wrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid metadata
     */
    public function testComponentWrapperGeneric()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = Crypto::encrypt(
            json_encode([
                GenericWrapper::KEY_METADATA => ['componentId' => 'dummy-component'],
                GenericWrapper::KEY_VALUE => $inCipher
            ]),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->decrypt($encrypted);
    }

    public function testComponentWrapperValid()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = Crypto::encrypt(
            json_encode([
                GenericWrapper::KEY_METADATA => [ComponentDefinitionWrapper::KEY_COMPONENT => 'dummy-component'],
                GenericWrapper::KEY_VALUE => $inCipher
            ]),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new ComponentDefinitionWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->setComponentId('dummy-component');
        $wrapper->decrypt($encrypted);
    }

    public function testConfigurationWrapperValid()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = Crypto::encrypt(
            json_encode([
                GenericWrapper::KEY_METADATA => [
                    ConfigurationWrapper::KEY_COMPONENT => 'dummy-component',
                    ConfigurationWrapper::KEY_STACK => 'my-stack'
                ],
                GenericWrapper::KEY_VALUE => $inCipher
            ]),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new ConfigurationWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->setComponentId('dummy-component');
        $wrapper->setStackId('my-stack');
        $wrapper->decrypt($encrypted);
    }

    public function testConfigurationWrapperGenericValid()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = Crypto::encrypt(
            json_encode([
                GenericWrapper::KEY_METADATA => ['componentId' => 'dummy-component', 'stackId' => 'my-stack'],
                GenericWrapper::KEY_VALUE => $inCipher
            ]),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->setMetadataValue('componentId', 'dummy-component');
        $wrapper->setMetadataValue('stackId', 'my-stack');
        $wrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid metadata
     */
    public function testConfigurationWrapperGenericInvalid1()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = Crypto::encrypt(
            json_encode(['metadata' => ['componentId' => 'dummy-component', 'stackId' => 'my-stack'], 'value' => $inCipher]),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->setMetadataValue('componentId', 'dummy-component');
        $wrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid metadata
     */
    public function testConfigurationWrapperGenericInvalid2()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = Crypto::encrypt(
            json_encode(['metadata' => ['componentId' => 'dummy-component', 'stackId' => 'my-stack'], 'value' => $inCipher]),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->setMetadataValue('componentId', 'dummy-component');
        $wrapper->setMetadataValue('stackId', 'not-my-stack');
        $wrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid metadata
     */
    public function testConfigurationWrapperGenericInvalid3()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = Crypto::encrypt(
            json_encode(['metadata' => ['componentId' => 'dummy-component', 'stackId' => 'my-stack', 'foo' => 'bar'], 'value' => $inCipher]),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->setMetadataValue('componentId', 'dummy-component');
        $wrapper->setMetadataValue('stackId', 'my-stack');
        $wrapper->decrypt($encrypted);
    }

    public function testGenericWrapperValid()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = Crypto::encrypt(
            json_encode(['metadata' => ['foo' => 'bar'], 'value' => $inCipher]),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->setMetadataValue('foo', 'bar');
        $wrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid metadata
     */
    public function testGenericWrapperInvalid()
    {
        $keyGeneral = Key::createNewRandomKey()->saveToAsciiSafeString();
        $keyStack = Key::createNewRandomKey()->saveToAsciiSafeString();
        $inCipher = Crypto::encrypt('fooBar', Key::loadFromAsciiSafeString($keyStack));
        $encrypted = Crypto::encrypt(
            json_encode(['metadata' => ['foo' => 'bar'], 'value' => $inCipher]),
            Key::loadFromAsciiSafeString($keyGeneral)
        );
        $wrapper = new GenericWrapper();
        $wrapper->setGeneralKey($keyGeneral);
        $wrapper->setStackKey($keyStack);
        $wrapper->decrypt($encrypted);
    }
}
