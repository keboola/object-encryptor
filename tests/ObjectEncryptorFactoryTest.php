<?php

namespace Keboola\ObjectEncryptor\Tests;

use Defuse\Crypto\Key;
use Keboola\ObjectEncryptor\Legacy\Wrapper\BaseWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentProjectWrapper;
use Keboola\ObjectEncryptor\Legacy\Wrapper\ComponentWrapper;
use Keboola\ObjectEncryptor\ObjectEncryptorFactory;
use Keboola\ObjectEncryptor\Wrapper\StackWrapper;
use PHPUnit\Framework\TestCase;

class ObjectEncryptorFactoryTest extends TestCase
{
    public function testFactoryLegacyComponentProject()
    {
        $globalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $stack = 'us-east-1';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory($globalKey, $legacyKey, $aesKey, $stackKey, $stack);
        $factory->setComponentId('keboola.docker-demo');
        $factory->setConfigurationId('123456');
        $factory->setProjectId('123');
        $wrapper = new ComponentProjectWrapper();
        $wrapper->setComponentId('keboola.docker-demo');
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
        $stack = 'us-east-1';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory($globalKey, $legacyKey, $aesKey, $stackKey, $stack);
        $factory->setComponentId('keboola.docker-demo');
        $factory->setConfigurationId('123456');
        $factory->setProjectId('123');
        $wrapper = new ComponentWrapper();
        $wrapper->setComponentId('keboola.docker-demo');
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
        $stack = 'us-east-1';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory($globalKey, $legacyKey, $aesKey, $stackKey, $stack);
        $factory->setComponentId('keboola.docker-demo');
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

    public function testFactoryStackWrapper()
    {
        $globalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $legacyKey = '1234567890123456';
        $aesKey = '123456789012345678901234567890ab';
        $stack = 'us-east-1';
        $secret = 'secret';
        $factory = new ObjectEncryptorFactory($globalKey, $legacyKey, $aesKey, $stackKey, $stack);
        $factory->setComponentId('keboola.docker-demo');
        $factory->setConfigurationId('123456');
        $factory->setProjectId('123');
        $wrapper = new StackWrapper();
        $wrapper->setStackId($stack);
        $wrapper->setStackKey($stackKey);
        $wrapper->setGeneralKey($globalKey);
        $wrapper->setComponentId('keboola.docker-demo');
        $wrapper->setConfigurationId('123456');
        $wrapper->setProjectId('123');
        $encrypted = $wrapper->encrypt($secret);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        $encrypted = $factory->getEncryptor()->encrypt($secret, StackWrapper::class);
        self::assertStringStartsWith('KBC::SecureV3::CPF::', $encrypted);
        $encrypted = substr($encrypted, strlen($wrapper->getPrefix()));
        $decrypted = $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $decrypted);
    }
}
