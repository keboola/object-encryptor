<?php

namespace Keboola\ObjectEncryptor\Tests;

use Defuse\Crypto\Key;
use Keboola\ObjectEncryptor\Wrapper\StackWrapper;

class StackWrapperTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @return StackWrapper
     */
    private function getStackWrapper()
    {
        $generalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey($generalKey);
        $stackWrapper->setStackKey($stackKey);
        $stackWrapper->setStackId('my-stack');
        return $stackWrapper;
    }

    public function testEncrypt()
    {
        $stackWrapper = $this->getStackWrapper();
        $encrypted = $stackWrapper->encrypt("mySecretValue");
        self::assertStringStartsWith('::', $encrypted);
        self::assertEquals("mySecretValue", $stackWrapper->decrypt($encrypted));
    }

    public function testEncryptComponent()
    {
        $stackWrapper = $this->getStackWrapper();
        $stackWrapper->setComponentId('keboola.docker-demo');
        $encrypted = $stackWrapper->encrypt("mySecretValue");
        self::assertStringStartsWith('C::', $encrypted);
        self::assertEquals("mySecretValue", $stackWrapper->decrypt($encrypted));
    }

    public function testEncryptConfiguration()
    {
        $stackWrapper = $this->getStackWrapper();
        $stackWrapper->setConfigurationId('123456');
        $encrypted = $stackWrapper->encrypt("mySecretValue");
        self::assertStringStartsWith('F::', $encrypted);
        self::assertEquals("mySecretValue", $stackWrapper->decrypt($encrypted));
    }

    public function testEncryptProject()
    {
        $stackWrapper = $this->getStackWrapper();
        $stackWrapper->setProjectId('123');
        $encrypted = $stackWrapper->encrypt("mySecretValue");
        self::assertStringStartsWith('P::', $encrypted);
        self::assertEquals("mySecretValue", $stackWrapper->decrypt($encrypted));
    }

    public function testEncryptComponentConfiguration()
    {
        $stackWrapper = $this->getStackWrapper();
        $stackWrapper->setComponentId('keboola.docker-demo');
        $stackWrapper->setConfigurationId('123456');
        $encrypted = $stackWrapper->encrypt("mySecretValue");
        self::assertStringStartsWith('CF::', $encrypted);
        self::assertEquals("mySecretValue", $stackWrapper->decrypt($encrypted));
    }

    public function testEncryptComponentProject()
    {
        $stackWrapper = $this->getStackWrapper();
        $stackWrapper->setComponentId('keboola.docker-demo');
        $stackWrapper->setProjectId('123');
        $encrypted = $stackWrapper->encrypt("mySecretValue");
        self::assertStringStartsWith('CP::', $encrypted);
        self::assertEquals("mySecretValue", $stackWrapper->decrypt($encrypted));
    }

    public function testEncryptConfigurationProject()
    {
        $stackWrapper = $this->getStackWrapper();
        $stackWrapper->setConfigurationId('123456');
        $stackWrapper->setProjectId('123');
        $encrypted = $stackWrapper->encrypt("mySecretValue");
        self::assertStringStartsWith('PF::', $encrypted);
        self::assertEquals("mySecretValue", $stackWrapper->decrypt($encrypted));
    }

    public function testEncryptComponentConfigurationProject()
    {
        $stackWrapper = $this->getStackWrapper();
        $stackWrapper->setComponentId('keboola.docker-demo');
        $stackWrapper->setConfigurationId('123456');
        $stackWrapper->setProjectId('123');
        $encrypted = $stackWrapper->encrypt("mySecretValue");
        self::assertStringStartsWith('CPF::', $encrypted);
        self::assertEquals("mySecretValue", $stackWrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad Init
     */
    public function testInvalidSetupEncrypt1()
    {
        $stackWrapper = new StackWrapper();
        $stackWrapper->encrypt("mySecretValue");
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad Init
     */
    public function testInvalidSetupEncrypt2()
    {
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->encrypt("mySecretValue");
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad Init
     */
    public function testInvalidSetupEncrypt3()
    {
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->encrypt("mySecretValue");
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad Init
     */
    public function testInvalidSetupDecrypt1()
    {
        $stackWrapper = new StackWrapper();
        $stackWrapper->decrypt("mySecretValue");
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad Init
     */
    public function testInvalidSetupDecrypt2()
    {
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->decrypt("mySecretValue");
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Bad Init
     */
    public function testInvalidSetupDecrypt3()
    {
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->decrypt("mySecretValue");
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid Key
     */
    public function testInvalidValue1()
    {
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->setStackKey(new \stdClass());
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->encrypt("mySecretValue");
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid Key
     */
    public function testInvalidValue2()
    {
        $stackWrapper = new StackWrapper();
        /** @noinspection PhpParamsInspection */
        $stackWrapper->setGeneralKey(["a" => "b"]);
        $stackWrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->encrypt("mySecretValue");
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid Stack
     */
    public function testInvalidValue3()
    {
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->setStackId(new \stdClass());
        $stackWrapper->encrypt("mySecretValue");
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid Key
     */
    public function testInvalidKey1()
    {
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey('foobar');
        $stackWrapper->setStackKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->encrypt("mySecretValue");
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid Key
     */
    public function testInvalidKey2()
    {
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->setStackKey('foobar');
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->encrypt("mySecretValue");
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid Project Id
     */
    public function testInvalidProject()
    {
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->setStackKey('foobar');
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setProjectId(new \stdClass());
        $stackWrapper->encrypt("mySecretValue");
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid Component Id
     */
    public function testInvalidComponent()
    {
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->setStackKey('foobar');
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setComponentId(new \stdClass());
        $stackWrapper->encrypt("mySecretValue");
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Invalid Configuration Id
     */
    public function testInvalidConfiguration()
    {
        $stackWrapper = new StackWrapper();
        $stackWrapper->setGeneralKey(Key::createNewRandomKey()->saveToAsciiSafeString());
        $stackWrapper->setStackKey('foobar');
        $stackWrapper->setStackId('my-stack');
        $stackWrapper->setConfigurationId(new \stdClass());
        $stackWrapper->encrypt("mySecretValue");
    }


//ruzny kombinace component id a project id
    public function testMissingStacks()
    {
        $stackKey = substr(hash('sha256', uniqid()), 0, 16);
        $generalKey = substr(hash('sha256', uniqid()), 0, 16);
        $stackWrapper = new Stack2Wrapper($generalKey, "my-stack", $stackKey);
        $jsonWrapper = new StackWrapper($generalKey);

        $encrypted = $jsonWrapper->encrypt(
            [
                "key" => "value"
            ]
        );

        $this->expectException("Keboola\\DockerBundle\\Exception\\StackDataEncryptionException");
        $this->expectExceptionMessageRegExp("/Stacks not found./");
        $stackWrapper->decrypt($encrypted);
    }

    public function testMissingCurrentStack()
    {
        $stackKey = substr(hash('sha256', uniqid()), 0, 16);
        $generalKey = substr(hash('sha256', uniqid()), 0, 16);
        $stackWrapper = new Stack2Wrapper($generalKey, "my-stack", $stackKey);
        $jsonWrapper = new StackWrapper($generalKey);

        $encrypted = $jsonWrapper->encrypt(
            [
                "stacks" => [
                    "unknown-stack" => "unknownvalue"
                ]
            ]
        );

        $this->expectException("Keboola\\DockerBundle\\Exception\\StackDataEncryptionException");
        $this->expectExceptionMessageRegExp("/Stack my-stack not found./");
        $stackWrapper->decrypt($encrypted);
    }

    public function testAdd()
    {
        $stack1Key = substr(hash('sha256', uniqid()), 0, 16);
        $stack2Key = substr(hash('sha256', uniqid()), 0, 16);
        $generalKey = substr(hash('sha256', uniqid()), 0, 16);
        $stack1Wrapper = new Stack2Wrapper($generalKey, "my-stack-1", $stack1Key);
        $stack2Wrapper = new Stack2Wrapper($generalKey, "my-stack-2", $stack2Key);
        $jsonWrapper = new StackWrapper($generalKey);

        $encrypted = $stack1Wrapper->encrypt("whatever1");
        $encrypted = $stack2Wrapper->add("whatever2", $encrypted);

        $decrypted = $jsonWrapper->decrypt($encrypted);
        $this->assertArrayHasKey("stacks", $decrypted);
        $this->assertArrayHasKey("my-stack-1", $decrypted["stacks"]);
        $this->assertArrayHasKey("my-stack-2", $decrypted["stacks"]);
        $this->assertEquals("whatever1", $stack1Wrapper->decrypt($encrypted));
        $this->assertEquals("whatever2", $stack2Wrapper->decrypt($encrypted));
    }

    public function testAddMissingStacks()
    {
        $stack2Key = substr(hash('sha256', uniqid()), 0, 16);
        $generalKey = substr(hash('sha256', uniqid()), 0, 16);
        $stack2Wrapper = new Stack2Wrapper($generalKey, "my-stack-2", $stack2Key);
        $jsonWrapper = new StackWrapper($generalKey);

        $this->expectException("Keboola\\DockerBundle\\Exception\\StackDataEncryptionException");
        $this->expectExceptionMessageRegExp("/Stacks not found./");
        $encrypted = $jsonWrapper->encrypt(["key" => "value"]);
        $stack2Wrapper->add("whatever2", $encrypted);
    }
}
