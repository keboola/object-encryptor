<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Wrapper\StackWrapper;
use Keboola\ObjectEncryptor\Wrapper\Stack2Wrapper;

class StackWrapperTest extends \PHPUnit_Framework_TestCase
{
    public function testEncrypt()
    {
        $stackKey = substr(hash('sha256', uniqid()), 0, 16);
        $generalKey = substr(hash('sha256', uniqid()), 0, 16);
        $stackWrapper = new Stack2Wrapper($generalKey, "my-stack", $stackKey);
        $jsonWrapper = new StackWrapper($generalKey);

        $encrypted = $stackWrapper->encrypt("mySecretValue");
        $this->assertEquals("mySecretValue", $stackWrapper->decrypt($encrypted));

        $dataDecrypted = $jsonWrapper->decrypt($encrypted);
        $this->assertArrayHasKey("stacks", $dataDecrypted);
        $this->assertArrayHasKey("my-stack", $dataDecrypted["stacks"]);
    }

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
