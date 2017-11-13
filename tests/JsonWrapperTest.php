<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Wrapper\BaseWrapper;
use Keboola\ObjectEncryptor\Wrapper\StackWrapper;

class JsonWrapperTest extends \PHPUnit_Framework_TestCase
{

    public function testEncrypt()
    {
        $generalKey = substr(hash('sha256', uniqid()), 0, 16);
        $jsonWrapper = new StackWrapper($generalKey);

        $encrypted = $jsonWrapper->encrypt(["key" => "value"]);
        $this->assertEquals(["key" => "value"], $jsonWrapper->decrypt($encrypted));
    }

    public function testSerializationFailure()
    {
        $generalKey = substr(hash('sha256', uniqid()), 0, 16);
        $jsonWrapper = new StackWrapper($generalKey);
        $this->expectException("Keboola\\DockerBundle\\Exception\\EncryptionException");

        $this->expectExceptionMessageRegExp("/Serialization of encrypted data failed/");
        $jsonWrapper->encrypt("string");
    }

    public function testDeserializationFailure()
    {
        $generalKey = substr(hash('sha256', uniqid()), 0, 16);
        $jsonWrapper = new StackWrapper($generalKey);
        $baseWrapper = new BaseWrapper($generalKey);

        $encryptedString = $baseWrapper->encrypt("string");

        $this->expectException("Keboola\\DockerBundle\\Exception\\EncryptionException");
        $this->expectExceptionMessageRegExp("/Deserialization of decrypted data failed/");
        $jsonWrapper->decrypt($encryptedString);
    }
}
