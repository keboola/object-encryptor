<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Legacy\Encryptor;
use PHPUnit\Framework\TestCase;

class EncryptorTest extends TestCase
{
    public function testEncryptor()
    {
        if (!extension_loaded('mcrypt')) {
            self::markTestSkipped("Mcrypt not available");
        }
        $encryptor = new Encryptor('123456789012345678901234567890ab');
        $encrypted = $encryptor->encrypt('secret');
        self::assertEquals('secret', $encryptor->decrypt($encrypted));
    }
}
