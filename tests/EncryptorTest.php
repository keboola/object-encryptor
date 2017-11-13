<?php

namespace Keboola\ObjectEncryptor\Tests;

use PHPUnit\Framework\TestCase;

class EncryptorTest extends TestCase
{
    public function testEncryptor()
    {
        $client = static::createClient();
        $container = $client->getContainer();

        $encryptor = $container->get('syrup.encryptor');

        $encrypted = $encryptor->encrypt('secret');

        $this->assertEquals('secret', $encryptor->decrypt($encrypted));
    }
}
