<?php

namespace Keboola\ObjectEncryptor\Tests;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class EncryptorTest extends WebTestCase
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
