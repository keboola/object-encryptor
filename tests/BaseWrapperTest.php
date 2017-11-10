<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\Syrup\Encryption\BaseWrapper;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class BaseWrapperTest extends KernelTestCase
{
    public function setUp()
    {
        static::bootKernel();
    }

    public function testPrefix()
    {
        /** @var BaseWrapper $wrapper */
        $wrapper = self::$kernel->getContainer()->get('syrup.encryption.base_wrapper');
        $this->assertEquals('KBC::Encrypted==', $wrapper->getPrefix());
    }

    public function testEncryptor()
    {
        $wrapper = self::$kernel->getContainer()->get('syrup.encryption.base_wrapper');
        $encrypted = $wrapper->encrypt('secret');
        $this->assertEquals('secret', $wrapper->decrypt($encrypted));
    }
}
