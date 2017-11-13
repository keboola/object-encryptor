<?php

namespace Keboola\ObjectEncryptor\Tests;

use Framework\TestCase;

class BaseWrapperTest extends TestCase
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
