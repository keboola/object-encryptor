<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Legacy\Wrapper\BaseWrapper;
use PHPUnit\Framework\TestCase;

class BaseWrapperTest extends TestCase
{
    public function testPrefix()
    {
        $wrapper = new BaseWrapper();
        self::assertEquals('KBC::Encrypted==', $wrapper->getPrefix());
    }

    public function testEncryptor()
    {
        $wrapper = new BaseWrapper();
        $wrapper->setKey(1234567890123456);
        $encrypted = $wrapper->encrypt('secret');
        self::assertEquals('secret', $wrapper->decrypt($encrypted));
    }
}
