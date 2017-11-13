<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Legacy\Wrapper\BaseWrapper;

class AnotherCryptoWrapper extends BaseWrapper
{
    /**
     * @inheritdoc
     */
    public function getPrefix()
    {
        return 'KBC::AnotherCryptoWrapper==';
    }
}
