<?php

namespace Keboola\ObjectEncryptor\Tests;

trait DataProviderTrait
{
    public function emptyValuesProvider()
    {
        return [
            [
                '',
            ],
            [
                '0',
            ],
            [
                0,
            ],
            [
                null,
            ],
        ];
    }

    /**
     * @return \string[][]
     */
    public function invalidCipherProvider()
    {
        return [
            [
                'some garbage',
                'Cipher is malformed',
            ],
            [
                base64_encode('some garbage'),
                'Cipher is malformed',
            ],
            [
                base64_encode(gzcompress('some garbage')),
                'Cipher is malformed',
            ],
            [
                base64_encode(gzcompress(serialize('some garbage'))),
                'Cipher is malformed',
            ],
        ];
    }
}
