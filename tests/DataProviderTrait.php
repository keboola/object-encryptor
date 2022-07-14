<?php

namespace Keboola\ObjectEncryptor\Tests;

trait DataProviderTrait
{
    public function emptyValuesProvider(): array
    {
        return [
            [
                '',
            ],
            [
                '0',
            ],
            [
                null,
            ],
        ];
    }

    /**
     * @return string[][]
     */
    public function invalidCipherProvider(): array
    {
        return [
            [
                'some garbage',
                'Deciphering failed.',
            ],
            [
                base64_encode('some garbage'),
                'Deciphering failed.',
            ],
            [
                base64_encode(gzcompress('some garbage')),
                'Deciphering failed.',
            ],
            [
                base64_encode(gzcompress(serialize('some garbage'))),
                'Deciphering failed.',
            ],
            [
                base64_encode(gzcompress(serialize(['some', 'garbage']))),
                'Deciphering failed.',
            ],
        ];
    }
}
