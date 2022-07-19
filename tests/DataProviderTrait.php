<?php

declare(strict_types=1);

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
                base64_encode((string) gzcompress('some garbage')),
                'Deciphering failed.',
            ],
            [
                base64_encode((string) gzcompress(serialize('some garbage'))),
                'Deciphering failed.',
            ],
            [
                base64_encode((string) gzcompress(serialize(['some', 'garbage']))),
                'Deciphering failed.',
            ],
        ];
    }
}
