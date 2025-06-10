<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use PHPUnit\Framework\TestCase;

class EncryptorOptionsTest extends TestCase
{
    public function testAccessors(): void
    {
        $options = new EncryptorOptions(
            stackId: 'my-stack',
            kmsKeyId: 'my-kms-id',
            kmsRegion: 'region',
            kmsRole: 'role',
            akvUrl: 'akv-url',
            gkmsKeyId: 'gkms-key-id',
            backoffMaxTries: 1,
        );
        self::assertSame('my-stack', $options->getStackId());
        self::assertSame('my-kms-id', $options->getKmsKeyId());
        self::assertSame('region', $options->getKmsKeyRegion());
        self::assertSame('role', $options->getKmsRole());
        self::assertSame('akv-url', $options->getAkvUrl());
        self::assertSame('gkms-key-id', $options->getGkmsKeyId());
        self::assertSame(1, $options->getBackoffMaxTries());
    }

    public function testConstructEmptyConfig(): void
    {
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Neither AWS KMS, nor KeyVault, nor Google KMS is configured.');
        new EncryptorOptions('my-stack', null, null, null, null, null);
    }

    public function testConstructEmptyStringsConfig(): void
    {
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Neither AWS KMS, nor KeyVault, nor Google KMS is configured.');
        // @phpstan-ignore-next-line
        new EncryptorOptions('my-stack', '', '', '', '', '');
    }
}
