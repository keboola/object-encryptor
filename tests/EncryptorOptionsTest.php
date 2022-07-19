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
        $options = new EncryptorOptions('my-stack', 'my-kms-id', 'region', 'akv-url');
        self::assertSame('my-stack', $options->getStackId());
        self::assertSame('my-kms-id', $options->getKmsKeyId());
        self::assertSame('region', $options->getKmsKeyRegion());
        self::assertSame('akv-url', $options->getAkvUrl());
    }

    public function testConstructEmptyStack(): void
    {
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Invalid Stack Id.');
        new EncryptorOptions('', null, null, null);
    }

    public function testConstructEmptyConfig(): void
    {
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Neither KMS, nor KeyVault configured.');
        new EncryptorOptions('my-stack', null, null, null);
    }
}
