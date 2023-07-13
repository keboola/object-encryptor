<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Wrapper;

interface CryptoWrapperInterface
{
    /**
     * Return a prefix for the encrypted string identifying this wrapper.
     *  It is important that this prefix is different for each wrapper.
     */
    public static function getPrefix(): string;

    public function encrypt(string $data): string;

    public function decrypt(string $encryptedData): string;
}
