<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\CryptoWrapperInterface;
use PHPUnit\Framework\Assert;

trait UnserializeCanaryTrait
{
    /**
     * A cipher is attacker-controlled and is unserialized before any MAC/KMS/AKV check runs,
     * so decoding it must never instantiate a class from the payload.
     */
    private function assertDecryptDoesNotInstantiateClasses(CryptoWrapperInterface $wrapper): void
    {
        UnserializeCanary::reset();

        // Single-element array so the wrapper's element-count guard rejects it before any
        // cloud call is made - this keeps the test offline.
        $cipher = base64_encode((string) gzcompress(serialize([new UnserializeCanary()])));

        try {
            $wrapper->decrypt($cipher);
            Assert::fail('Decrypting a crafted cipher must fail.');
        } catch (UserException $e) {
            Assert::assertSame('Deciphering failed.', $e->getMessage());
        }

        Assert::assertFalse(
            UnserializeCanary::$wokenUp,
            'unserialize() instantiated a class from the cipher payload.',
        );
    }
}
