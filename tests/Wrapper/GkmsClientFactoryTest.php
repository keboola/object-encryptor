<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests\Wrapper;

use Google\Cloud\Kms\V1\KeyManagementServiceClient;
use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Tests\AbstractTestCase;
use Keboola\ObjectEncryptor\Wrapper\GkmsClientFactory;

class GkmsClientFactoryTest extends AbstractTestCase
{
    public function setUp(): void
    {
        parent::setUp();
    }

    public function testCreatedClientWorks(): void
    {
        $client = (new GkmsClientFactory())->createClient(new EncryptorOptions(
            stackId: 'some-stack',
            gkmsKeyId: self::getGkmsKeyId(),
            backoffMaxTries: 0,
        ));

        self::assertInstanceOf(KeyManagementServiceClient::class, $client);
        $originalValue = 'foo';
        $encryptedValue = $client->encrypt(
            self::getGkmsKeyId(),
            $originalValue,
        )->getCiphertext();
        $decryptedValue = $client->decrypt(
            self::getGkmsKeyId(),
            $encryptedValue,
        )->getPlaintext();

        self::assertSame($originalValue, $decryptedValue);
    }
}
