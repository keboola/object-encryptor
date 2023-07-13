<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests\Wrapper;

use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Tests\AbstractTestCase;
use Keboola\ObjectEncryptor\Wrapper\KmsClientFactory;

class KmsClientFactoryTest extends AbstractTestCase
{
    public function testCreatedClientWorks(): void
    {
        $client = (new KmsClientFactory())->createClient(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: self::getKmsKeyId(),
            kmsRegion: self::getKmsRegion(),
            backoffMaxTries: 0,
        ));

        $originalValue = 'foo';
        $encryptedValue = $client->encrypt([
            'KeyId' => self::getKmsKeyId(),
            'Plaintext' => $originalValue,
        ]);
        $decryptedValue = $client->decrypt([
            'KeyId' => self::getKmsKeyId(),
            'CiphertextBlob' => $encryptedValue['CiphertextBlob'],
        ]);

        self::assertSame($originalValue, $decryptedValue['Plaintext']);
    }

    public function testCreatedClientWithCustomRoleWorks(): void
    {
        $client = (new KmsClientFactory())->createClient(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: self::getKmsKeyId(),
            kmsRegion: self::getKmsRegion(),
            kmsRole: self::getKmsRoleId(),
            backoffMaxTries: 0,
        ));

        $originalValue = 'foo';
        $encryptedValue = $client->encrypt([
            'KeyId' => self::getKmsKeyId(),
            'Plaintext' => $originalValue,
        ]);
        $decryptedValue = $client->decrypt([
            'KeyId' => self::getKmsKeyId(),
            'CiphertextBlob' => $encryptedValue['CiphertextBlob'],
        ]);

        self::assertSame($originalValue, $decryptedValue['Plaintext']);
    }
}
