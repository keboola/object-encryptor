<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Aws\CommandInterface;
use Aws\Kms\KmsClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;

class GenericKMSWrapperTest extends AbstractTestCase
{
    use DataProviderTrait;

    public function setUp(): void
    {
        parent::setUp();
        putenv('AWS_ACCESS_KEY_ID=' . getenv('TEST_AWS_ACCESS_KEY_ID'));
        putenv('AWS_SECRET_ACCESS_KEY='. getenv('TEST_AWS_SECRET_ACCESS_KEY'));
    }

    private function getWrapper(): GenericKMSWrapper
    {
        return new GenericKMSWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: self::getKmsKeyId(),
            kmsRegion: self::getKmsRegion(),
            backoffMaxTries: 1,
        ));
    }

    public function testEncrypt(): void
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptWrongKey(): void
    {
        $wrapper = $this->getWrapper();
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = new GenericKMSWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            // This is ok, because KMS key is found automatically during decryption
            kmsKeyId: 'non-existent',
            kmsRegion: self::getKmsRegion(),
        ));
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @dataProvider emptyValuesProvider()
     */
    public function testEncryptEmptyValue(?string $secret): void
    {
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testRetryEncrypt(): void
    {
        $mockKmsClient = $this->getMockBuilder(KmsClient::class)
            // Need to pass service explicitly, because AwsClient fails to detect it from mock
            ->setConstructorArgs([
                ['region' => self::getKmsRegion(), 'version' => '2014-11-01', 'service' => 'kms'],
            ])
            ->onlyMethods(['execute'])
            ->getMock();
        $callNo = 0;
        $mockKmsClient->method('execute')
            ->willReturnCallback(function (CommandInterface $command) use (&$callNo, $mockKmsClient) {
                $callNo++;
                if ($callNo < 3) {
                    throw new ConnectException('mock failed to connect', new Request('GET', 'some-uri'));
                } else {
                    /** @var KmsClient $mockKmsClient */
                    return $mockKmsClient->executeAsync($command)->wait();
                }
            });

        $mockWrapper = $this->getMockBuilder(GenericKMSWrapper::class)
            ->setConstructorArgs([new EncryptorOptions(
                stackId: 'some-stack',
                kmsKeyId: self::getKmsKeyId(),
                kmsRegion: self::getKmsRegion(),
                backoffMaxTries: 3,
            )])
            ->onlyMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')->willReturn($mockKmsClient);

        $secret = 'secret';
        /** @var GenericKMSWrapper $mockWrapper */
        $mockWrapper->setKMSKeyId(self::getKmsKeyId());
        $mockWrapper->setKMSRegion(self::getKmsRegion());
        $encrypted = $mockWrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $mockWrapper->decrypt($encrypted));
    }

    public function testRetryEncryptFail(): void
    {
        $mockKmsClient = $this->getMockBuilder(KmsClient::class)
            // Need to pass service explicitly, because AwsClient fails to detect it from mock
            ->setConstructorArgs([
                ['region' => self::getKmsRegion(), 'version' => '2014-11-01', 'service' => 'kms'],
            ])
            ->onlyMethods(['execute'])
            ->getMock();
        $mockKmsClient->method('execute')
            ->willThrowException(
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri'))
            );

        $mockWrapper = $this->getMockBuilder(GenericKMSWrapper::class)
            ->setConstructorArgs([new EncryptorOptions(
                stackId: 'some-stack',
                kmsKeyId: self::getKmsKeyId(),
                kmsRegion: self::getKmsRegion(),
                backoffMaxTries: 3,
            )])
            ->onlyMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')->willReturn($mockKmsClient);

        $secret = 'secret';
        /** @var GenericKMSWrapper $mockWrapper */
        $mockWrapper->setKMSKeyId(self::getKmsKeyId());
        $mockWrapper->setKMSRegion(self::getKmsRegion());
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Ciphering failed: Failed to obtain encryption key.');
        $mockWrapper->encrypt($secret);
    }

    public function testRetryDecrypt(): void
    {
        $mockKmsClient = $this->getMockBuilder(KmsClient::class)
            // Need to pass service explicitly, because AwsClient fails to detect it from mock
            ->setConstructorArgs([
                ['region' => getenv('TEST_AWS_REGION'), 'version' => '2014-11-01', 'service' => 'kms'],
            ])
            ->onlyMethods(['execute'])
            ->getMock();
        $mockKmsClient->method('execute')
            ->willReturnCallback(function (CommandInterface $command) use (&$callNo, $mockKmsClient) {
                $callNo++;
                if ($callNo < 3) {
                    throw new ConnectException('mock failed to connect', new Request('GET', 'some-uri'));
                } else {
                    /** @var KmsClient $mockKmsClient */
                    return $mockKmsClient->executeAsync($command)->wait();
                }
            });

        $mockWrapper = $this->getMockBuilder(GenericKMSWrapper::class)
            ->setConstructorArgs([new EncryptorOptions(
                stackId: 'some-stack',
                kmsKeyId: self::getKmsKeyId(),
                kmsRegion: self::getKmsRegion(),
                backoffMaxTries: 3,
            )])
            ->onlyMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')->willReturn($mockKmsClient);

        $secret = 'secret';
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        /** @var GenericKMSWrapper $mockWrapper */
        self::assertEquals($secret, $mockWrapper->decrypt($encrypted));
    }

    public function testRetryDecryptFail(): void
    {
        $mockKmsClient = $this->getMockBuilder(KmsClient::class)
            // Need to pass service explicitly, because AwsClient fails to detect it from mock
            ->setConstructorArgs([
                ['region' => self::getKmsRegion(), 'version' => '2014-11-01', 'service' => 'kms'],
            ])
            ->setMethods(['execute'])
            ->getMock();
        $mockKmsClient->method('execute')
            ->willThrowException(
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri'))
            );

        $mockWrapper = $this->getMockBuilder(GenericKMSWrapper::class)
            ->setConstructorArgs([new EncryptorOptions(
                stackId: 'some-stack',
                kmsKeyId: self::getKmsKeyId(),
                kmsRegion: self::getKmsRegion(),
                backoffMaxTries: 3,
            )])
            ->onlyMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')->willReturn($mockKmsClient);

        $secret = 'secret';
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        /** @var GenericKMSWrapper $mockWrapper */
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Deciphering failed.');
        $mockWrapper->decrypt($encrypted);
    }

    public function testEncryptMetadata(): void
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptRole(): void
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $wrapper->setKMSRole((string) getenv('TEST_AWS_ROLE_ID'));
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptMetadataCacheHit(): void
    {
        $secret1 = 'mySecretValue1';
        $secret2 = 'mySecretValue2';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $encrypted1 = $wrapper->encrypt($secret1);
        self::assertNotEquals($secret1, $encrypted1);
        self::assertEquals($secret1, $wrapper->decrypt($encrypted1));
        $encrypted2 = $wrapper->encrypt($secret2);
        self::assertNotEquals($secret2, $encrypted2);
        self::assertEquals($secret2, $wrapper->decrypt($encrypted2));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $wrapper->decrypt($encrypted1);
        self::assertEquals($secret1, $wrapper->decrypt($encrypted1));
        $wrapper->decrypt($encrypted2);
        self::assertEquals($secret2, $wrapper->decrypt($encrypted2));
    }

    public function testEncryptMetadataCacheMiss(): void
    {
        $secret1 = 'mySecretValue1';
        $secret2 = 'mySecretValue2';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key1', 'value1');
        $encrypted1 = $wrapper->encrypt($secret1);
        self::assertNotEquals($secret1, $encrypted1);
        self::assertEquals($secret1, $wrapper->decrypt($encrypted1));
        $wrapper->setMetadataValue('key2', 'value2');
        $encrypted2 = $wrapper->encrypt($secret2);
        self::assertNotEquals($secret2, $encrypted2);
        self::assertEquals($secret2, $wrapper->decrypt($encrypted2));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key1', 'value1');
        $wrapper->decrypt($encrypted1);
        self::assertEquals($secret1, $wrapper->decrypt($encrypted1));
        $wrapper->setMetadataValue('key2', 'value2');
        $wrapper->decrypt($encrypted2);
        self::assertEquals($secret2, $wrapper->decrypt($encrypted2));
    }

    public function testEncryptMetadataMismatchNoMetadata(): void
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        $this->expectException(UserException::class);
        $this->expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    public function testEncryptMetadataMismatchBadMetadata(): void
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value-bad');
        $this->expectException(UserException::class);
        $this->expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    public function testInvalidSetupDecryptMissingAll(): void
    {
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Cipher key settings are missing.');
        new GenericKMSWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'some-url',
        ));
    }

    public function testInvalidCredentials(): void
    {
        putenv('AWS_ACCESS_KEY_ID=' . getenv('TEST_AWS_ACCESS_KEY_ID'));
        putenv('AWS_SECRET_ACCESS_KEY=some-garbage');
        $wrapper = $this->getWrapper();

        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Ciphering failed: Failed to obtain encryption key.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidRole(): void
    {
        $wrapper = new GenericKMSWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: self::getKmsKeyId(),
            kmsRegion: self::getKmsRegion(),
            kmsRole: 'invalidEncryptionRoleName',
            backoffMaxTries: 1,
        ));
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Ciphering failed: Error executing "AssumeRole" ');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidNonExistentRegion(): void
    {
        $wrapper = new GenericKMSWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: self::getKmsKeyId(),
            kmsRegion: 'non-existent',
            backoffMaxTries: 1
        ));
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Ciphering failed: Failed to obtain encryption key.');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @dataProvider invalidCipherProvider()
     */
    public function testDecryptInvalidCiphers(string $cipher, string $message): void
    {
        $wrapper = $this->getWrapper();
        $this->expectException(UserException::class);
        $this->expectExceptionMessage($message);
        $wrapper->decrypt($cipher);
    }
}
