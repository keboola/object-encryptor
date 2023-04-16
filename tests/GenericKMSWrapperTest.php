<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Aws\CommandInterface;
use Aws\Kms\KmsClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;
use PHPUnit\Framework\TestCase;

class GenericKMSWrapperTest extends TestCase
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
        $wrapper = self::createPartialMock(GenericKMSWrapper::class, ['getRetries']);
        $wrapper->method('getRetries')->willReturn(1);
        $wrapper->setKMSKeyId((string) getenv('TEST_AWS_KMS_KEY_ID'));
        $wrapper->setKMSRegion((string) getenv('TEST_AWS_REGION'));
        return $wrapper;
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

        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSRegion((string) getenv('TEST_AWS_REGION'));
        // This is ok, because KMS key is found automatically during decryption
        $wrapper->setKMSKeyId('non-existent');
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
                ['region' => (string) getenv('TEST_AWS_REGION'), 'version' => '2014-11-01', 'service' => 'kms'],
            ])
            ->setMethods(['execute'])
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
            ->setMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')
            ->willReturn($mockKmsClient);

        $secret = 'secret';
        /** @var GenericKMSWrapper $mockWrapper */
        $mockWrapper->setKMSKeyId((string) getenv('TEST_AWS_KMS_KEY_ID'));
        $mockWrapper->setKMSRegion((string) getenv('TEST_AWS_REGION'));
        $encrypted = $mockWrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $mockWrapper->decrypt($encrypted));
    }

    public function testRetryEncryptFail(): void
    {
        $mockKmsClient = $this->getMockBuilder(KmsClient::class)
            // Need to pass service explicitly, because AwsClient fails to detect it from mock
            ->setConstructorArgs([
                ['region' => (string) getenv('TEST_AWS_REGION'), 'version' => '2014-11-01', 'service' => 'kms'],
            ])
            ->onlyMethods(['execute'])
            ->getMock();
        $mockKmsClient->method('execute')
            ->willThrowException(
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri'))
            );

        $mockWrapper = $this->getMockBuilder(GenericKMSWrapper::class)
            ->setMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')
            ->willReturn($mockKmsClient);

        $secret = 'secret';
        /** @var GenericKMSWrapper $mockWrapper */
        $mockWrapper->setKMSKeyId((string) getenv('TEST_AWS_KMS_KEY_ID'));
        $mockWrapper->setKMSRegion((string) getenv('TEST_AWS_REGION'));
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
            ->setMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')
            ->willReturn($mockKmsClient);

        $secret = 'secret';
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId((string) getenv('TEST_AWS_KMS_KEY_ID'));
        $wrapper->setKMSRegion((string) getenv('TEST_AWS_REGION'));
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        /** @var GenericKMSWrapper $mockWrapper */
        $mockWrapper->setKMSKeyId((string) getenv('TEST_AWS_KMS_KEY_ID'));
        $mockWrapper->setKMSRegion((string) getenv('TEST_AWS_REGION'));
        self::assertEquals($secret, $mockWrapper->decrypt($encrypted));
    }

    public function testRetryDecryptFail(): void
    {
        $mockKmsClient = $this->getMockBuilder(KmsClient::class)
            // Need to pass service explicitly, because AwsClient fails to detect it from mock
            ->setConstructorArgs([
                ['region' => (string) getenv('TEST_AWS_REGION'), 'version' => '2014-11-01', 'service' => 'kms'],
            ])
            ->setMethods(['execute'])
            ->getMock();
        $mockKmsClient->method('execute')
            ->willThrowException(
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri'))
            );

        $mockWrapper = $this->getMockBuilder(GenericKMSWrapper::class)
            ->onlyMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')
            ->willReturn($mockKmsClient);

        $secret = 'secret';
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId((string) getenv('TEST_AWS_KMS_KEY_ID'));
        $wrapper->setKMSRegion((string) getenv('TEST_AWS_REGION'));
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        /** @var GenericKMSWrapper $mockWrapper */
        $mockWrapper->setKMSKeyId((string) getenv('TEST_AWS_KMS_KEY_ID'));
        $mockWrapper->setKMSRegion((string) getenv('TEST_AWS_REGION'));
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

    public function testInvalidSetupEncryptMissingAll(): void
    {
        $wrapper = new GenericKMSWrapper();
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupEncryptMissingKeyId(): void
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSRegion('my-region');
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupEncryptMissingRegion(): void
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId('my-key');
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupDecryptMissingAll(): void
    {
        $wrapper = new GenericKMSWrapper();
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidSetupDecryptMissingKeyId(): void
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSRegion('my-region');
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidSetupDecryptMissingRegion(): void
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId('my-key');
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidCredentials(): void
    {
        putenv('AWS_ACCESS_KEY_ID=' . getenv('TEST_AWS_ACCESS_KEY_ID'));
        putenv('AWS_SECRET_ACCESS_KEY=some-garbage');
        $wrapper = self::createPartialMock(GenericKMSWrapper::class, ['getRetries']);
        $wrapper->method('getRetries')->willReturn(0);

        $wrapper->setKMSKeyId((string) getenv('TEST_AWS_KMS_KEY_ID'));
        $wrapper->setKMSRegion((string) getenv('TEST_AWS_REGION'));
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Ciphering failed: Failed to obtain encryption key.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidRole(): void
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId((string) getenv('TEST_AWS_KMS_KEY_ID'));
        $wrapper->setKMSRegion((string) getenv('TEST_AWS_REGION'));
        $wrapper->setKMSRole('invalidEncryptionRoleName');
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Ciphering failed: Error executing "AssumeRole" ');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidNonExistentRegion(): void
    {
        $wrapper = self::createPartialMock(GenericKMSWrapper::class, ['getRetries']);
        $wrapper->method('getRetries')->willReturn(0);

        $wrapper->setKMSKeyId((string) getenv('TEST_AWS_KMS_KEY_ID'));
        $wrapper->setKMSRegion('non-existent');
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
