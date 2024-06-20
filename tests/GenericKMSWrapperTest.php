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
use Keboola\ObjectEncryptor\Wrapper\KmsClientFactory;

class GenericKMSWrapperTest extends AbstractTestCase
{
    use DataProviderTrait;
    use TestEnvVarsTrait;

    public function setUp(): void
    {
        parent::setUp();
        putenv('AWS_ACCESS_KEY_ID=' . getenv('TEST_AWS_ACCESS_KEY_ID'));
        putenv('AWS_SECRET_ACCESS_KEY='. getenv('TEST_AWS_SECRET_ACCESS_KEY'));
    }

    /**
     * @param non-empty-string|null $role
     */
    private function getWrapper(?string $role = null): GenericKMSWrapper
    {
        $options = new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: self::getKmsKeyId(),
            kmsRegion: self::getKmsRegion(),
            kmsRole: $role,
            backoffMaxTries: 1,
        );

        return new GenericKMSWrapper(
            (new KmsClientFactory())->createClient($options),
            $options,
        );
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

        $options = new EncryptorOptions(
            stackId: 'some-stack',
            // This is ok, because KMS key is found automatically during decryption
            kmsKeyId: 'non-existent',
            kmsRegion: self::getKmsRegion(),
        );

        $wrapper = new GenericKMSWrapper(
            (new KmsClientFactory())->createClient($options),
            $options,
        );
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

        $options = new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: self::getKmsKeyId(),
            kmsRegion: self::getKmsRegion(),
            backoffMaxTries: 3,
        );

        $mockWrapper = new GenericKMSWrapper(
            $mockKmsClient,
            $options,
        );

        $secret = 'secret';
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
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri')),
            );

        $mockWrapper = new GenericKMSWrapper(
            $mockKmsClient,
            new EncryptorOptions(
                stackId: 'some-stack',
                kmsKeyId: self::getKmsKeyId(),
                kmsRegion: self::getKmsRegion(),
                backoffMaxTries: 3,
            ),
        );

        $secret = 'secret';
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

        $mockWrapper = new GenericKMSWrapper(
            $mockKmsClient,
            new EncryptorOptions(
                stackId: 'some-stack',
                kmsKeyId: self::getKmsKeyId(),
                kmsRegion: self::getKmsRegion(),
                backoffMaxTries: 3,
            ),
        );
        $secret = 'secret';
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
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
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri')),
            );

        $mockWrapper = new GenericKMSWrapper(
            $mockKmsClient,
            new EncryptorOptions(
                stackId: 'some-stack',
                kmsKeyId: self::getKmsKeyId(),
                kmsRegion: self::getKmsRegion(),
                backoffMaxTries: 3,
            ),
        );

        $secret = 'secret';
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);

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
        $wrapper = $this->getWrapper(self::getRequiredEnv('TEST_AWS_ROLE_ID'));
        $wrapper->setMetadataValue('key', 'value');
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
        $options = new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'some-url',
        );

        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Cipher key settings are missing.');
        new GenericKMSWrapper(
            (new KmsClientFactory())->createClient($options),
            $options,
        );
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
        $options = new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: self::getKmsKeyId(),
            kmsRegion: self::getKmsRegion(),
            kmsRole: 'invalidEncryptionRoleName',
            backoffMaxTries: 1,
        );

        $wrapper = new GenericKMSWrapper(
            (new KmsClientFactory())->createClient($options),
            $options,
        );
        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage('Ciphering failed: Failed to obtain encryption key.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidNonExistentRegion(): void
    {
        $options = new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: self::getKmsKeyId(),
            kmsRegion: 'non-existent',
            backoffMaxTries: 1,
        );

        $wrapper = new GenericKMSWrapper(
            (new KmsClientFactory())->createClient($options),
            $options,
        );
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
