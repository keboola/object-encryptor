<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Google\Cloud\Kms\V1\DecryptResponse;
use Google\Cloud\Kms\V1\EncryptResponse;
use Google\Cloud\Kms\V1\KeyManagementServiceClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\GenericGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\GkmsClientFactory;

class GenericGKMWrapperTest extends AbstractTestCase
{
    use DataProviderTrait;
    use TestEnvVarsTrait;

    public function setUp(): void
    {
        parent::setUp();
        putenv('GOOGLE_APPLICATION_CREDENTIALS=' . getenv('TEST_GOOGLE_APPLICATION_CREDENTIALS'));
    }

    /**
     * @param non-empty-string|null $role
     */
    private function getWrapper(?string $role = null): GenericGKMSWrapper
    {
        $options = new EncryptorOptions(
            stackId: 'some-stack',
            gkmsKeyId: self::getGkmsKeyId(),
            backoffMaxTries: 1,
        );

        return new GenericGKMSWrapper(
            (new GKmsClientFactory())->createClient($options),
            $options,
        );
    }

    public function testEncryptNoMetadata(): void
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
        self::assertEquals('KBC::SecureGKMS::', $wrapper->getPrefix());
    }

    public function testEncryptMetadata(): void
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('componentId', 'keboola.a-very-long-component-id-with-some-extra-characters');
        $wrapper->setMetadataValue('configurationId', 'a-very-long-configuration-id-with-some-extra-characters');
        $wrapper->setMetadataValue('stackId', 'https://connection.azure.us-east-1.keboola.com');
        $wrapper->setMetadataValue('projectId', '123456789');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        // the ordering is intentionally different to the above
        $wrapper->setMetadataValue('stackId', 'https://connection.azure.us-east-1.keboola.com');
        $wrapper->setMetadataValue('projectId', '123456789');
        $wrapper->setMetadataValue('componentId', 'keboola.a-very-long-component-id-with-some-extra-characters');
        $wrapper->setMetadataValue('configurationId', 'a-very-long-configuration-id-with-some-extra-characters');

        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptMetadataMismatch(): void
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('componentId', 'keboola.a-very-long-component-id-with-some-extra-characters');
        $wrapper->setMetadataValue('configurationId', 'a-very-long-configuration-id-with-some-extra-characters');
        $wrapper->setMetadataValue('stackId', 'https://connection.azure.us-east-1.keboola.com');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('stackId', 'https://connection.azure.us-east-1.keboola.com');
        $wrapper->setMetadataValue('configurationId', 'a-very-long-configuration-id-with-some-extra-characters');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
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

    public function testRetryEncryptDecrypt(): void
    {
        $mockClient = $this->createMock(KeyManagementServiceClient::class);
        $callNoSet = 0;
        $callNoGet = 0;
        $mockClient->expects(self::exactly(3))->method('encrypt')
            ->willReturnCallback(function (string $keyId, string $valueToEncrypt) use (&$callNoSet) {
                $callNoSet++;
                if ($callNoSet < 3) {
                    throw new ConnectException('mock failed to connect', new Request('GET', 'some-uri'));
                } else {
                    return new EncryptResponse(['ciphertext' => $valueToEncrypt]);
                }
            });
        $secret = 'secret';
        $mockClient->expects(self::exactly(3))->method('decrypt')
            ->willReturnCallback(function (string $keyId, string $encryptedValue) use (&$callNoGet) {
                $callNoGet++;
                if ($callNoGet < 3) {
                    throw new ConnectException('mock failed to connect', new Request('GET', 'some-uri'));
                } else {
                    return new DecryptResponse(['plaintext' => $encryptedValue]);
                }
            });

        $options = new EncryptorOptions(
            stackId: 'some-stack',
            gkmsKeyId: self::getGkmsKeyId(),
            backoffMaxTries: 3,
        );

        $wrapper = new GenericGKMSWrapper($mockClient, $options);
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testRetryEncryptFail(): void
    {
        $mockClient = $this->createMock(KeyManagementServiceClient::class);
        $mockClient->expects(self::exactly(1))->method('encrypt')
            ->willThrowException(
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri')),
            );

        $options = new EncryptorOptions(
            stackId: 'some-stack',
            gkmsKeyId: self::getGkmsKeyId(),
            backoffMaxTries: 1,
        );
        $wrapper = new GenericGKMSWrapper($mockClient, $options);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Ciphering failed: mock failed to connect');
        $wrapper->encrypt('secret');
    }

    public function testRetryDecryptFail(): void
    {
        $mockClient = $this->createMock(KeyManagementServiceClient::class);
        $mockClient->expects(self::exactly(1))->method('decrypt')
            ->willThrowException(
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri')),
            );

        $options = new EncryptorOptions(
            stackId: 'some-stack',
            gkmsKeyId: self::getGkmsKeyId(),
            backoffMaxTries: 1,
        );
        $secret = 'secret';
        $wrapper = new GenericGKMSWrapper(new KeyManagementServiceClient(), $options);
        $encrypted = $wrapper->encrypt($secret);

        $wrapper = new GenericGKMSWrapper($mockClient, $options);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    public function testInvalidSecretCipher(): void
    {
        $mockClient = $this->createMock(KeyManagementServiceClient::class);
        $mockClient->expects(self::once())->method('decrypt')
            ->willReturnCallback(function () {
                return new DecryptResponse(['plaintext' => 'garbage']);
            });
        $options = new EncryptorOptions(
            stackId: 'some-stack',
            gkmsKeyId: self::getGkmsKeyId(),
            backoffMaxTries: 1,
        );
        $secret = 'secret';
        $wrapper = new GenericGKMSWrapper(new KeyManagementServiceClient(), $options);
        $encrypted = $wrapper->encrypt($secret);

        $wrapper = new GenericGKMSWrapper($mockClient, $options);
        self::assertNotEquals($secret, $encrypted);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    /**
     * @dataProvider invalidCipherProvider()
     */
    public function testDecryptInvalidCiphers(string $cipher, string $message): void
    {
        $wrapper = $this->getWrapper();
        self::expectException(UserException::class);
        self::expectExceptionMessage($message);
        $wrapper->decrypt($cipher);
    }

    public function testInvalidSetupMissingKeyId(): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        new GenericGKMSWrapper(
            new KeyManagementServiceClient(),
            new EncryptorOptions(
                stackId: 'some-stack',
                kmsKeyId: 'test-key',
                kmsRegion: 'test-region',
            ),
        );
    }

    public function testInvalidSetupInvalidKeyId(): void
    {
        $wrapper = new GenericGKMSWrapper(
            new KeyManagementServiceClient(),
            new EncryptorOptions(
                stackId: 'some-stack',
                gkmsKeyId: 'test-key',
            ),
        );
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Ciphering failed: Could not map bindings for');
        $wrapper->encrypt('test');
    }

    public function testInvalidSetupInvalidUrlDecrypt(): void
    {
        $wrapper = new GenericGKMSWrapper(
            new KeyManagementServiceClient(),
            new EncryptorOptions(
                stackId: 'some-stack',
                gkmsKeyId: 'test-key',
            ),
        );
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt(base64_encode((string) gzcompress(serialize([0 => 'test', 1 => 'test']))));
    }

    public function testInvalidSetupInvalidCredentialsAfterConstruct(): void
    {
        $client = new KeyManagementServiceClient();
        putenv('GOOGLE_APPLICATION_CREDENTIALS=invalid-credentials.json');
        $wrapper = new GenericGKMSWrapper(
            $client,
            new EncryptorOptions(
                stackId: 'some-stack',
                gkmsKeyId: self::getGkmsKeyId(),
            ),
        );
        $encrypted = $wrapper->encrypt('test');
        self::assertNotEquals('test', $encrypted);
    }
}
