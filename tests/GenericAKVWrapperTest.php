<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use Keboola\AzureKeyVaultClient\Authentication\AuthenticatorFactory;
use Keboola\AzureKeyVaultClient\Client;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Keboola\AzureKeyVaultClient\Requests\SetSecretRequest;
use Keboola\AzureKeyVaultClient\Responses\SecretBundle;
use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\GenericAKVWrapper;
use Psr\Log\NullLogger;
use RuntimeException;

class GenericAKVWrapperTest extends AbstractTestCase
{
    use DataProviderTrait;

    public function setUp(): void
    {
        parent::setUp();
        $envs = ['TEST_TENANT_ID', 'TEST_CLIENT_ID', 'TEST_CLIENT_SECRET', 'TEST_KEY_VAULT_URL'];
        foreach ($envs as $env) {
            if (!getenv($env)) {
                throw new RuntimeException(
                    sprintf('At least one of %s environment variables is empty.', implode(', ', $envs)),
                );
            }
        }
        putenv('AZURE_TENANT_ID=' . getenv('TEST_TENANT_ID'));
        putenv('AZURE_CLIENT_ID=' . getenv('TEST_CLIENT_ID'));
        putenv('AZURE_CLIENT_SECRET=' . getenv('TEST_CLIENT_SECRET'));
        $this->clearSecrets();
    }

    private function clearSecrets(): void
    {
        $client = new Client(
            new GuzzleClientFactory(new NullLogger()),
            new AuthenticatorFactory(),
            self::getAkvUrl(),
        );
        foreach ($client->getAllSecrets() as $secret) {
            $client->deleteSecret($secret->getName());
        }
    }

    private function getWrapper(): GenericAKVWrapper
    {
        return new GenericAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: self::getAkvUrl(),
        ));
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
        self::assertEquals('KBC::SecureKV::', $wrapper->getPrefix());
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

    public function testIgnoreSecretVersionWhenRetrievingSecret(): void
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);

        // decode the encrypted secret and manually change the version
        $decoded = unserialize((string) gzuncompress(base64_decode($encrypted)));
        $secretVersionIndex = 4; // = GenericAKVWrapper::SECRET_VERSION
        /** @var array<int, string> $decoded */
        $decoded[$secretVersionIndex] = bin2hex(random_bytes(16));

        // encode back with the changed version
        $encrypted = base64_encode((string) gzcompress(serialize($decoded)));

        // decrypt should succeed regardless of changed version
        $decrypted = $wrapper->decrypt($encrypted);

        self::assertSame($secret, $decrypted);
    }

    private function getMockWrapper(Client $mockClient): GenericAKVWrapper
    {
        $mockWrapper = $this->createPartialMock(GenericAKVWrapper::class, ['getClient']);
        $mockWrapper->method('getClient')->willReturn($mockClient);
        return $mockWrapper;
    }

    public function testRetryEncryptDecrypt(): void
    {
        $mockClient = $this->getMockBuilder(Client::class)
            ->setConstructorArgs([
                new GuzzleClientFactory(new NullLogger()),
                new AuthenticatorFactory(),
                self::getAkvUrl(),
            ])
            ->onlyMethods(['setSecret', 'getSecret'])
            ->getMock();
        $callNoSet = 0;
        $callNoGet = 0;
        $secretInternal = '';
        $mockClient->expects(self::exactly(3))->method('setSecret')
            ->willReturnCallback(function (
                SetSecretRequest $setSecretRequest,
            ) use (
                &$callNoSet,
                &$secretInternal,
            ) {
                $callNoSet++;
                $secretInternal = $setSecretRequest->getArray()['value'];
                if ($callNoSet < 3) {
                    throw new ConnectException('mock failed to connect', new Request('GET', 'some-uri'));
                } else {
                    return new SecretBundle([
                        'id' => 'https://test.vault.azure.net/secrets/foo/53af0dad94f248',
                        'value' => $secretInternal,
                        'attributes' => [],
                    ]);
                }
            });
        $secret = 'secret';
        $mockClient->expects(self::exactly(3))->method('getSecret')
            ->willReturnCallback(function (
                $secretName,
                $secretVersion,
            ) use (
                &$callNoGet,
                &$secretInternal,
            ) {
                $callNoGet++;
                if ($callNoGet < 3) {
                    throw new ConnectException('mock failed to connect', new Request('GET', 'some-uri'));
                } else {
                    return new SecretBundle([
                        'id' => 'https://test.vault.azure.net/secrets/foo/53af0dad94f248',
                        'attributes' => [],
                        'value' => $secretInternal,
                    ]);
                }
            });

        $mockWrapper = $this->getMockWrapper($mockClient);
        $encrypted = $mockWrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $mockWrapper->decrypt($encrypted));
    }

    public function testRetryEncryptFail(): void
    {
        $mockClient = $this->getMockBuilder(Client::class)
            ->setConstructorArgs([
                new GuzzleClientFactory(new NullLogger()),
                new AuthenticatorFactory(),
                self::getAkvUrl(),
            ])
            ->onlyMethods(['setSecret'])
            ->getMock();
        $mockClient->method('setSecret')
            ->willThrowException(
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri')),
            );

        $secret = 'secret';
        $mockWrapper = $this->getMockWrapper($mockClient);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Ciphering failed: mock failed to connect');
        $mockWrapper->encrypt($secret);
    }

    public function testRetryDecryptFail(): void
    {
        $mockClient = $this->getMockBuilder(Client::class)
            ->setConstructorArgs([
                new GuzzleClientFactory(new NullLogger()),
                new AuthenticatorFactory(),
                self::getAkvUrl(),
            ])
            ->setMethods(['getSecret'])
            ->getMock();
        $mockClient->method('getSecret')
            ->willThrowException(
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri')),
            );

        $secret = 'secret';
        $wrapper = new GenericAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: self::getAkvUrl(),
        ));
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        $mockWrapper = $this->getMockWrapper($mockClient);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $mockWrapper->decrypt($encrypted);
    }

    /** @noinspection PhpUnusedParameterInspection */
    public function testInvalidSecretContents(): void
    {
        $mockClient = $this->getMockBuilder(Client::class)
            ->setConstructorArgs([
                new GuzzleClientFactory(new NullLogger()),
                new AuthenticatorFactory(),
                self::getAkvUrl(),
            ])
            ->setMethods(['setSecret', 'getSecret'])
            ->getMock();
        $mockClient->method('setSecret')
            ->willReturnCallback(function (SetSecretRequest $setSecretRequest, $secretName) {
                return new SecretBundle([
                    'id' => 'https://test.vault.azure.net/secrets/foo/53af0dad94f248',
                    'value' => 'not-used',
                    'attributes' => [],
                ]);
            });
        $secret = 'secret';
        $mockClient->method('getSecret')
            ->willReturnCallback(function ($secretName, $secretVersion) {
                return new SecretBundle([
                    'id' => 'https://test.vault.azure.net/secrets/foo/53af0dad94f248',
                    'attributes' => [],
                    'value' => 'garbage',
                ]);
            });

        $mockWrapper = $this->getMockWrapper($mockClient);
        $encrypted = $mockWrapper->encrypt($secret);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $mockWrapper->decrypt($encrypted);
    }

    public function testInvalidSecretCipher(): void
    {
        $mockClient = $this->getMockBuilder(Client::class)
            ->setConstructorArgs([
                new GuzzleClientFactory(new NullLogger()),
                new AuthenticatorFactory(),
                self::getAkvUrl(),
            ])
            ->setMethods(['setSecret', 'getSecret'])
            ->getMock();
        $secretInternal = '';
        $mockClient->method('setSecret')
            ->willReturnCallback(function (
                SetSecretRequest $setSecretRequest,
                $secretName,
            ) use (
                &$secretInternal,
            ) {
                $secretInternal = $setSecretRequest->getArray()['value'];
                return new SecretBundle([
                    'id' => 'https://test.vault.azure.net/secrets/foo/53af0dad94f248',
                    'value' => $secretInternal,
                    'attributes' => [],
                ]);
            });
        $secret = 'secret';
        $mockClient->method('getSecret')
            ->willReturnCallback(function () use (&$secretInternal) {
                $contents = unserialize((string) gzuncompress(base64_decode($secretInternal)));
                self::assertIsArray($contents);
                $contents[1] = 'garbage';
                return new SecretBundle([
                    'id' => 'https://test.vault.azure.net/secrets/foo/53af0dad94f248',
                    'attributes' => [],
                    'value' => base64_encode((string) gzcompress(serialize($contents))),
                ]);
            });

        $mockWrapper = $this->getMockWrapper($mockClient);
        $encrypted = $mockWrapper->encrypt($secret);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $mockWrapper->decrypt($encrypted);
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

    public function testInvalidSetupMissingUrl(): void
    {
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        new GenericAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            kmsKeyId: 'test-key',
            kmsRegion: 'test-region',
        ));
    }

    public function testInvalidSetupInvalidUrl(): void
    {
        $wrapper = new GenericAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'test-key',
        ));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid options when creating client: Value "test-key" is invalid');
        $wrapper->encrypt('test');
    }

    public function testInvalidSetupInvalidUrlDecrypt(): void
    {
        $wrapper = new GenericAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'test-key',
        ));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt(base64_encode((string) gzcompress(serialize([2 => 'test', 3 => 'test', 4 => 'test']))));
    }

    public function testInvalidSetupInvalidCredentials(): void
    {
        putenv('AZURE_CLIENT_ID=invalid');
        $wrapper = new GenericAKVWrapper(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: self::getAkvUrl(),
        ));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Ciphering failed: Failed to get authentication token');
        $wrapper->encrypt('test');
    }
}
