<?php

namespace Keboola\ObjectEncryptor\Tests;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use Keboola\AzureKeyVaultClient\Authentication\AuthenticatorFactory;
use Keboola\AzureKeyVaultClient\Client;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Keboola\AzureKeyVaultClient\Requests\SetSecretRequest;
use Keboola\AzureKeyVaultClient\Responses\SecretBundle;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\GenericAKVWrapper;
use PHPUnit\Framework\TestCase;
use PHPUnit_Framework_MockObject_MockObject;
use Psr\Log\NullLogger;
use RuntimeException;

class GenericAKVWrapperTest extends TestCase
{
    use DataProviderTrait;

    public function setUp()
    {
        parent::setUp();
        $envs = ['TEST_TENANT_ID', 'TEST_CLIENT_ID', 'TEST_CLIENT_SECRET', 'TEST_KEY_VAULT_URL'];
        foreach ($envs as $env) {
            if (!getenv($env)) {
                throw new RuntimeException(
                    sprintf('At least one of %s environment variables is empty.', implode(', ', $envs))
                );
            }
        }
        putenv('AZURE_TENANT_ID=' . getenv('TEST_TENANT_ID'));
        putenv('AZURE_CLIENT_ID=' . getenv('TEST_CLIENT_ID'));
        putenv('AZURE_CLIENT_SECRET=' . getenv('TEST_CLIENT_SECRET'));
    }

    /**
     * @return GenericAKVWrapper
     */
    private function getWrapper()
    {
        $wrapper = new GenericAKVWrapper();
        $wrapper->setKeyVaultUrl(getenv('TEST_KEY_VAULT_URL'));
        return $wrapper;
    }

    public function testEncryptNonScalar()
    {
        $wrapper = $this->getWrapper();
        self::expectException(UserException::class);
        self::expectExceptionMessage('Cannot encrypt a non-scalar value.');
        /** @noinspection PhpParamsInspection */
        $wrapper->encrypt(['invalid']);
    }

    public function testEncryptNoMetadata()
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

    public function testEncryptMetadata()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('componentId', 'keboola.a-very-long-component-id-with-some-extra-characters');
        $wrapper->setMetadataValue('configurationId', 'a-very-long-coniguration-id-with-some-extra-characters');
        $wrapper->setMetadataValue('stackId', 'https://connection.azure.us-east-1.keboola.com');
        $wrapper->setMetadataValue('projectId', '123456789');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('stackId', 'https://connection.azure.us-east-1.keboola.com');
        $wrapper->setMetadataValue('projectId', '123456789');
        $wrapper->setMetadataValue('componentId', 'keboola.a-very-long-component-id-with-some-extra-characters');
        $wrapper->setMetadataValue('configurationId', 'a-very-long-coniguration-id-with-some-extra-characters');
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptMetadataMismatch()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('componentId', 'keboola.a-very-long-component-id-with-some-extra-characters');
        $wrapper->setMetadataValue('configurationId', 'a-very-long-coniguration-id-with-some-extra-characters');
        $wrapper->setMetadataValue('stackId', 'https://connection.azure.us-east-1.keboola.com');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('stackId', 'https://connection.azure.us-east-1.keboola.com');
        $wrapper->setMetadataValue('configurationId', 'a-very-long-coniguration-id-with-some-extra-characters');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt($encrypted);
    }

    /**
     * @dataProvider emptyValuesProvider()
     * @param $secret
     * @throws ApplicationException
     * @throws UserException
     */
    public function testEncryptEmptyValue($secret)
    {
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @param Client|PHPUnit_Framework_MockObject_MockObject $mockClient
     * @return GenericAKVWrapper
     */
    private function getMockWrapper($mockClient)
    {
        $mockWrapper = self::getMockBuilder(GenericAKVWrapper::class)
            ->setMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')
            ->willReturn($mockClient);
        /** @var GenericAKVWrapper $mockWrapper */
        $mockWrapper->setKeyVaultUrl(getenv('TEST_KEY_VAULT_URL'));
        return $mockWrapper;
    }

    /** @noinspection PhpUnusedParameterInspection */
    public function testRetryEncryptDecrypt()
    {
        $mockClient = self::getMockBuilder(Client::class)
            ->setConstructorArgs([
                new GuzzleClientFactory(new NullLogger()),
                new AuthenticatorFactory(),
                getenv('TEST_KEY_VAULT_URL')
            ])
            ->setMethods(['setSecret', 'getSecret'])
            ->getMock();
        $callNoSet = 0;
        $callNoGet = 0;
        $secretInternal = '';
        $mockClient->expects(self::exactly(3))->method('setSecret')
            ->willReturnCallback(function (SetSecretRequest $setSecretRequest, $secretName)
                use (&$callNoSet, $mockClient, &$secretInternal)
            {
                $callNoSet++;
                $secretInternal = $setSecretRequest->getArray()['value'];
                if ($callNoSet < 3) {
                    throw new ConnectException('mock failed to connect', new Request('GET', 'some-uri'));
                } else {
                    /** @var Client $mockClient */
                    return new SecretBundle([
                        'id' => 'https://test.vault.azure.net/secrets/foo/53af0dad94f248',
                        'value' => $secretInternal,
                        'attributes' => [],
                    ]);
                }
            });
        $secret = 'secret';
        $mockClient->expects(self::exactly(3))->method('getSecret')
            ->willReturnCallback(function ($secretName, $secretVersion)
            use (&$callNoGet, $mockClient, &$secretInternal)
            {
                $callNoGet++;
                if ($callNoGet < 3) {
                    throw new ConnectException('mock failed to connect', new Request('GET', 'some-uri'));
                } else {
                    /** @var Client $mockClient */
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

    public function testRetryEncryptFail()
    {
        $mockClient = self::getMockBuilder(Client::class)
            ->setConstructorArgs([
                new GuzzleClientFactory(new NullLogger()),
                new AuthenticatorFactory(),
                getenv('TEST_KEY_VAULT_URL')
            ])
            ->setMethods(['setSecret'])
            ->getMock();
        $mockClient->method('setSecret')
            ->willThrowException(
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri'))
            );

        $secret = 'secret';
        $mockWrapper = $this->getMockWrapper($mockClient);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Ciphering failed: mock failed to connect');
        $mockWrapper->encrypt($secret);
    }

    public function testRetryDecryptFail()
    {
        $mockClient = self::getMockBuilder(Client::class)
            ->setConstructorArgs([
                new GuzzleClientFactory(new NullLogger()),
                new AuthenticatorFactory(),
                getenv('TEST_KEY_VAULT_URL')
            ])
            ->setMethods(['getSecret'])
            ->getMock();
        $mockClient->method('getSecret')
            ->willThrowException(
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri'))
            );

        $secret = 'secret';
        $wrapper = new GenericAKVWrapper();
        $wrapper->setKeyVaultUrl(getenv('TEST_KEY_VAULT_URL'));
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        $mockWrapper = $this->getMockWrapper($mockClient);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $mockWrapper->decrypt($encrypted);
    }

    /** @noinspection PhpUnusedParameterInspection */
    public function testInvalidSecretContents()
    {
        $mockClient = self::getMockBuilder(Client::class)
            ->setConstructorArgs([
                new GuzzleClientFactory(new NullLogger()),
                new AuthenticatorFactory(),
                getenv('TEST_KEY_VAULT_URL')
            ])
            ->setMethods(['setSecret', 'getSecret'])
            ->getMock();
        $mockClient->method('setSecret')
            ->willReturnCallback(function (SetSecretRequest $setSecretRequest, $secretName) use ($mockClient) {
                /** @var Client $mockClient */
                return new SecretBundle([
                    'id' => 'https://test.vault.azure.net/secrets/foo/53af0dad94f248',
                    'value' => 'not-used',
                    'attributes' => [],
                ]);
            });
        $secret = 'secret';
        $mockClient->method('getSecret')
            ->willReturnCallback(function ($secretName, $secretVersion) use ($mockClient, &$secretInternal) {
                /** @var Client $mockClient */
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

    /** @noinspection PhpUnusedParameterInspection */
    public function testInvalidSecretCipher()
    {
        $mockClient = self::getMockBuilder(Client::class)
            ->setConstructorArgs([
                new GuzzleClientFactory(new NullLogger()),
                new AuthenticatorFactory(),
                getenv('TEST_KEY_VAULT_URL')
            ])
            ->setMethods(['setSecret', 'getSecret'])
            ->getMock();
        $secretInternal = '';
        $mockClient->method('setSecret')
            ->willReturnCallback(function (SetSecretRequest $setSecretRequest, $secretName)
            use ($mockClient, &$secretInternal)
            {
                $secretInternal = $setSecretRequest->getArray()['value'];
                /** @var Client $mockClient */
                return new SecretBundle([
                    'id' => 'https://test.vault.azure.net/secrets/foo/53af0dad94f248',
                    'value' => $secretInternal,
                    'attributes' => []
                ]);
            });
        $secret = 'secret';
        $mockClient->method('getSecret')
            ->willReturnCallback(function ($secretName, $secretVersion) use ($mockClient, &$secretInternal) {
                /** @var Client $mockClient */
                $contents = unserialize(gzuncompress(base64_decode($secretInternal)));
                $contents[GenericAKVWrapper::KEY_INDEX] = 'garbage';
                return new SecretBundle([
                    'id' => 'https://test.vault.azure.net/secrets/foo/53af0dad94f248',
                    'attributes' => [],
                    'value' => base64_encode(gzcompress(serialize($contents))),
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
     * @param string $cipher
     * @param string $message
     * @throws ApplicationException
     * @throws UserException
     */
    public function testDecryptInvalidCiphers($cipher, $message)
    {
        $wrapper = $this->getWrapper();
        self::expectException(UserException::class);
        self::expectExceptionMessage($message);
        $wrapper->decrypt($cipher);
    }

    public function testInvalidSetupMissingUrl()
    {
        $wrapper = new GenericAKVWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are invalid.');
        $wrapper->encrypt('test');
    }

    public function testInvalidSetupInvalidUrl()
    {
        $wrapper = new GenericAKVWrapper();
        $wrapper->setKeyVaultUrl('test-key');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Invalid options when creating client: Value "test-key" is invalid');
        $wrapper->encrypt('test');
    }

    public function testInvalidSetupInvalidUrlDecrypt()
    {
        $wrapper = new GenericAKVWrapper();
        $wrapper->setKeyVaultUrl('test-key');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $wrapper->decrypt(base64_encode(gzcompress(serialize([2 => 'test', 3 => 'test', 4 => 'test']))));
    }

    public function testInvalidSetupInvalidCredentials()
    {
        putenv('AZURE_CLIENT_ID=');
        $wrapper = new GenericAKVWrapper();
        $wrapper->setKeyVaultUrl(getenv('TEST_KEY_VAULT_URL'));
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Ciphering failed: No suitable authentication method found.');
        $wrapper->encrypt('test');
    }
}
