<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests\Temporary;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Keboola\AzureKeyVaultClient\Client;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\Requests\SetSecretRequest;
use Keboola\AzureKeyVaultClient\Responses\SecretBundle;
use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\ObjectEncryptor;
use Keboola\ObjectEncryptor\ObjectEncryptorFactory;
use Keboola\ObjectEncryptor\Temporary\TransClient;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeProjectWideAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectWideAKVWrapper;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class AKVWrappersWithTransClientTest extends TestCase
{
    public function setUp(): void
    {
        parent::setUp();

        putenv('TRANS_AZURE_TENANT_ID=');
        putenv('TRANS_AZURE_CLIENT_ID=');
        putenv('TRANS_AZURE_CLIENT_SECRET=');
        putenv('TRANS_ENCRYPTOR_STACK_ID=');
    }

    public static function provideAKVWrappers(): iterable
    {
        yield GenericAKVWrapper::class => [
            'wrapperClass' => GenericAKVWrapper::class,
            'metadata' => [],
        ];

        yield ComponentAKVWrapper::class => [
            'wrapperClass' => ComponentAKVWrapper::class,
            'metadata' => [
                'stackId' => 'some-stack',
                'componentId' => 'component-id',
            ],
        ];

        yield ProjectAKVWrapper::class => [
            'wrapperClass' => ProjectAKVWrapper::class,
            'metadata' => [
                'stackId' => 'some-stack',
                'componentId' => 'component-id',
                'projectId' => 'project-id',
            ],
        ];

        yield ConfigurationAKVWrapper::class => [
            'wrapperClass' => ConfigurationAKVWrapper::class,
            'metadata' => [
                'stackId' => 'some-stack',
                'componentId' => 'component-id',
                'projectId' => 'project-id',
                'configurationId' => 'config-id',
            ],
        ];

        yield ProjectWideAKVWrapper::class => [
            'wrapperClass' => ProjectWideAKVWrapper::class,
            'metadata' => [
                'stackId' => 'some-stack',
                'projectId' => 'project-id',
            ],
        ];

        yield BranchTypeProjectAKVWrapper::class => [
            'wrapperClass' => BranchTypeProjectAKVWrapper::class,
            'metadata' => [
                'stackId' => 'some-stack',
                'componentId' => 'component-id',
                'projectId' => 'project-id',
                'branchType' => 'branch-type',
            ],
        ];

        yield BranchTypeConfigurationAKVWrapper::class => [
            'wrapperClass' => BranchTypeConfigurationAKVWrapper::class,
            'metadata' => [
                'stackId' => 'some-stack',
                'componentId' => 'component-id',
                'projectId' => 'project-id',
                'configurationId' => 'config-id',
                'branchType' => 'branch-type',
            ],
        ];

        yield BranchTypeProjectWideAKVWrapper::class => [
            'wrapperClass' => BranchTypeProjectWideAKVWrapper::class,
            'metadata' => [
                'stackId' => 'some-stack',
                'projectId' => 'project-id',
                'branchType' => 'branch-type',
            ],
        ];
    }

    /**
     * @dataProvider provideAKVWrappers
     * @param class-string<GenericAKVWrapper> $wrapperClass
     */
    public function testWrappersDoNotHaveTransClientInitializedWhenTransEnvsMissing(
        string $wrapperClass,
    ): void {
        $encryptorOptions = new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'some-url',
        );

        $wrapper = new $wrapperClass($encryptorOptions);

        self::assertNull($wrapper->getTransClient());
    }

    /**
     * @dataProvider provideAKVWrappers
     * @param class-string<GenericAKVWrapper> $wrapperClass
     */
    public function testWrappersHaveTransClientInitialized(
        string $wrapperClass,
    ): void {
        putenv('TRANS_AZURE_TENANT_ID=tenant-id');
        putenv('TRANS_AZURE_CLIENT_ID=client-id');
        putenv('TRANS_AZURE_CLIENT_SECRET=client-secret');
        putenv('TRANS_AZURE_KEY_VAULT_URL=https://vault-url');

        $encryptorOptions = new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'some-url',
        );

        $wrapper = new $wrapperClass($encryptorOptions);

        $transClient = $wrapper->getTransClient();
        self::assertInstanceOf(TransClient::class, $transClient);

        // ensure getter returns a single instance of the TransClient
        self::assertSame($transClient, $wrapper->getTransClient());
    }

    /**
     * @dataProvider provideAKVWrappers
     * @param class-string<GenericAKVWrapper> $wrapperClass
     */
    public function testWrappersHaveTransClientWhenEncryptorIdMatches(
        string $wrapperClass,
    ): void {
        putenv('TRANS_AZURE_TENANT_ID=tenant-id');
        putenv('TRANS_AZURE_CLIENT_ID=client-id');
        putenv('TRANS_AZURE_CLIENT_SECRET=client-secret');
        putenv('TRANS_AZURE_KEY_VAULT_URL=');
        putenv('TRANS_AZURE_KEY_VAULT_URL_EXTRA_BRATWURST=https://german-vault-url');

        $encryptorOptions = new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'some-url',
            encryptorId: 'extra-bratwurst',
        );

        $wrapper = new $wrapperClass($encryptorOptions);

        $transClient = $wrapper->getTransClient();
        self::assertInstanceOf(TransClient::class, $transClient);

        // ensure getter returns a single instance of the TransClient
        self::assertSame($transClient, $wrapper->getTransClient());
    }

    /**
     * @dataProvider provideAKVWrappers
     * @param class-string<GenericAKVWrapper> $wrapperClass
     */
    public function testWrappersDoNotHaveTransClientWhenEncryptorIdMismatches(
        string $wrapperClass,
    ): void {
        putenv('TRANS_AZURE_TENANT_ID=tenant-id');
        putenv('TRANS_AZURE_CLIENT_ID=client-id');
        putenv('TRANS_AZURE_CLIENT_SECRET=client-secret');
        putenv('TRANS_AZURE_KEY_VAULT_URL=');
        putenv('TRANS_AZURE_KEY_VAULT_URL_EXTRA_BRATWURST=https://german-vault-url');

        // null encryptorId
        $wrapper = new $wrapperClass(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'some-url',
            encryptorId: null,
        ));
        self::assertNull($wrapper->getTransClient());

        // encryptorId does not match env suffix ('extra-sausage' vs. _EXTRA_BRATWURST)
        $wrapper = new $wrapperClass(new EncryptorOptions(
            stackId: 'some-stack',
            akvUrl: 'some-url',
            encryptorId: 'extra-sausage',
        ));
        self::assertNull($wrapper->getTransClient());
    }

    /**
     * @dataProvider provideAKVWrappers
     * @param class-string<GenericAKVWrapper> $wrapperClass
     */
    public function testDecryptWithBackfillWhenSecretNotFoundInTransVault(
        string $wrapperClass,
        array $metadata,
    ): void {
        putenv('TRANS_ENCRYPTOR_STACK_ID=trans-stack');

        $key = Key::createNewRandomKey();

        $mockClient = $this->createMock(Client::class);
        $mockClient->expects(self::once())
            ->method('getSecret')
            ->with('secret-name')
            ->willReturn(new SecretBundle([
                'id' => 'secret-id',
                'value' => self::encode([
                    0 => $metadata,
                    1 => $key->saveToAsciiSafeString(),
                ]),
                'attributes' => [],
            ]));

        $mockTransClient = $this->createMock(TransClient::class);
        $mockTransClient->expects(self::once())
            ->method('getSecret')
            ->with('secret-name')
            ->willThrowException(new ClientException('not found', 404));
        $mockTransClient->expects(self::once())
            ->method('setSecret')
            ->with(
                self::callback(function ($arg) use ($key, $metadata) {
                    self::assertInstanceOf(SetSecretRequest::class, $arg);

                    if (array_key_exists('stackId', $metadata)) {
                        $metadata['stackId'] = 'trans-stack';
                    }
                    $encodedKey = self::encode([
                        0 => $metadata,
                        1 => $key->saveToAsciiSafeString(),
                    ]);

                    self::assertSame($encodedKey, $arg->getArray()['value']);
                    return true;
                }),
                'secret-name',
            );

        $logsHandler = new TestHandler();
        $logger = new Logger('test', [$logsHandler]);

        /** @var GenericAKVWrapper|MockObject $mockWrapper */
        $mockWrapper = $this->getMockBuilder($wrapperClass)
            ->setConstructorArgs([
                new EncryptorOptions(
                    stackId: 'some-stack',
                    akvUrl: 'some-url',
                ),
            ])
            ->onlyMethods(['getClient', 'getTransClient'])
            ->getMock();
        $mockWrapper->logger = $logger;
        foreach ($metadata as $metaKey => $metaValue) {
            $mockWrapper->setMetadataValue($metaKey, $metaValue);
        }
        $mockWrapper->expects(self::once())
            ->method('getClient')
            ->willReturn($mockClient);
        $mockWrapper->expects(self::atLeast(3))
            ->method('getTransClient')
            ->willReturn($mockTransClient);

        $encryptedSecret = self::encode([
            2 => Crypto::encrypt('something very secret', $key, true),
            3 => 'secret-name',
            4 => 'secret-version',
        ]);

        $secret = $mockWrapper->decrypt($encryptedSecret);

        self::assertSame('something very secret', $secret);
        self::assertTrue($logsHandler->hasInfoThatPasses(fn($r) =>
            $r['message'] === 'Secret "{secretName}" migrated in {stackId} AKV.' &&
            $r['context'] === [
                'secretName' => 'secret-name',
                'stackId' => 'trans-stack',
            ]));
    }

    /**
     * @dataProvider provideAKVWrappers
     * @param class-string<GenericAKVWrapper> $wrapperClass
     */
    public function testDecryptOmitsPrimaryVaultWhenSecretFoundInTransVault(
        string $wrapperClass,
        array $metadata,
    ): void {
        $key = Key::createNewRandomKey();

        $mockTransClient = $this->createMock(TransClient::class);
        $mockTransClient->expects(self::once())
            ->method('getSecret')
            ->with('secret-name')
            ->willReturn(new SecretBundle([
                'id' => 'secret-id',
                'value' => self::encode([
                    0 => $metadata,
                    1 => $key->saveToAsciiSafeString(),
                ]),
                'attributes' => [],
            ]));
        $mockTransClient->expects(self::never())->method('setSecret');

        /** @var GenericAKVWrapper|MockObject $mockWrapper */
        $mockWrapper = $this->getMockBuilder($wrapperClass)
            ->setConstructorArgs([
                new EncryptorOptions(
                    stackId: 'some-stack',
                    akvUrl: 'some-url',
                ),
            ])
            ->onlyMethods(['getClient', 'getTransClient'])
            ->getMock();
        foreach ($metadata as $metaKey => $metaValue) {
            $mockWrapper->setMetadataValue($metaKey, $metaValue);
        }
        $mockWrapper->expects(self::never())->method('getClient');
        $mockWrapper->expects(self::exactly(2))
            ->method('getTransClient')
            ->willReturn($mockTransClient);

        $encryptedSecret = self::encode([
            2 => Crypto::encrypt('something very secret', $key, true),
            3 => 'secret-name',
            4 => 'secret-version',
        ]);

        $secret = $mockWrapper->decrypt($encryptedSecret);

        self::assertSame('something very secret', $secret);
    }

    public function testTransVaultGetSecretFails(): void
    {
        $key = Key::createNewRandomKey();

        $mockTransClient = $this->createMock(TransClient::class);
        $mockTransClient->expects(self::exactly(3))
            ->method('getSecret')
            ->with('secret-name')
            ->willThrowException(new ClientException('something failed', 500));
        $mockTransClient->expects(self::never())->method('setSecret');

        /** @var GenericAKVWrapper|MockObject $mockWrapper */
        $mockWrapper = $this->getMockBuilder(GenericAKVWrapper::class)
            ->setConstructorArgs([
                new EncryptorOptions(
                    stackId: 'some-stack',
                    akvUrl: 'some-url',
                ),
            ])
            ->onlyMethods(['getClient', 'getTransClient'])
            ->getMock();
        $mockWrapper->expects(self::never())->method('getClient');
        $mockWrapper->expects(self::exactly(4))
            ->method('getTransClient')
            ->willReturn($mockTransClient);

        $encryptedSecret = self::encode([
            2 => Crypto::encrypt('something very secret', $key, true),
            3 => 'secret-name',
            4 => 'secret-version',
        ]);

        $this->expectException(ApplicationException::class);
        $this->expectExceptionCode(500);
        $this->expectExceptionMessage('Deciphering failed.');

        $mockWrapper->decrypt($encryptedSecret);
    }

    public function testLogErrorWhenTransVaultSetSecretFails(): void
    {
        putenv('TRANS_ENCRYPTOR_STACK_ID=trans-stack');

        $key = Key::createNewRandomKey();

        $mockClient = $this->createMock(Client::class);
        $mockClient->expects(self::once())
            ->method('getSecret')
            ->with('secret-name')
            ->willReturn(new SecretBundle([
                'id' => 'secret-id',
                'value' => self::encode([
                    0 => [],
                    1 => $key->saveToAsciiSafeString(),
                ]),
                'attributes' => [],
            ]));

        $mockTransClient = $this->createMock(TransClient::class);
        $mockTransClient->expects(self::once())
            ->method('getSecret')
            ->with('secret-name')
            ->willThrowException(new ClientException('not found', 404));

        $setSecretException = new ClientException('something failed', 500);
        $mockTransClient->expects(self::exactly(3))
            ->method('setSecret')
            ->willThrowException($setSecretException);

        $logsHandler = new TestHandler();
        $logger = new Logger('test', [$logsHandler]);

        /** @var GenericAKVWrapper|MockObject $mockWrapper */
        $mockWrapper = $this->getMockBuilder(GenericAKVWrapper::class)
            ->setConstructorArgs([
                new EncryptorOptions(
                    stackId: 'some-stack',
                    akvUrl: 'some-url',
                ),
            ])
            ->onlyMethods(['getClient', 'getTransClient'])
            ->getMock();
        $mockWrapper->logger = $logger;
        $mockWrapper->expects(self::once())
            ->method('getClient')
            ->willReturn($mockClient);
        $mockWrapper->expects(self::exactly(5))
            ->method('getTransClient')
            ->willReturn($mockTransClient);

        $encryptedSecret = self::encode([
            2 => Crypto::encrypt('something very secret', $key, true),
            3 => 'secret-name',
            4 => 'secret-version',
        ]);

        $secret = $mockWrapper->decrypt($encryptedSecret);

        self::assertSame('something very secret', $secret);
        self::assertTrue($logsHandler->hasErrorThatPasses(fn($r) =>
            $r['message'] === 'Migration of secret "{secretName}" in {stackId} AKV failed.' &&
            $r['context'] === [
                'secretName' => 'secret-name',
                'stackId' => 'trans-stack',
                'exception' => $setSecretException,
            ]));
    }

    public function testSkipBackfillWhenTransStackIdEnvNotSet(): void
    {
        putenv('TRANS_ENCRYPTOR_STACK_ID=');

        $key = Key::createNewRandomKey();

        $mockClient = $this->createMock(Client::class);
        $mockClient->expects(self::once())
            ->method('getSecret')
            ->with('secret-name')
            ->willReturn(new SecretBundle([
                'id' => 'secret-id',
                'value' => self::encode([
                    0 => [],
                    1 => $key->saveToAsciiSafeString(),
                ]),
                'attributes' => [],
            ]));

        $mockTransClient = $this->createMock(TransClient::class);
        $mockTransClient->expects(self::once())
            ->method('getSecret')
            ->with('secret-name')
            ->willThrowException(new ClientException('not found', 404));
        $mockTransClient->expects(self::never())->method('setSecret');

        $logsHandler = new TestHandler();
        $logger = new Logger('test', [$logsHandler]);

        /** @var GenericAKVWrapper|MockObject $mockWrapper */
        $mockWrapper = $this->getMockBuilder(GenericAKVWrapper::class)
            ->setConstructorArgs([
                new EncryptorOptions(
                    stackId: 'some-stack',
                    akvUrl: 'some-url',
                ),
            ])
            ->onlyMethods(['getClient', 'getTransClient'])
            ->getMock();
        $mockWrapper->logger = $logger;
        $mockWrapper->expects(self::once())
            ->method('getClient')
            ->willReturn($mockClient);
        $mockWrapper->expects(self::exactly(2))
            ->method('getTransClient')
            ->willReturn($mockTransClient);

        $encryptedSecret = self::encode([
            2 => Crypto::encrypt('something very secret', $key, true),
            3 => 'secret-name',
            4 => 'secret-version',
        ]);

        $secret = $mockWrapper->decrypt($encryptedSecret);

        self::assertSame('something very secret', $secret);
        self::assertTrue($logsHandler->hasErrorThatContains('Env TRANS_ENCRYPTOR_STACK_ID not set.'));
    }

    public function testObjectEncryptorFactoryInjectsLoggerInAKVWrappers(): void
    {
        $logsHandler = new TestHandler();
        $logger = new Logger('test', [$logsHandler]);

        $encryptor = ObjectEncryptorFactory::getEncryptor(
            new EncryptorOptions(
                stackId: 'some-stack',
                akvUrl: 'some-url',
            ),
            $logger,
        );

        $reflection = new ReflectionClass(ObjectEncryptor::class);
        $method = $reflection->getMethod('getWrappers');
        $method->setAccessible(true);

        /** @var array<GenericAKVWrapper> $wrappers */
        $wrappers = $method->invokeArgs($encryptor, ['component-id', 'project-id', 'config-id', 'branch-type']);

        self::assertIsArray($wrappers);
        self::assertCount(8, $wrappers);

        foreach ($wrappers as $wrapper) {
            self::assertSame($logger, $wrapper->logger);
        }
    }

    private static function encode(mixed $data): string
    {
        return base64_encode((string) gzcompress(serialize($data)));
    }
}
