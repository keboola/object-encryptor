<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests\Temporary;

use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Keboola\ObjectEncryptor\Temporary\TransClient;
use Keboola\ObjectEncryptor\Temporary\TransClientNotAvailableException;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class TransClientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        putenv('TRANS_AZURE_TENANT_ID=');
        putenv('TRANS_AZURE_CLIENT_ID=');
        putenv('TRANS_AZURE_CLIENT_SECRET=');

        $definedEnvsInProviders = array_column([
            ...self::provideTransClientUrlTestData(),
            ...self::provideTransClientMismatchEnvsTestData(),
            ], 'envs');
        foreach (array_keys(array_merge(...$definedEnvsInProviders)) as $envName) {
            putenv(sprintf('%s=', $envName));
        }
    }

    public static function provideDeterminateVaultUrlEnvNameTestData(): iterable
    {
        yield 'encryptorId is null' => [
            'encryptorId' => null,
            'expectedEnvName' => 'TRANS_AZURE_KEY_VAULT_URL',
        ];
        yield 'encryptorId is empty' => [
            'encryptorId' => '',
            'expectedEnvName' => 'TRANS_AZURE_KEY_VAULT_URL',
        ];
        yield 'encryptorId = "internal"' => [
            'encryptorId' => 'internal',
            'expectedEnvName' => 'TRANS_AZURE_KEY_VAULT_URL_INTERNAL',
        ];
        yield 'encryptorId = "job_queue"' => [
            'encryptorId' => 'job_queue',
            'expectedEnvName' => 'TRANS_AZURE_KEY_VAULT_URL_JOB_QUEUE',
        ];
        yield 'encryptorId = "job__queue_"' => [
            'encryptorId' => 'job__queue_',
            'expectedEnvName' => 'TRANS_AZURE_KEY_VAULT_URL_JOB_QUEUE',
        ];
        yield 'encryptorId = "job-queue"' => [
            'encryptorId' => 'job-queue',
            'expectedEnvName' => 'TRANS_AZURE_KEY_VAULT_URL_JOB_QUEUE',
        ];
        yield 'encryptorId = "job queue"' => [
            'encryptorId' => 'job queue',
            'expectedEnvName' => 'TRANS_AZURE_KEY_VAULT_URL_JOB_QUEUE',
        ];
    }

    /** @dataProvider provideDeterminateVaultUrlEnvNameTestData */
    public function testDeterminateVaultUrlEnvName(
        ?string $encryptorId,
        string $expectedEnvName,
    ): void {
        self::assertSame(
            $expectedEnvName,
            TransClient::determinateVaultUrlEnvName($encryptorId),
        );
    }

    public static function provideTransClientUrlTestData(): iterable
    {
        yield 'encryptorId is null' => [
            'encryptorId' => null,
            'envs' => [
                'TRANS_AZURE_KEY_VAULT_URL' => 'https://vault-url',
            ],
            'expectedClientUrl' => 'https://vault-url',
        ];

        yield 'encryptorId = "internal"' => [
            'encryptorId' => 'internal',
            'envs' => [
                'TRANS_AZURE_KEY_VAULT_URL_INTERNAL' => 'https://internal-vault-url',
            ],
            'expectedClientUrl' => 'https://internal-vault-url',
        ];
    }

    /** @dataProvider provideTransClientUrlTestData */
    public function testTransClientUrl(
        ?string $encryptorId,
        array $envs,
        string $expectedVaultUrl,
    ): void {
        putenv('TRANS_AZURE_TENANT_ID=tenant-id');
        putenv('TRANS_AZURE_CLIENT_ID=client-id');
        putenv('TRANS_AZURE_CLIENT_SECRET=client-secret');
        foreach ($envs as $envName => $envValue) {
            putenv(sprintf('%s=%s', $envName, $envValue));
        }

        $guzzleClientFactoryCounter = self::exactly(2);
        $guzzleClientFactoryMock = $this->createMock(GuzzleClientFactory::class);
        $guzzleClientFactoryMock->expects($guzzleClientFactoryCounter)
            ->method('getClient')
            ->with(
                self::callback(fn($url) => match ($guzzleClientFactoryCounter->getInvocationCount()) {
                    1 => $url === $expectedVaultUrl,
                    2 => $url === 'https://management.azure.com/metadata/endpoints?api-version=2020-01-01',
                    default => self::fail('Unexpected url: ' . $url),
                }),
                self::isType('array'),
            );

        try {
            new TransClient(
                $guzzleClientFactoryMock,
                $encryptorId,
            );
        } catch (TransClientNotAvailableException) {
            self::fail('Test should not have thrown an exception');
        }
    }

    public static function provideTransClientMismatchEnvsTestData(): iterable
    {
        yield 'encryptorId is null, env has suffix' => [
            'encryptorId' => null,
            'envs' => [
                'TRANS_AZURE_KEY_VAULT_URL_SOMETHING' => 'https://vault-url',
            ],
        ];

        yield 'encryptorId = "internal", env suffix is missing' => [
            'encryptorId' => 'internal',
            'envs' => [
                'TRANS_AZURE_KEY_VAULT_URL' => 'https://vault-url',
            ],
        ];
    }

    /** @dataProvider provideTransClientMismatchEnvsTestData */
    public function testTransClientMismatchEnvs(
        ?string $encryptorId,
        array $envs,
    ): void {
        putenv('TRANS_AZURE_TENANT_ID=tenant-id');
        putenv('TRANS_AZURE_CLIENT_ID=client-id');
        putenv('TRANS_AZURE_CLIENT_SECRET=client-secret');
        foreach ($envs as $envName => $envValue) {
            putenv(sprintf('%s=%s', $envName, $envValue));
        }

        $this->expectException(TransClientNotAvailableException::class);

        new TransClient(
            new GuzzleClientFactory(new NullLogger()),
            $encryptorId,
        );
    }
}
