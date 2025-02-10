<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests\Temporary;

use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Keboola\ObjectEncryptor\Temporary\TransAuthenticatorFactory;
use Keboola\ObjectEncryptor\Temporary\TransClientNotAvailableException;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class TransAuthenticatorFactoryTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        putenv('TRANS_AZURE_TENANT_ID=');
        putenv('TRANS_AZURE_CLIENT_ID=');
        putenv('TRANS_AZURE_CLIENT_SECRET=');
    }

    public function testTransAuthenticatorIsAvailable(): void
    {
        putenv('TRANS_AZURE_TENANT_ID=tenant-id');
        putenv('TRANS_AZURE_CLIENT_ID=client-id');
        putenv('TRANS_AZURE_CLIENT_SECRET=client-secret');

        $transAuthFactory = new TransAuthenticatorFactory();

        try {
            $transAuthFactory->getAuthenticator(
                new GuzzleClientFactory(new NullLogger()),
                'https://vault.azure.net',
            );
            self::assertTrue(true);
        } catch (TransClientNotAvailableException) {
            self::fail('Test should not have thrown an exception');
        }
    }

    public static function provideInvalidTransEnvs(): iterable
    {
        yield 'missing all' => [
            [],
        ];

        yield 'missing TRANS_AZURE_TENANT_ID' => [
            [
                'TRANS_AZURE_TENANT_ID' => '',
                'TRANS_AZURE_CLIENT_ID' => 'client-id',
                'TRANS_AZURE_CLIENT_SECRET' => 'client-secret',
            ],
        ];

        yield 'missing TRANS_AZURE_CLIENT_ID' => [
            [
                'TRANS_AZURE_TENANT_ID' => 'tenant-id',
                'TRANS_AZURE_CLIENT_ID' => '',
                'TRANS_AZURE_CLIENT_SECRET' => 'client-secret',
            ],
        ];

        yield 'missing TRANS_AZURE_CLIENT_SECRET' => [
            [
                'TRANS_AZURE_TENANT_ID' => 'tenant-id',
                'TRANS_AZURE_CLIENT_ID' => 'client-id',
                'TRANS_AZURE_CLIENT_SECRET' => '',
            ],
        ];
    }

    /** @dataProvider provideInvalidTransEnvs */
    public function testTransAuthenticatorIsUnavailable(array $invalidEnvs): void
    {
        foreach ($invalidEnvs as $name => $value) {
            putenv(sprintf('%s=%s', $name, $value));
        }

        $transAuthFactory = new TransAuthenticatorFactory();

        $this->expectException(TransClientNotAvailableException::class);

        $transAuthFactory->getAuthenticator(
            new GuzzleClientFactory(new NullLogger()),
            'https://vault.azure.net',
        );
    }
}
