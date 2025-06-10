<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests\Temporary;

use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Temporary\TransClient;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeProjectWideAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectWideAKVWrapper;
use PHPUnit\Framework\TestCase;

class AKVWrappersWithTransClientTest extends TestCase
{
    public function setUp(): void
    {
        parent::setUp();

        putenv('TRANS_AZURE_TENANT_ID=');
        putenv('TRANS_AZURE_CLIENT_ID=');
        putenv('TRANS_AZURE_CLIENT_SECRET=');
    }

    public static function provideAKVWrappers(): iterable
    {
        $classes = [
            GenericAKVWrapper::class,
            ComponentAKVWrapper::class,
            ProjectAKVWrapper::class,
            ConfigurationAKVWrapper::class,
            ProjectWideAKVWrapper::class,
            BranchTypeProjectAKVWrapper::class,
            BranchTypeProjectWideAKVWrapper::class,
            BranchTypeConfigurationAKVWrapper::class,
        ];

        foreach ($classes as $className) {
            yield $className => [
                'wrapperClass' => $className,
            ];
        }
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
}
