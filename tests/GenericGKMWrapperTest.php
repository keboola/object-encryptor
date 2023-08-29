<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Google\ApiCore\ApiException;
use Google\ApiCore\ApiStatus;
use Google\ApiCore\RetrySettings;
use Google\Cloud\Kms\V1\KeyManagementServiceClient;
use Google\Cloud\Kms\V1\KeyRing;
use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\GenericGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\GkmsClientFactory;
use Keboola\ObjectEncryptor\Wrapper\KmsClientFactory;
use Retry\BackOff\ExponentialBackOffPolicy;
use Retry\Policy\SimpleRetryPolicy;
use Retry\RetryProxy;
use Throwable;

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
}
