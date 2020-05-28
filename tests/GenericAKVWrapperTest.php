<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Wrapper\GenericAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class GenericAKVWrapperTest extends TestCase
{
    public function setUp()
    {
        parent::setUp();
        $envs = ['TEST_TENANT_ID', 'TEST_CLIENT_ID', 'TEST_CLIENT_SECRET',
            'TEST_KEY_VAULT_URL', 'TEST_KEY_NAME', 'TEST_KEY_VERSION'];
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
        $wrapper->setKeyName(getenv('TEST_KEY_NAME'));
        $wrapper->setKeyVersion(getenv('TEST_KEY_VERSION'));
        return $wrapper;
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

    public function testEncryptWrongKey()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        // This is ok, because KMS key is found automatically during decryption
        $wrapper->setKMSKeyId('non-existent');
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptEmptyValue1()
    {
        $secret = '';
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptEmptyValue2()
    {
        $secret = '0';
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptEmptyValue3()
    {
        $secret = null;
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }
}
