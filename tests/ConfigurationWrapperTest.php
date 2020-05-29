<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationWrapper;
use PHPUnit\Framework\TestCase;

class ConfigurationWrapperTest extends TestCase
{
    public function setUp()
    {
        parent::setUp();
        putenv('AWS_ACCESS_KEY_ID=' . AWS_ACCESS_KEY_ID);
        putenv('AWS_SECRET_ACCESS_KEY='. AWS_SECRET_ACCESS_KEY);
    }

    /**
     * @return ConfigurationWrapper
     */
    private function getConfigurationWrapper()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setConfigurationId('my-configuration');
        $wrapper->setProjectId('my-project');
        return $wrapper;
    }

    public function testEncrypt()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getConfigurationWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getConfigurationWrapper();
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptDifferentConfiguration()
    {
        $wrapper = $this->getConfigurationWrapper();
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getConfigurationWrapper();
        $wrapper->setConfigurationId('some-other-configuration');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Invalid metadata.');
        $wrapper->decrypt($encrypted);
    }

    public function testEncryptDifferentProject()
    {
        $wrapper = $this->getConfigurationWrapper();
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getConfigurationWrapper();
        $wrapper->setProjectId('some-other-project');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Invalid metadata.');
        $wrapper->decrypt($encrypted);
    }

    public function testInvalidSetupEncrypt1()
    {
        $wrapper = new ConfigurationWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupEncrypt2()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupEncrypt3()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('component-id');
        $wrapper->setStackId('my-stack');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No project id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupEncrypt4()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('component-id');
        $wrapper->setStackId('my-stack');
        $wrapper->setProjectId('my-project');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No configuration id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupDecrypt1()
    {
        $wrapper = new ConfigurationWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidSetupDecrypt2()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidSetupDecrypt3()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('component-id');
        $wrapper->setStackId('my-stack');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No project id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidSetupDecrypt4()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('component-id');
        $wrapper->setStackId('my-stack');
        $wrapper->setProjectId('my-project');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No configuration id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidConfiguration()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('my-component');
        $wrapper->setProjectId('my-project');
        $wrapper->setConfigurationId(new \stdClass());
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Configuration id is invalid.');
        $wrapper->encrypt('mySecretValue');
    }
}
