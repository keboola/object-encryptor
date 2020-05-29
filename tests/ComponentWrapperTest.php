<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\ComponentWrapper;
use PHPUnit\Framework\TestCase;

class ComponentWrapperTest extends TestCase
{
    public function setUp()
    {
        parent::setUp();
        putenv('AWS_ACCESS_KEY_ID=' . AWS_ACCESS_KEY_ID);
        putenv('AWS_SECRET_ACCESS_KEY='. AWS_SECRET_ACCESS_KEY);
    }

    /**
     * @return ComponentWrapper
     */
    private function getComponentWrapper()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        return $wrapper;
    }

    public function testEncrypt()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getComponentWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getComponentWrapper();
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptDifferentStack()
    {
        $wrapper = $this->getComponentWrapper();
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getComponentWrapper();
        $wrapper->setStackId('some-other-stack');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Invalid metadata.');
        $wrapper->decrypt($encrypted);
    }

    public function testEncryptDifferentComponent()
    {
        $wrapper = $this->getComponentWrapper();
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getComponentWrapper();
        $wrapper->setComponentId('some-other-component');
        self::expectException(UserException::class);
        self::expectExceptionMessage('Invalid metadata.');
        $wrapper->decrypt($encrypted);
    }

    public function testInvalidSetupEncrypt1()
    {
        $wrapper = new ComponentWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupEncrypt2()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupEncrypt3()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('component-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupEncrypt4()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('stack-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidSetupDecrypt1()
    {
        $wrapper = new ComponentWrapper();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Cipher key settings are missing.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidSetupDecrypt2()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidSetupDecrypt3()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('component-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidSetupDecrypt4()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('stack-id');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('No stack or component id provided.');
        $wrapper->decrypt('mySecretValue');
    }

    public function testInvalidComponent()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId(new \stdClass());
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Component id is invalid.');
        $wrapper->encrypt('mySecretValue');
    }

    public function testInvalidStack()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setStackId(new \stdClass());
        $wrapper->setComponentId('dummy-component');
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Stack id is invalid.');
        $wrapper->encrypt('mySecretValue');
    }
}
