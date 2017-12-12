<?php

namespace Keboola\ObjectEncryptor\Tests;

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

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid metadata.
     */
    public function testEncryptDifferentStack()
    {
        $wrapper = $this->getComponentWrapper();
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getComponentWrapper();
        $wrapper->setStackId('some-other-stack');
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid metadata.
     */
    public function testEncryptDifferentComponent()
    {
        $wrapper = $this->getComponentWrapper();
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getComponentWrapper();
        $wrapper->setComponentId('some-other-component');
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher key settings are missing.
     */
    public function testInvalidSetupEncrypt1()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage No stack or component id provided.
     */
    public function testInvalidSetupEncrypt2()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage No stack or component id provided.
     */
    public function testInvalidSetupEncrypt3()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('component-id');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage No stack or component id provided.
     */
    public function testInvalidSetupEncrypt4()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('stack-id');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher key settings are missing.
     */
    public function testInvalidSetupDecrypt1()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage No stack or component id provided.
     */
    public function testInvalidSetupDecrypt2()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage No stack or component id provided.
     */
    public function testInvalidSetupDecrypt3()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('component-id');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage No stack or component id provided.
     */
    public function testInvalidSetupDecrypt4()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('stack-id');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Component id is invalid.
     */
    public function testInvalidComponent()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId(new \stdClass());
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Stack id is invalid.
     */
    public function testInvalidStack()
    {
        $wrapper = new ComponentWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setStackId(new \stdClass());
        $wrapper->setComponentId('dummy-component');
        $wrapper->encrypt('mySecretValue');
    }
}
