<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Wrapper\ConfigurationWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectWrapper;
use PHPUnit\Framework\TestCase;

class ProjectWrapperTest extends TestCase
{
    public function setUp()
    {
        parent::setUp();
        putenv('AWS_ACCESS_KEY_ID=' . AWS_ACCESS_KEY_ID);
        putenv('AWS_SECRET_ACCESS_KEY='. AWS_SECRET_ACCESS_KEY);
    }

    /**
     * @return ProjectWrapper
     */
    private function getProjectWrapper()
    {
        $wrapper = new ProjectWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('dummy-component');
        $wrapper->setProjectId('my-project');
        return $wrapper;
    }

    public function testEncrypt()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getProjectWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getProjectWrapper();
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid metadata.
     */
    public function testEncryptDifferentConfiguration()
    {
        $wrapper = $this->getProjectWrapper();
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getProjectWrapper();
        $wrapper->setProjectId('some-other-project');
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid metadata.
     */
    public function testEncryptDifferentComponent()
    {
        $wrapper = $this->getProjectWrapper();
        $secret = 'mySecretValue';
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getProjectWrapper();
        $wrapper->setComponentId('some-other-component');
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher key settings are missing.
     */
    public function testInvalidSetupEncrypt1()
    {
        $wrapper = new ProjectWrapper();
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage No stack or component id provided.
     */
    public function testInvalidSetupEncrypt2()
    {
        $wrapper = new ConfigurationWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage No project id provided.
     */
    public function testInvalidSetupEncrypt3()
    {
        $wrapper = new ProjectWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('component-id');
        $wrapper->setStackId('my-stack');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher key settings are missing.
     */
    public function testInvalidSetupDecrypt1()
    {
        $wrapper = new ProjectWrapper();
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage No stack or component id provided.
     */
    public function testInvalidSetupDecrypt2()
    {
        $wrapper = new ProjectWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage No project id provided.
     */
    public function testInvalidSetupDecrypt3()
    {
        $wrapper = new ProjectWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setComponentId('component-id');
        $wrapper->setStackId('my-stack');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Project id is invalid.
     */
    public function testInvalidConfiguration()
    {
        $wrapper = new ProjectWrapper();
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setStackId('my-stack');
        $wrapper->setComponentId('my-component');
        $wrapper->setProjectId(new \stdClass());
        $wrapper->encrypt('mySecretValue');
    }
}
