<?php

namespace Keboola\ObjectEncryptor\Tests;

use Aws\CommandInterface;
use Aws\Kms\KmsClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;
use PHPUnit\Framework\TestCase;

class GenericKMSWrapperTest extends TestCase
{
    public function setUp()
    {
        parent::setUp();
        putenv('AWS_ACCESS_KEY_ID=' . AWS_ACCESS_KEY_ID);
        putenv('AWS_SECRET_ACCESS_KEY='. AWS_SECRET_ACCESS_KEY);
    }

    /**
     * @return GenericKMSWrapper
     */
    private function getWrapper()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        return $wrapper;
    }

    public function testEncrypt()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
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

    public function testRetryEncrypt()
    {
        $mockKmsClient = self::getMockBuilder(KmsClient::class)
            // Need to pass service explicitly, because AwsClient fails to detect it from mock
            ->setConstructorArgs([['region' => AWS_DEFAULT_REGION, 'version' => '2014-11-01', 'service' => 'kms']])
            ->setMethods(['execute'])
            ->getMock();
        $callNo = 0;
        $mockKmsClient->method('execute')
            ->willReturnCallback(function (CommandInterface $command) use (&$callNo, $mockKmsClient) {
                $callNo++;
                if ($callNo < 3) {
                    throw new ConnectException('mock failed to connect', new Request('GET', 'some-uri'));
                } else {
                    /** @var KmsClient $mockKmsClient */
                    return $mockKmsClient->executeAsync($command)->wait();
                }
            });

        /** @var \PHPUnit_Framework_MockObject_MockObject $mockWrapper */
        $mockWrapper = self::getMockBuilder(GenericKMSWrapper::class)
            ->setMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')
            ->willReturn($mockKmsClient);

        $secret = 'secret';
        /** @var GenericKMSWrapper $mockWrapper */
        $mockWrapper->setKMSKeyId(KMS_TEST_KEY);
        $mockWrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $encrypted = $mockWrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $mockWrapper->decrypt($encrypted));
    }

    public function testRetryEncryptFail()
    {
        $mockKmsClient = self::getMockBuilder(KmsClient::class)
            // Need to pass service explicitly, because AwsClient fails to detect it from mock
            ->setConstructorArgs([['region' => AWS_DEFAULT_REGION, 'version' => '2014-11-01', 'service' => 'kms']])
            ->setMethods(['execute'])
            ->getMock();
        $mockKmsClient->method('execute')
            ->willThrowException(
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri'))
            );

        /** @var \PHPUnit_Framework_MockObject_MockObject $mockWrapper */
        $mockWrapper = self::getMockBuilder(GenericKMSWrapper::class)
            ->setMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')
            ->willReturn($mockKmsClient);

        $secret = 'secret';
        /** @var GenericKMSWrapper $mockWrapper */
        $mockWrapper->setKMSKeyId(KMS_TEST_KEY);
        $mockWrapper->setKMSRegion(AWS_DEFAULT_REGION);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Ciphering failed: Failed to obtain encryption key.');
        $mockWrapper->encrypt($secret);
    }

    public function testRetryDecrypt()
    {
        $mockKmsClient = self::getMockBuilder(KmsClient::class)
            // Need to pass service explicitly, because AwsClient fails to detect it from mock
            ->setConstructorArgs([['region' => AWS_DEFAULT_REGION, 'version' => '2014-11-01', 'service' => 'kms']])
            ->setMethods(['execute'])
            ->getMock();
        $mockKmsClient->method('execute')
            ->willReturnCallback(function (CommandInterface $command) use (&$callNo, $mockKmsClient) {
                $callNo++;
                if ($callNo < 3) {
                    throw new ConnectException('mock failed to connect', new Request('GET', 'some-uri'));
                } else {
                    /** @var KmsClient $mockKmsClient */
                    return $mockKmsClient->executeAsync($command)->wait();
                }
            });

        /** @var \PHPUnit_Framework_MockObject_MockObject $mockWrapper */
        $mockWrapper = self::getMockBuilder(GenericKMSWrapper::class)
            ->setMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')
            ->willReturn($mockKmsClient);

        $secret = 'secret';
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        /** @var GenericKMSWrapper $mockWrapper */
        $mockWrapper->setKMSKeyId(KMS_TEST_KEY);
        $mockWrapper->setKMSRegion(AWS_DEFAULT_REGION);
        self::assertEquals($secret, $mockWrapper->decrypt($encrypted));
    }

    public function testRetryDecryptFail()
    {
        $mockKmsClient = self::getMockBuilder(KmsClient::class)
            // Need to pass service explicitly, because AwsClient fails to detect it from mock
            ->setConstructorArgs([['region' => AWS_DEFAULT_REGION, 'version' => '2014-11-01', 'service' => 'kms']])
            ->setMethods(['execute'])
            ->getMock();
        $mockKmsClient->method('execute')
            ->willThrowException(
                new ConnectException('mock failed to connect', new Request('GET', 'some-uri'))
            );

        /** @var \PHPUnit_Framework_MockObject_MockObject $mockWrapper */
        $mockWrapper = self::getMockBuilder(GenericKMSWrapper::class)
            ->setMethods(['getClient'])
            ->getMock();
        $mockWrapper->method('getClient')
            ->willReturn($mockKmsClient);

        $secret = 'secret';
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        /** @var GenericKMSWrapper $mockWrapper */
        $mockWrapper->setKMSKeyId(KMS_TEST_KEY);
        $mockWrapper->setKMSRegion(AWS_DEFAULT_REGION);
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Deciphering failed.');
        $mockWrapper->decrypt($encrypted);
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Cannot encrypt a non-scalar value
     */
    public function testEncryptNonScalar()
    {
        $secret = ['a' => 'b'];
        $wrapper = $this->getWrapper();
        /** @noinspection PhpParamsInspection */
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptMetadata()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    public function testEncryptMetadataCacheHit()
    {
        $secret1 = 'mySecretValue1';
        $secret2 = 'mySecretValue2';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $encrypted1 = $wrapper->encrypt($secret1);
        self::assertNotEquals($secret1, $encrypted1);
        self::assertEquals($secret1, $wrapper->decrypt($encrypted1));
        $encrypted2 = $wrapper->encrypt($secret2);
        self::assertNotEquals($secret2, $encrypted2);
        self::assertEquals($secret2, $wrapper->decrypt($encrypted2));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $wrapper->decrypt($encrypted1);
        self::assertEquals($secret1, $wrapper->decrypt($encrypted1));
        $wrapper->decrypt($encrypted2);
        self::assertEquals($secret2, $wrapper->decrypt($encrypted2));
    }

    public function testEncryptMetadataCacheMiss()
    {
        $secret1 = 'mySecretValue1';
        $secret2 = 'mySecretValue2';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key1', 'value1');
        $encrypted1 = $wrapper->encrypt($secret1);
        self::assertNotEquals($secret1, $encrypted1);
        self::assertEquals($secret1, $wrapper->decrypt($encrypted1));
        $wrapper->setMetadataValue('key2', 'value2');
        $encrypted2 = $wrapper->encrypt($secret2);
        self::assertNotEquals($secret2, $encrypted2);
        self::assertEquals($secret2, $wrapper->decrypt($encrypted2));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key1', 'value1');
        $wrapper->decrypt($encrypted1);
        self::assertEquals($secret1, $wrapper->decrypt($encrypted1));
        $wrapper->setMetadataValue('key2', 'value2');
        $wrapper->decrypt($encrypted2);
        self::assertEquals($secret2, $wrapper->decrypt($encrypted2));
    }
    /**
     *
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid metadata.
     */
    public function testEncryptMetadataMismatch1()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid metadata.
     */
    public function testEncryptMetadataMismatch2()
    {
        $secret = 'mySecretValue';
        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value');
        $encrypted = $wrapper->encrypt($secret);
        self::assertNotEquals($secret, $encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));

        $wrapper = $this->getWrapper();
        $wrapper->setMetadataValue('key', 'value-bad');
        $wrapper->decrypt($encrypted);
        self::assertEquals($secret, $wrapper->decrypt($encrypted));
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher key settings are missing.
     */
    public function testInvalidSetupEncrypt1()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher key settings are missing.
     */
    public function testInvalidSetupEncrypt2()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSRegion('my-region');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher key settings are missing.
     */
    public function testInvalidSetupEncrypt3()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId('my-key');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher key settings are missing.
     */
    public function testInvalidSetupDecrypt1()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher key settings are missing.
     */
    public function testInvalidSetupDecrypt2()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSRegion('my-region');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher key settings are missing.
     */
    public function testInvalidSetupDecrypt3()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId('my-key');
        $wrapper->decrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher key settings are invalid.
     */
    public function testInvalidValue1()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId(new \stdClass());
        $wrapper->setKMSRegion('my-region');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Cipher key settings are invalid.
     */
    public function testInvalidValue2()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId('my-key');
        /** @noinspection PhpParamsInspection */
        $wrapper->setKMSRegion(['a' => 'b']);
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Ciphering failed: Failed to obtain encryption key.
     */
    public function testInvalidKeys1()
    {
        putenv('AWS_ACCESS_KEY_ID=' . AWS_ACCESS_KEY_ID);
        putenv('AWS_SECRET_ACCESS_KEY=some-garbage');
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setKMSRegion(AWS_DEFAULT_REGION);
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException \Keboola\ObjectEncryptor\Exception\ApplicationException
     * @expectedExceptionMessage Ciphering failed: Failed to obtain encryption key.
     */
    public function testInvalidKeys2()
    {
        $wrapper = new GenericKMSWrapper();
        $wrapper->setKMSKeyId(KMS_TEST_KEY);
        $wrapper->setKMSRegion('non-existent');
        $wrapper->encrypt('mySecretValue');
    }

    /**
     * @expectedException  \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Cipher is malformed
     */
    public function testDecryptInvalid1()
    {
        $wrapper = $this->getWrapper();
        $wrapper->decrypt("some garbage");
    }

    /**
     * @expectedException  \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Cipher is malformed
     */
    public function testDecryptInvalid2()
    {
        $wrapper = $this->getWrapper();
        $wrapper->decrypt(base64_encode("some garbage"));
    }

    /**
     * @expectedException  \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Cipher is malformed
     */
    public function testDecryptInvalid3()
    {
        $wrapper = $this->getWrapper();
        $wrapper->decrypt(base64_encode(gzcompress("some garbage")));
    }

    /**
     * @expectedException  \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Cipher is malformed
     */
    public function testDecryptInvalid4()
    {
        $wrapper = $this->getWrapper();
        $wrapper->decrypt(base64_encode(gzcompress(serialize("some garbage"))));
    }

    /**
     * @expectedException  \Keboola\ObjectEncryptor\Exception\UserException
     * @expectedExceptionMessage Invalid metadata
     */
    public function testDecryptInvalid5()
    {
        $wrapper = $this->getWrapper();
        $wrapper->decrypt(base64_encode(gzcompress(serialize(["some", "garbage"]))));
    }
}
