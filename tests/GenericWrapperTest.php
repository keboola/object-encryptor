<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;
use PHPUnit\Framework\TestCase;

class GenericWrapperTest extends TestCase
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
}
