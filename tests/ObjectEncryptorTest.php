<?php

namespace Keboola\ObjectEncryptor\Tests;

use Defuse\Crypto\Key;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Legacy\Encryptor;
use Keboola\ObjectEncryptor\ObjectEncryptor;
use Keboola\ObjectEncryptor\ObjectEncryptorFactory;
use Keboola\ObjectEncryptor\Wrapper\StackWrapper;
use PHPUnit\Framework\TestCase;

class ObjectEncryptorTest extends TestCase
{
    /**
     * @var ObjectEncryptorFactory
     */
    private $factory;

    /**
     * @var string
     */
    private $aesKey;

    public function setUp()
    {
        $globalKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $stackKey = Key::createNewRandomKey()->saveToAsciiSafeString();
        $legacyKey = '1234567890123456';
        $this->aesKey = '123456789012345678901234567890ab';
        $stack = 'us-east-1';
        $componentId = 'keboola.docker-demo';
        $configurationId = '123456';
        $projectId = '123';
        $this->factory = new ObjectEncryptorFactory($globalKey, $legacyKey, $this->aesKey, $stackKey, $stack, $projectId, $componentId, $configurationId);
    }

    public function testEncryptorScalar()
    {
        $encryptor = $this->factory->getEncryptor();
        $originalText = 'secret';
        $encrypted = $encryptor->encrypt($originalText);
        self::assertStringStartsWith("KBC::Encrypted==", $encrypted);
        self::assertEquals($originalText, $encryptor->decrypt($encrypted));
    }

    public function testEncryptorStack()
    {
        $encryptor = $this->factory->getEncryptor();
        $originalText = 'secret';
        $encrypted = $encryptor->encrypt($originalText, StackWrapper::class);
        self::assertStringStartsWith("KBC::SecureV3::CPF::", $encrypted);
        self::assertEquals($originalText, $encryptor->decrypt($encrypted));
    }

    public function testEncryptorInvalidService()
    {
        $encryptor = $this->factory->getEncryptor();
        try {
            $encryptor->encrypt('secret', 'fooBar');
            $this->fail("Invalid crypto wrapper must throw exception");
        } catch (ApplicationException $e) {
        }
    }


    public function testEncryptorUnsupportedInput()
    {
        $invalidClass = $this->getMockBuilder('stdClass')
             ->disableOriginalConstructor()
             ->getMock();
        $encryptor = $this->factory->getEncryptor();

        $unsupportedInput = $invalidClass;
        try {
            $encryptor->encrypt($unsupportedInput);
            $this->fail("Encryption of invalid data should fail.");
        } catch (ApplicationException $e) {
        }

        $unsupportedInput = [
            'key' => 'value',
            'key2' => $invalidClass
        ];
        try {
            $encryptor->encrypt($unsupportedInput);
            $this->fail("Encryption of invalid data should fail.");
        } catch (ApplicationException $e) {
        }

        $unsupportedInput = [
            'key' => 'value',
            '#key2' => $invalidClass,
        ];
        try {
            $encryptor->encrypt($unsupportedInput);
            $this->fail("Encryption of invalid data should fail.");
        } catch (ApplicationException $e) {
        }
    }

    public function testDecryptorUnsupportedInput()
    {
        $invalidClass = $this->getMockBuilder('stdClass')
             ->disableOriginalConstructor()
             ->getMock();
        $encryptor = $this->factory->getEncryptor();

        $unsupportedInput = $invalidClass;
        try {
            $encryptor->decrypt($unsupportedInput);
            $this->fail("Encryption of invalid data should fail.");
        } catch (ApplicationException $e) {
        }

        $unsupportedInput = [
            'key' => 'value',
            'key2' => $invalidClass,
        ];
        try {
            $encryptor->decrypt($unsupportedInput);
            $this->fail("Encryption of invalid data should fail.");
        } catch (ApplicationException $e) {
        }

        $unsupportedInput = [
            'key' => 'value',
            '#key2' => $invalidClass,
        ];
        try {
            $encryptor->decrypt($unsupportedInput);
            $this->fail("Encryption of invalid data should fail.");
        } catch (ApplicationException $e) {
        }
    }

    public function testDecryptorInvalidCipherText()
    {
        $encryptor = $this->factory->getEncryptor();
        $encrypted = 'KBC::Encrypted==yI0sawothis is not a valid cipher but it looks like one N2Jg==';
        try {
            $this->assertEquals($encrypted, $encryptor->decrypt($encrypted));
            $this->fail("Invalid cipher text must raise exception");
        } catch (UserException $e) {
            $this->assertContains('KBC::Encrypted==yI0sawothis', $e->getMessage());
        }
    }


    public function testDecryptorInvalidCipherText2()
    {
        $encryptor = $this->factory->getEncryptor();
        $encrypted = 'this does not even look like a cipher text';
        try {
            $this->assertEquals($encrypted, $encryptor->decrypt($encrypted));
            $this->fail("Invalid cipher text must raise exception");
        } catch (UserException $e) {
            $this->assertNotContains('this does not even look like a cipher text', $e->getMessage());
        }
    }


    public function testDecryptorInvalidCipherStructure()
    {
        $encryptor = $this->factory->getEncryptor();
        $encrypted = [
            'key1' => 'somevalue',
            'key2' => [
                '#anotherKey' => 'KBC::Encrypted==yI0sawothis is not a valid cipher but it looks like one N2Jg=='
            ]
        ];
        try {
            $this->assertEquals($encrypted, $encryptor->decrypt($encrypted));
            $this->fail("Invalid cipher text must raise exception");
        } catch (UserException $e) {
            $this->assertContains('KBC::Encrypted==yI0sawothis', $e->getMessage());
            $this->assertContains('#anotherKey', $e->getMessage());
        }
    }


    public function testDecryptorInvalidCipherStructure2()
    {
        $encryptor = $this->factory->getEncryptor();
        $encrypted = [
            'key1' => 'somevalue',
            'key2' => [
                '#anotherKey' => 'this does not even look like a cipher text'
            ]
        ];
        try {
            $this->assertEquals($encrypted, $encryptor->decrypt($encrypted));
            $this->fail("Invalid cipher text must raise exception");
        } catch (UserException $e) {
            $this->assertNotContains('this does not even look like a cipher text', $e->getMessage());
            $this->assertContains('#anotherKey', $e->getMessage());
        }
    }


    public function testEncryptorAlreadyEncrypted()
    {
        $encryptor = $this->factory->getEncryptor();
        $encryptedValue = $encryptor->encrypt("test");

        $encrypted = $encryptor->encrypt($encryptedValue);
        $this->assertEquals("KBC::Encrypted==", substr($encrypted, 0, 16));
        $this->assertEquals("test", $encryptor->decrypt($encrypted));
    }

    public function testEncryptorAlreadyEncryptedWrapper()
    {
        $encryptor = $this->factory->getEncryptor();
        $wrapper = new MockCryptoWrapper();
        $encryptor->pushWrapper($wrapper);

        $secret = 'secret';
        $encryptedValue = $encryptor->encrypt($secret, MockCryptoWrapper::class);
        $this->assertEquals("KBC::MockCryptoWrapper==" . $secret, $encryptedValue);

        $encryptedSecond = $encryptor->encrypt($encryptedValue);
        $this->assertEquals("KBC::MockCryptoWrapper==" . $secret, $encryptedSecond);
        $this->assertEquals($secret, $encryptor->decrypt($encryptedSecond));
    }

    public function testInvalidWrapper()
    {
        $encryptor = $this->factory->getEncryptor();
        $wrapper = new MockCryptoWrapper();
        $encryptor->pushWrapper($wrapper);
        try {
            $encryptor->pushWrapper($wrapper);
            $this->fail("Adding crypto wrapper with same prefix must fail.");
        } catch (ApplicationException $e) {
        }
    }

    public function testEncryptorSimpleArray()
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [
            "key1" => "value1",
            "#key2" => "value2"
        ];
        $result = $encryptor->encrypt($array);
        $this->assertArrayHasKey("key1", $result);
        $this->assertArrayHasKey("#key2", $result);
        $this->assertEquals("value1", $result["key1"]);
        $this->assertEquals("KBC::Encrypted==", substr($result["#key2"], 0, 16));

        $decrypted = $encryptor->decrypt($result);
        $this->assertArrayHasKey("key1", $decrypted);
        $this->assertArrayHasKey("#key2", $decrypted);
        $this->assertEquals("value1", $decrypted["key1"]);
        $this->assertEquals("value2", $decrypted["#key2"]);
    }

    public function testEncryptorSimpleObject()
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new \stdClass();
        $object->key1 = "value1";
        $object->{"#key2"} = "value2";

        $result = $encryptor->encrypt($object);
        $this->assertObjectHasAttribute("key1", $result);
        $this->assertObjectHasAttribute("#key2", $result);
        $this->assertEquals("value1", $result->key1);
        $this->assertEquals("KBC::Encrypted==", substr($result->{"#key2"}, 0, 16));

        $decrypted = $encryptor->decrypt($result);
        $this->assertObjectHasAttribute("key1", $decrypted);
        $this->assertObjectHasAttribute("#key2", $decrypted);
        $this->assertEquals("value1", $decrypted->key1);
        $this->assertEquals("value2", $decrypted->{"#key2"});
    }

    public function testEncryptorSimpleArrayScalars()
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [
            "key1" => "value1",
            "#key2" => "value2",
            "#key3" => true,
            "#key4" => 1,
            "#key5" => 1.5,
            "#key6" => null,
            "key7" => null
        ];
        $result = $encryptor->encrypt($array);
        $this->assertArrayHasKey("key1", $result);
        $this->assertArrayHasKey("#key2", $result);
        $this->assertEquals("value1", $result["key1"]);
        $this->assertEquals("KBC::Encrypted==", substr($result["#key2"], 0, 16));
        $this->assertEquals("KBC::Encrypted==", substr($result["#key3"], 0, 16));
        $this->assertEquals("KBC::Encrypted==", substr($result["#key4"], 0, 16));
        $this->assertEquals("KBC::Encrypted==", substr($result["#key5"], 0, 16));
        $this->assertEquals("KBC::Encrypted==", substr($result["#key6"], 0, 16));

        $decrypted = $encryptor->decrypt($result);
        $this->assertArrayHasKey("key1", $decrypted);
        $this->assertArrayHasKey("#key2", $decrypted);
        $this->assertEquals("value1", $decrypted["key1"]);
        $this->assertEquals("value2", $decrypted["#key2"]);
        $this->assertEquals(true, $decrypted["#key3"]);
        $this->assertEquals(1, $decrypted["#key4"]);
        $this->assertEquals(1.5, $decrypted["#key5"]);
        $this->assertEquals(null, $decrypted["#key6"]);
        $this->assertEquals(null, $decrypted["key7"]);
    }

    public function testEncryptorSimpleObjectScalars()
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new \stdClass();
        $object->key1= "value1";
        $object->{"#key2"} = "value2";
        $object->{"#key3"} = true;
        $object->{"#key4"} = 1;
        $object->{"#key5"} = 1.5;
        $object->{"#key6"} = null;
        $object->key7 = null;

        $result = $encryptor->encrypt($object);
        $this->assertObjectHasAttribute("key1", $result);
        $this->assertObjectHasAttribute("#key2", $result);
        $this->assertEquals("value1", $result->key1);
        $this->assertEquals("KBC::Encrypted==", substr($result->{"#key2"}, 0, 16));
        $this->assertEquals("KBC::Encrypted==", substr($result->{"#key3"}, 0, 16));
        $this->assertEquals("KBC::Encrypted==", substr($result->{"#key4"}, 0, 16));
        $this->assertEquals("KBC::Encrypted==", substr($result->{"#key5"}, 0, 16));
        $this->assertEquals("KBC::Encrypted==", substr($result->{"#key6"}, 0, 16));

        $decrypted = $encryptor->decrypt($result);
        $this->assertObjectHasAttribute("key1", $decrypted);
        $this->assertObjectHasAttribute("#key2", $decrypted);
        $this->assertEquals("value1", $decrypted->key1);
        $this->assertEquals("value2", $decrypted->{"#key2"});
        $this->assertEquals(true, $decrypted->{"#key3"});
        $this->assertEquals(1, $decrypted->{"#key4"});
        $this->assertEquals(1.5, $decrypted->{"#key5"});
        $this->assertEquals(null, $decrypted->{"#key6"});
        $this->assertEquals(null, $decrypted->{"key7"});
    }

    public function testEncryptorSimpleArrayEncrypted()
    {
        $encryptor = $this->factory->getEncryptor();
        $encryptedValue = $encryptor->encrypt("test");
        $array = [
            "key1" => "value1",
            "#key2" => $encryptedValue
        ];
        $result = $encryptor->encrypt($array);
        $this->assertArrayHasKey("key1", $result);
        $this->assertArrayHasKey("#key2", $result);
        $this->assertEquals("value1", $result["key1"]);
        $this->assertEquals($encryptedValue, $result["#key2"]);

        $decrypted = $encryptor->decrypt($result);
        $this->assertArrayHasKey("key1", $decrypted);
        $this->assertArrayHasKey("#key2", $decrypted);
        $this->assertEquals("value1", $decrypted["key1"]);
        $this->assertEquals("test", $decrypted["#key2"]);
    }

    public function testEncryptorSimpleObjectEncrypted()
    {
        $encryptor = $this->factory->getEncryptor();
        $encryptedValue = $encryptor->encrypt("test");
        $object = new \stdClass();
        $object->key1 = "value1";
        $object->{'#key2'} = $encryptedValue;

        $result = $encryptor->encrypt($object);
        $this->assertObjectHasAttribute("key1", $result);
        $this->assertObjectHasAttribute("#key2", $result);
        $this->assertEquals("value1", $result->key1);
        $this->assertEquals($encryptedValue, $result->{"#key2"});

        $decrypted = $encryptor->decrypt($result);
        $this->assertObjectHasAttribute("key1", $decrypted);
        $this->assertObjectHasAttribute("#key2", $decrypted);
        $this->assertEquals("value1", $decrypted->key1);
        $this->assertEquals("test", $decrypted->{"#key2"});
    }


    public function testEncryptorNestedArray()
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [
            "key1" => "value1",
            "key2" => [
                "nestedKey1" => "value2",
                "nestedKey2" => [
                    "#finalKey" => "value3"
                ]
            ]
        ];
        $result = $encryptor->encrypt($array);
        $this->assertArrayHasKey("key1", $result);
        $this->assertArrayHasKey("key2", $result);
        $this->assertArrayHasKey("nestedKey1", $result["key2"]);
        $this->assertArrayHasKey("nestedKey2", $result["key2"]);
        $this->assertArrayHasKey("#finalKey", $result["key2"]["nestedKey2"]);
        $this->assertEquals("value1", $result["key1"]);
        $this->assertEquals("value2", $result["key2"]["nestedKey1"]);
        $this->assertEquals("KBC::Encrypted==", substr($result["key2"]["nestedKey2"]["#finalKey"], 0, 16));

        $decrypted = $encryptor->decrypt($result);
        $this->assertArrayHasKey("key1", $decrypted);
        $this->assertArrayHasKey("key2", $decrypted);
        $this->assertArrayHasKey("nestedKey1", $decrypted["key2"]);
        $this->assertArrayHasKey("nestedKey2", $decrypted["key2"]);
        $this->assertArrayHasKey("#finalKey", $decrypted["key2"]["nestedKey2"]);
        $this->assertEquals("value1", $decrypted["key1"]);
        $this->assertEquals("value2", $decrypted["key2"]["nestedKey1"]);
        $this->assertEquals("value3", $decrypted["key2"]["nestedKey2"]["#finalKey"]);
    }

    public function testEncryptorNestedObject()
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new \stdClass();
        $nested1 = new \stdClass();
        $nested2 = new \stdClass();
        $nested2->{"#finalKey"} = "value3";
        $nested1->nestedKey1 = "value2";
        $nested1->nestedKey2 = $nested2;
        $object->key1 = "value1";
        $object->key2 = $nested1;

        $result = $encryptor->encrypt($object);
        $this->assertObjectHasAttribute("key1", $result);
        $this->assertObjectHasAttribute("key2", $result);
        $this->assertObjectHasAttribute("nestedKey1", $result->key2);
        $this->assertObjectHasAttribute("nestedKey2", $result->key2);
        $this->assertObjectHasAttribute("#finalKey", $result->key2->nestedKey2);
        $this->assertEquals("value1", $result->key1);
        $this->assertEquals("value2", $result->key2->nestedKey1);
        $this->assertEquals("KBC::Encrypted==", substr($result->key2->nestedKey2->{"#finalKey"}, 0, 16));

        $decrypted = $encryptor->decrypt($result);
        $this->assertObjectHasAttribute("key1", $decrypted);
        $this->assertObjectHasAttribute("key2", $decrypted);
        $this->assertObjectHasAttribute("nestedKey1", $decrypted->key2);
        $this->assertObjectHasAttribute("nestedKey2", $decrypted->key2);
        $this->assertObjectHasAttribute("#finalKey", $decrypted->key2->nestedKey2);
        $this->assertEquals("value1", $decrypted->key1);
        $this->assertEquals("value2", $decrypted->key2->nestedKey1);
        $this->assertEquals("value3", $decrypted->key2->nestedKey2->{"#finalKey"});
    }

    public function testEncryptorNestedArrayWithArrayKeyHashmark()
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [
            "key1" => "value1",
            "key2" => [
                "nestedKey1" => "value2",
                "nestedKey2" => [
                    "#finalKey" => "value3"
                ]
            ],
            "#key3" => [
                "anotherNestedKey" => "someValue",
                "#encryptedNestedKey" => "someValue2"
            ]
        ];
        $result = $encryptor->encrypt($array);
        $this->assertArrayHasKey("key1", $result);
        $this->assertArrayHasKey("key2", $result);
        $this->assertArrayHasKey("#key3", $result);
        $this->assertArrayHasKey("nestedKey1", $result["key2"]);
        $this->assertArrayHasKey("nestedKey2", $result["key2"]);
        $this->assertArrayHasKey("#finalKey", $result["key2"]["nestedKey2"]);
        $this->assertArrayHasKey("anotherNestedKey", $result["#key3"]);
        $this->assertEquals("value1", $result["key1"]);
        $this->assertEquals("value2", $result["key2"]["nestedKey1"]);
        $this->assertEquals("someValue", $result["#key3"]["anotherNestedKey"]);
        $this->assertEquals("KBC::Encrypted==", substr($result["#key3"]["#encryptedNestedKey"], 0, 16));
        $this->assertEquals("KBC::Encrypted==", substr($result["key2"]["nestedKey2"]["#finalKey"], 0, 16));

        $decrypted = $encryptor->decrypt($result);
        $this->assertArrayHasKey("key1", $decrypted);
        $this->assertArrayHasKey("key2", $decrypted);
        $this->assertArrayHasKey("#key3", $decrypted);
        $this->assertArrayHasKey("nestedKey1", $decrypted["key2"]);
        $this->assertArrayHasKey("nestedKey2", $decrypted["key2"]);
        $this->assertArrayHasKey("#finalKey", $decrypted["key2"]["nestedKey2"]);
        $this->assertEquals("value1", $decrypted["key1"]);
        $this->assertEquals("value2", $decrypted["key2"]["nestedKey1"]);
        $this->assertEquals("value3", $decrypted["key2"]["nestedKey2"]["#finalKey"]);
        $this->assertEquals("someValue", $decrypted["#key3"]["anotherNestedKey"]);
        $this->assertEquals("someValue2", $decrypted["#key3"]["#encryptedNestedKey"]);
    }


    public function testEncryptorNestedObjectWithArrayKeyHashmark()
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new \stdClass();
        $nested1 = new \stdClass();
        $nested2 = new \stdClass();
        $nested2->{"#finalKey"} = "value3";
        $nested1->nestedKey1 = "value2";
        $nested1->nestedKey2 = $nested2;
        $object->key1 = "value1";
        $object->key2 = $nested1;
        $nested3 = new \stdClass();
        $nested3->anotherNestedKey = "someValue";
        $nested3->{"#encryptedNestedKey"} = "someValue2";
        $object->{"#key3"} = $nested3;


        $result = $encryptor->encrypt($object);
        $this->assertObjectHasAttribute("key1", $result);
        $this->assertObjectHasAttribute("key2", $result);
        $this->assertObjectHasAttribute("#key3", $result);
        $this->assertObjectHasAttribute("nestedKey1", $result->key2);
        $this->assertObjectHasAttribute("nestedKey2", $result->key2);
        $this->assertObjectHasAttribute("#finalKey", $result->key2->nestedKey2);
        $this->assertObjectHasAttribute("anotherNestedKey", $result->{"#key3"});
        $this->assertEquals("value1", $result->key1);
        $this->assertEquals("value2", $result->key2->nestedKey1);
        $this->assertEquals("someValue", $result->{"#key3"}->anotherNestedKey);
        $this->assertEquals("KBC::Encrypted==", substr($result->{"#key3"}->{"#encryptedNestedKey"}, 0, 16));
        $this->assertEquals("KBC::Encrypted==", substr($result->key2->nestedKey2->{"#finalKey"}, 0, 16));

        $decrypted = $encryptor->decrypt($result);
        $this->assertObjectHasAttribute("key1", $decrypted);
        $this->assertObjectHasAttribute("key2", $decrypted);
        $this->assertObjectHasAttribute("#key3", $decrypted);
        $this->assertObjectHasAttribute("nestedKey1", $decrypted->key2);
        $this->assertObjectHasAttribute("nestedKey2", $decrypted->key2);
        $this->assertObjectHasAttribute("#finalKey", $decrypted->key2->nestedKey2);
        $this->assertEquals("value1", $decrypted->key1);
        $this->assertEquals("value2", $decrypted->key2->nestedKey1);
        $this->assertEquals("value3", $decrypted->key2->nestedKey2->{"#finalKey"});
        $this->assertEquals("someValue", $decrypted->{"#key3"}->anotherNestedKey);
        $this->assertEquals("someValue2", $decrypted->{"#key3"}->{"#encryptedNestedKey"});
    }

    public function testEncryptorNestedArrayEncrypted()
    {
        $encryptor = $this->factory->getEncryptor();
        $encryptedValue = $encryptor->encrypt("test");
        $array = [
            "key1" => "value1",
            "key2" => [
                "nestedKey1" => "value2",
                "nestedKey2" => [
                    "#finalKey" => "value3",
                    "#finalKeyEncrypted" => $encryptedValue
                ]
            ]
        ];

        $result = $encryptor->encrypt($array);
        $this->assertArrayHasKey("key1", $result);
        $this->assertArrayHasKey("key2", $result);
        $this->assertArrayHasKey("nestedKey1", $result["key2"]);
        $this->assertArrayHasKey("nestedKey2", $result["key2"]);
        $this->assertArrayHasKey("#finalKey", $result["key2"]["nestedKey2"]);
        $this->assertArrayHasKey("#finalKeyEncrypted", $result["key2"]["nestedKey2"]);
        $this->assertEquals("value1", $result["key1"]);
        $this->assertEquals("value2", $result["key2"]["nestedKey1"]);
        $this->assertEquals("KBC::Encrypted==", substr($result["key2"]["nestedKey2"]["#finalKey"], 0, 16));
        $this->assertEquals($encryptedValue, $result["key2"]["nestedKey2"]["#finalKeyEncrypted"]);

        $decrypted = $encryptor->decrypt($result);
        $this->assertArrayHasKey("key1", $decrypted);
        $this->assertArrayHasKey("key2", $decrypted);
        $this->assertArrayHasKey("nestedKey1", $decrypted["key2"]);
        $this->assertArrayHasKey("nestedKey2", $decrypted["key2"]);
        $this->assertArrayHasKey("#finalKey", $decrypted["key2"]["nestedKey2"]);
        $this->assertArrayHasKey("#finalKeyEncrypted", $decrypted["key2"]["nestedKey2"]);
        $this->assertEquals("value1", $decrypted["key1"]);
        $this->assertEquals("value2", $decrypted["key2"]["nestedKey1"]);
        $this->assertEquals("value3", $decrypted["key2"]["nestedKey2"]["#finalKey"]);
        $this->assertEquals("test", $decrypted["key2"]["nestedKey2"]["#finalKeyEncrypted"]);
    }


    public function testEncryptorNestedObjectEncrypted()
    {
        $encryptor = $this->factory->getEncryptor();
        $encryptedValue = $encryptor->encrypt("test");

        $object = new \stdClass();
        $object->key1 = "value1";
        $nested1 = new \stdClass();
        $nested1->nestedKey1 = "value2";
        $nested2 = new \stdClass();
        $nested2->{"#finalKey"} = "value3";
        $nested2->{"#finalKeyEncrypted"} = $encryptedValue;
        $nested1->nestedKey2 = $nested2;
        $object->key2 = $nested1;

        $result = $encryptor->encrypt($object);
        $this->assertObjectHasAttribute("key1", $result);
        $this->assertObjectHasAttribute("key2", $result);
        $this->assertObjectHasAttribute("nestedKey1", $result->key2);
        $this->assertObjectHasAttribute("nestedKey2", $result->key2);
        $this->assertObjectHasAttribute("#finalKey", $result->key2->nestedKey2);
        $this->assertObjectHasAttribute("#finalKeyEncrypted", $result->key2->nestedKey2);
        $this->assertEquals("value1", $result->key1);
        $this->assertEquals("value2", $result->key2->nestedKey1);
        $this->assertEquals("KBC::Encrypted==", substr($result->key2->nestedKey2->{"#finalKey"}, 0, 16));
        $this->assertEquals($encryptedValue, $result->key2->nestedKey2->{"#finalKeyEncrypted"});

        $decrypted = $encryptor->decrypt($result);
        $this->assertObjectHasAttribute("key1", $decrypted);
        $this->assertObjectHasAttribute("key2", $decrypted);
        $this->assertObjectHasAttribute("nestedKey1", $decrypted->key2);
        $this->assertObjectHasAttribute("nestedKey2", $decrypted->key2);
        $this->assertObjectHasAttribute("#finalKey", $decrypted->key2->nestedKey2);
        $this->assertObjectHasAttribute("#finalKeyEncrypted", $decrypted->key2->nestedKey2);
        $this->assertEquals("value1", $decrypted->key1);
        $this->assertEquals("value2", $decrypted->key2->nestedKey1);
        $this->assertEquals("value3", $decrypted->key2->nestedKey2->{"#finalKey"});
        $this->assertEquals("test", $decrypted->key2->nestedKey2->{"#finalKeyEncrypted"});
    }

    public function testEncryptorNestedArrayWithArray()
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [
            "key1" => "value1",
            "key2" => [
                ["nestedKey1" => "value2"],
                ["nestedKey2" => ["#finalKey" => "value3"]]
            ]
        ];
        $result = $encryptor->encrypt($array);
        $this->assertArrayHasKey("key1", $result);
        $this->assertArrayHasKey("key2", $result);
        $this->assertCount(2, $result["key2"]);
        $this->assertArrayHasKey("nestedKey1", $result["key2"][0]);
        $this->assertArrayHasKey("nestedKey2", $result["key2"][1]);
        $this->assertArrayHasKey("#finalKey", $result["key2"][1]["nestedKey2"]);
        $this->assertEquals("value1", $result["key1"]);
        $this->assertEquals("value2", $result["key2"][0]["nestedKey1"]);
        $this->assertEquals("KBC::Encrypted==", substr($result["key2"][1]["nestedKey2"]["#finalKey"], 0, 16));

        $decrypted = $encryptor->decrypt($result);
        $this->assertArrayHasKey("key1", $decrypted);
        $this->assertArrayHasKey("key2", $decrypted);
        $this->assertCount(2, $result["key2"]);
        $this->assertArrayHasKey("nestedKey1", $decrypted["key2"][0]);
        $this->assertArrayHasKey("nestedKey2", $decrypted["key2"][1]);
        $this->assertArrayHasKey("#finalKey", $decrypted["key2"][1]["nestedKey2"]);
        $this->assertEquals("value1", $decrypted["key1"]);
        $this->assertEquals("value2", $decrypted["key2"][0]["nestedKey1"]);
        $this->assertEquals("value3", $decrypted["key2"][1]["nestedKey2"]["#finalKey"]);
    }

    public function testEncryptorNestedObjectWithArray()
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new \stdClass();
        $object->key1 = "value1";
        $object->key2 = [];
        $nested1 = new \stdClass();
        $nested1->nestedKey1 = "value2";
        $object->key2[] = $nested1;
        $nested2 = new \stdClass();
        $nested3 = new \stdClass();
        $nested3->{"#finalKey"} = "value3";
        $nested2->nestedKey2 = $nested3;
        $object->key2[] = $nested2;

        $result = $encryptor->encrypt($object);

        $this->assertObjectHasAttribute("key1", $result);
        $this->assertObjectHasAttribute("key2", $result);
        $this->assertCount(2, $result->key2);
        $this->assertObjectHasAttribute("nestedKey1", $result->key2[0]);
        $this->assertObjectHasAttribute("nestedKey2", $result->key2[1]);
        $this->assertObjectHasAttribute("#finalKey", $result->key2[1]->nestedKey2);
        $this->assertEquals("value1", $result->key1);
        $this->assertEquals("value2", $result->key2[0]->nestedKey1);
        $this->assertEquals("KBC::Encrypted==", substr($result->key2[1]->nestedKey2->{"#finalKey"}, 0, 16));

        $decrypted = $encryptor->decrypt($result);
        $this->assertObjectHasAttribute("key1", $decrypted);
        $this->assertObjectHasAttribute("key2", $decrypted);
        $this->assertCount(2, $result->key2);
        $this->assertObjectHasAttribute("nestedKey1", $decrypted->key2[0]);
        $this->assertObjectHasAttribute("nestedKey2", $decrypted->key2[1]);
        $this->assertObjectHasAttribute("#finalKey", $decrypted->key2[1]->nestedKey2);
        $this->assertEquals("value1", $decrypted->key1);
        $this->assertEquals("value2", $decrypted->key2[0]->nestedKey1);
        $this->assertEquals("value3", $decrypted->key2[1]->nestedKey2->{"#finalKey"});
    }

    public function testMixedCryptoWrappersDecryptArray()
    {
        $encryptor = $this->factory->getEncryptor();
        $wrapper = new AnotherCryptoWrapper();
        $wrapper->setKey(md5(uniqid()));
        $encryptor->pushWrapper($wrapper);

        $array = [
            "#key1" => $encryptor->encrypt("value1"),
            "#key2" => $encryptor->encrypt("value2", AnotherCryptoWrapper::class)
        ];
        $this->assertEquals("KBC::Encrypted==", substr($array["#key1"], 0, 16));
        $this->assertEquals("KBC::AnotherCryptoWrapper==", substr($array["#key2"], 0, 27));

        $decrypted = $encryptor->decrypt($array);
        $this->assertArrayHasKey("#key1", $decrypted);
        $this->assertArrayHasKey("#key2", $decrypted);
        $this->assertCount(2, $decrypted);
        $this->assertEquals("value1", $decrypted["#key1"]);
        $this->assertEquals("value2", $decrypted["#key2"]);
    }

    public function testMixedCryptoWrappersDecryptObject()
    {
        $encryptor = $this->factory->getEncryptor();
        $wrapper = new AnotherCryptoWrapper();
        $wrapper->setKey(md5(uniqid()));
        $encryptor->pushWrapper($wrapper);

        $object = new \stdClass();
        $object->{"#key1"} = $encryptor->encrypt("value1");
        $object->{"#key2"} = $encryptor->encrypt("value2", AnotherCryptoWrapper::class);

        $this->assertEquals("KBC::Encrypted==", substr($object->{"#key1"}, 0, 16));
        $this->assertEquals("KBC::AnotherCryptoWrapper==", substr($object->{"#key2"}, 0, 27));

        $decrypted = $encryptor->decrypt($object);
        $this->assertObjectHasAttribute("#key1", $decrypted);
        $this->assertObjectHasAttribute("#key2", $decrypted);
        $this->assertEquals("value1", $decrypted->{"#key1"});
        $this->assertEquals("value2", $decrypted->{"#key2"});
    }

    public function testEncryptEmptyArray()
    {
        $encryptor = $this->factory->getEncryptor();
        $array = [];
        $encrypted = $encryptor->encrypt($array);
        $this->assertEquals([], $encrypted);
        $this->assertEquals([], $encryptor->decrypt($encrypted));
    }

    public function testEncryptEmptyObject()
    {
        $encryptor = $this->factory->getEncryptor();
        $object = new \stdClass();
        $encrypted = $encryptor->encrypt($object);
        $this->assertEquals('stdClass', get_class($encrypted));
        $this->assertEquals('stdClass', get_class($encryptor->decrypt($encrypted)));
    }

    public function testEncryptorNoWrappers()
    {
        $encryptor = new ObjectEncryptor();
        try {
            $encryptor->encrypt("test");
            $this->fail("Misconfigured object encryptor must raise exception.");
        } catch (ApplicationException $e) {
        }
    }

    public function testEncryptorDecodedJSONObject()
    {
        $encryptor = $this->factory->getEncryptor();
        $json = str_replace([" ", "\n"], ['', ''], '{
            "key1": "value1",
            "key2": {
                "nestedKey1": "value2",
                "nestedKey2": {
                    "#finalKey": "value3"
                }
            },
            "#key3": {
                "anotherNestedKey": "someValue",
                "#encryptedNestedKey": "someValue2"
            },
            "array": ["a", "b"],
            "emptyArray": [],
            "emptyObject": {}
        }');

        $result = $encryptor->encrypt(json_decode($json));
        $this->assertTrue(is_object($result));
        $this->assertObjectHasAttribute("key1", $result);
        $this->assertObjectHasAttribute("key2", $result);
        $this->assertObjectHasAttribute("#key3", $result);
        $this->assertObjectHasAttribute("array", $result);
        $this->assertObjectHasAttribute("emptyArray", $result);
        $this->assertObjectHasAttribute("emptyObject", $result);
        $this->assertObjectHasAttribute("nestedKey1", $result->key2);
        $this->assertObjectHasAttribute("nestedKey2", $result->key2);
        $this->assertObjectHasAttribute("#finalKey", $result->key2->nestedKey2);
        $this->assertTrue(is_array($result->array));
        $this->assertTrue(is_array($result->emptyArray));
        $this->assertTrue(is_object($result->emptyObject));
        $this->assertTrue(is_object($result->key2));
        $this->assertObjectHasAttribute("anotherNestedKey", $result->{"#key3"});
        $this->assertTrue(is_object($result->{"#key3"}));
        $this->assertEquals("value1", $result->key1);
        $this->assertEquals("value2", $result->key2->nestedKey1);
        $this->assertEquals("someValue", $result->{"#key3"}->anotherNestedKey);
        $this->assertEquals("KBC::Encrypted==", substr($result->{"#key3"}->{"#encryptedNestedKey"}, 0, 16));
        $this->assertEquals("KBC::Encrypted==", substr($result->key2->nestedKey2->{"#finalKey"}, 0, 16));

        $decrypted = $encryptor->decrypt($result);
        $this->assertTrue(is_object($decrypted));
        $this->assertObjectHasAttribute("key1", $decrypted);
        $this->assertObjectHasAttribute("key2", $decrypted);
        $this->assertObjectHasAttribute("#key3", $decrypted);
        $this->assertObjectHasAttribute("array", $decrypted);
        $this->assertObjectHasAttribute("emptyArray", $decrypted);
        $this->assertObjectHasAttribute("emptyObject", $decrypted);
        $this->assertObjectHasAttribute("nestedKey1", $decrypted->key2);
        $this->assertObjectHasAttribute("nestedKey2", $decrypted->key2);
        $this->assertObjectHasAttribute("#finalKey", $decrypted->key2->nestedKey2);
        $this->assertTrue(is_array($decrypted->array));
        $this->assertTrue(is_array($decrypted->emptyArray));
        $this->assertTrue(is_object($decrypted->emptyObject));
        $this->assertTrue(is_object($decrypted->key2));
        $this->assertObjectHasAttribute("anotherNestedKey", $decrypted->{"#key3"});
        $this->assertTrue(is_object($decrypted->{"#key3"}));
        $this->assertEquals("value1", $decrypted->key1);
        $this->assertEquals("value2", $decrypted->key2->nestedKey1);
        $this->assertEquals("someValue", $decrypted->{"#key3"}->anotherNestedKey);
        $this->assertEquals("someValue2", $decrypted->{"#key3"}->{"#encryptedNestedKey"});
        $this->assertEquals("value3", $decrypted->key2->nestedKey2->{"#finalKey"});

        $this->assertEquals(json_encode($decrypted), $json);
    }

    public function testEncryptorLegacy()
    {
        $encryptor = $this->factory->getEncryptor();
        $legacyEncryptor = new Encryptor($this->aesKey);

        $originalText = 'secret';
        $encrypted = $legacyEncryptor->encrypt($originalText);
        $this->assertNotEquals($originalText, $encrypted);
        $this->assertEquals($originalText, $encryptor->decrypt($encrypted));
    }

    public function testEncryptorLegacyFail()
    {
        $encryptor = $this->factory->getEncryptor();
        $originalText = 'test';
        try {
            $encryptor->decrypt($originalText);
            $this->fail("Invalid cipher must fail.");
        } catch (UserException $e) {
            $this->assertContains('is not an encrypted value', $e->getMessage());
        }
    }
}
