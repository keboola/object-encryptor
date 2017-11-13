<?php

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\ObjectEncryptor;
use PHPUnit\Framework\TestCase;

class ObjectEncryptorTest extends TestCase
{

    public function testEncryptorScalar()
    {
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

        $originalText = 'secret';
        $encrypted = $encryptor->encrypt($originalText);
        $this->assertEquals("KBC::Encrypted==", substr($encrypted, 0, 16));
        $this->assertEquals($originalText, $encryptor->decrypt($encrypted));
    }

    public function testEncryptorInvalidService()
    {
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');
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

        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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

        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

        $encryptedValue = $encryptor->encrypt("test");

        $encrypted = $encryptor->encrypt($encryptedValue);
        $this->assertEquals("KBC::Encrypted==", substr($encrypted, 0, 16));
        $this->assertEquals("test", $encryptor->decrypt($encrypted));
    }

    public function testEncryptorAlreadyEncryptedWrapper()
    {
        $client = static::createClient();

        /** @var ObjectEncryptor $encryptor */
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');
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
        $client = static::createClient();

        /** @var ObjectEncryptor $encryptor */
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');
        $wrapper = new MockCryptoWrapper();
        $client->getContainer()->set('mock.crypto.wrapper', $wrapper);
        $encryptor->pushWrapper($wrapper);
        try {
            $encryptor->pushWrapper($wrapper);
            $this->fail("Adding crypto wrapper with same prefix must fail.");
        } catch (ApplicationException $e) {
        }
    }

    public function testEncryptorSimpleArray()
    {
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');


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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');


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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        /**
         * @var $encryptor ObjectEncryptor
         */
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');
        $wrapper = new AnotherCryptoWrapper(md5(uniqid()));
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
        $client = static::createClient();
        /** @var ObjectEncryptor $encryptor */
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');
        $wrapper = new AnotherCryptoWrapper(md5(uniqid()));
        $client->getContainer()->set('another.crypto.wrapper', $wrapper);
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
        $client = static::createClient();
        /**
         * @var $encryptor ObjectEncryptor
         */
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');
        $array = [];
        $encrypted = $encryptor->encrypt($array);
        $this->assertEquals([], $encrypted);
        $this->assertEquals([], $encryptor->decrypt($encrypted));
    }

    public function testEncryptEmptyObject()
    {
        $client = static::createClient();
        /**
         * @var $encryptor ObjectEncryptor
         */
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');
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
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

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
        $client = static::createClient();
        $legacyEncryptor = $client->getContainer()->get('syrup.encryptor');
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

        $originalText = 'secret';
        $encrypted = $legacyEncryptor->encrypt($originalText);
        $this->assertNotEquals($originalText, $encrypted);
        $this->assertEquals($originalText, $encryptor->decrypt($encrypted));
    }

    public function testEncryptorLegacyFail()
    {
        $client = static::createClient();
        $encryptor = $client->getContainer()->get('syrup.object_encryptor');

        $originalText = 'test';
        try {
            $encryptor->decrypt($originalText);
            $this->fail("Invalid cipher must fail.");
        } catch (UserException $e) {
            $this->assertContains('is not an encrypted value', $e->getMessage());
        }
    }
}
