<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Generator;
use Keboola\ObjectEncryptor\EncryptorOptions;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\ObjectEncryptor;
use Keboola\ObjectEncryptor\ObjectEncryptorFactory;
use stdClass;

class ObjectEncryptorTest extends AbstractTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        putenv('AWS_ACCESS_KEY_ID=' . getenv('TEST_AWS_ACCESS_KEY_ID'));
        putenv('AWS_SECRET_ACCESS_KEY=' . getenv('TEST_AWS_SECRET_ACCESS_KEY'));
        putenv('AZURE_TENANT_ID=' . getenv('TEST_TENANT_ID'));
        putenv('AZURE_CLIENT_ID=' . getenv('TEST_CLIENT_ID'));
        putenv('AZURE_CLIENT_SECRET=' . getenv('TEST_CLIENT_SECRET'));
        putenv('GOOGLE_APPLICATION_CREDENTIALS=' . getenv('TEST_GOOGLE_APPLICATION_CREDENTIALS'));
    }

    private function getEncryptor(): ObjectEncryptor
    {
        $options = new EncryptorOptions(
            'my-stack',
            self::getKmsKeyId(),
            self::getKmsRegion(),
            null,
            self::getAkvUrl(),
            self::getGkmsKeyId(),
        );
        $factory = new ObjectEncryptorFactory();
        return $factory->getEncryptor($options);
    }

    public function testEncryptorScalar(): void
    {
        $encryptor = $this->getEncryptor();
        $originalText = 'secret';
        $encrypted = $encryptor->encryptForComponent($originalText, 'my-component');
        self::assertIsString($encrypted);
        self::assertStringStartsWith('KBC::ComponentSecureKV::', (string) $encrypted);
        self::assertEquals($originalText, $encryptor->decryptForComponent($encrypted, 'my-component'));
    }

    public function testEncryptorStackAwsNoAwsCredentials(): void
    {
        putenv('AWS_ACCESS_KEY_ID=fail');
        putenv('AWS_SECRET_ACCESS_KEY=fail');
        $encryptor = ObjectEncryptorFactory::getAwsEncryptor(
            'my-stack',
            self::getKmsKeyId(),
            self::getKmsRegion(),
            null
        );
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage('Encryption failed: Ciphering failed: Failed to obtain encryption key.');
        $encryptor->encryptForComponent('secret', 'some-component');
        // for azure, this test takes minutes to execute, so it is not included
    }

    public function testEncryptorStackGcpNoGcpCredentials(): void
    {
        putenv('GOOGLE_APPLICATION_CREDENTIALS=fail');
        $encryptor = ObjectEncryptorFactory::getGcpEncryptor(
            'my-stack',
            self::getGkmsKeyId()
        );
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage(
            'Cipher key settings are invalid: Could not construct ApplicationDefaultCredentials'
        );
        $encryptor->encryptGeneric('secret');
    }

    public function unsupportedEncryptionInputProvider(): array
    {
        return [
            'invalid class' => [
                new class() {
                },
                'Only stdClass, array and string are supported types for encryption.',
            ],
            'invalid class in value' => [
                [
                    'key' => 'value',
                    'key2' => new class() {
                    },
                ],
                'Invalid item $key - only stdClass, array and scalar can be encrypted.',
            ],
            'invalid class in encrypted value' => [
                [
                    'key' => 'value',
                    '#key2' => new class() {
                    },
                ],
                'Invalid item $key - only stdClass, array and scalar can be encrypted.',
            ],
        ];
    }

    /**
     * @dataProvider unsupportedEncryptionInputProvider
     * @param array|stdClass|string $input
     */
    public function testEncryptorUnsupportedInput($input, string $expectedMessage): void
    {
        $encryptor = $this->getEncryptor();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage($expectedMessage);
        $encryptor->encryptForComponent($input, 'my-component');
    }

    public function unsupportedDecryptionInputProvider(): array
    {
        return [
            'invalid class' => [
                new class() {
                },
                'Only stdClass, array and string are supported types for decryption.',
            ],
            'invalid class in value' => [
                [
                    'key' => 'value',
                    'key2' => new class() {
                    },
                ],
                'Invalid item key2 - only stdClass, array and scalar can be decrypted.',
            ],
            'invalid class in encrypted value' => [
                [
                    'key' => 'value',
                    '#key2' => new class() {
                    },
                ],
                'Invalid item #key2 - only stdClass, array and scalar can be decrypted.',
            ],
        ];
    }

    /**
     * @dataProvider unsupportedDecryptionInputProvider
     * @param array|stdClass|string $input
     */
    public function testDecryptorUnsupportedInput($input, string $expectedMessage): void
    {
        $encryptor = $this->getEncryptor();
        self::expectException(ApplicationException::class);
        self::expectExceptionMessage($expectedMessage);
        $encryptor->decryptForComponent($input, 'my-component');
    }

    public function decryptorInvalidCipherTextProvider(): array
    {
        return [
            'somewhat similar' => [
                'KBC::ComponentSecureKV::eJxLtDK2qs60Mrthis is not a valid cipher but it looks like one lo1Sww=',
                'Value "KBC::ComponentSecureKV::eJxLtDK2qs60Mrthis is not a valid cipher but it looks like one lo1Sww="'
                . ' is not an encrypted value.',
            ],
            'completely off' => [
                'this does not even look like a cipher text',
                'Value "this does not even look like a cipher text" is not an encrypted value.',
            ],
            'somewhat similar in key' => [
                [
                    'key1' => 'somevalue',
                    'key2' => [
                        '#anotherKey' => 'KBC::ComponentSecureKV::eJxLtDK2qs60Mrthis is not a valid cipher but it ' .
                            'looks like one lo1Sww=',
                    ],
                ],
                'Invalid cipher text for key #anotherKey Value "KBC::ComponentSecureKV::eJxLtDK2qs60Mrthis is not ' .
                'a valid cipher but it looks like one lo1Sww=" is not an encrypted value.',
            ],
            'completely off in key' => [
                [
                    'key1' => 'somevalue',
                    'key2' => [
                        '#anotherKey' => 'this does not even look like a cipher text',
                    ],
                ],
                'Invalid cipher text for key #anotherKey Value "this does not even look like a cipher text" ' .
                'is not an encrypted value.',
            ],
        ];
    }

    /**
     * @dataProvider decryptorInvalidCipherTextProvider
     * @param array|stdClass|string $encrypted
     */
    public function testDecryptorInvalidCipherText($encrypted, string $expectedMessage): void
    {
        $encryptor = $this->getEncryptor();
        self::expectException(UserException::class);
        self::expectExceptionMessage($expectedMessage);
        $encryptor->decryptForComponent($encrypted, 'my-component');
    }

    public function testEncryptorAlreadyEncrypted(): void
    {
        $encryptor = $this->getEncryptor();
        $data = [
            '#GenericAKVWrapper' => 'KBC::SecureKV::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#GenericGKMSWrapper' => 'KBC::SecureGKMS::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#GenericKMSWrapper' => 'KBC::Secure::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ComponentAKVWrapper' => 'KBC::ComponentSecureKV::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ComponentGKMSWrapper' => 'KBC::ComponentSecureGKMS::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ComponentKMSWrapper' => 'KBC::ComponentSecure::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ProjectAKVWrapper' =>  'KBC::ProjectSecureKV::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ProjectGKMSWrapper' =>  'KBC::ProjectSecureGKMS::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ProjectKMSWrapper' =>  'KBC::ProjectSecure::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ConfigurationAKVWrapper' => 'KBC::ConfigSecureKV::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ConfigurationGKMSWrapper' => 'KBC::ConfigSecureGKMS::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ConfigurationKMSWrapper' => 'KBC::ConfigSecure::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ProjectWideAKVWrapper' => 'KBC::ConfigSecureKV::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ProjectWideGKMSWrapper' => 'KBC::ConfigSecureGKMS::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#ProjectWideKMSWrapper' => 'KBC::ConfigSecure::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#BranchTypeProjectAKVWrapper' => 'KBC::BranchTypeSecureKV::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#BranchTypeProjectGKMSWrapper' => 'KBC::BranchTypeSecureGKMS::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#BranchTypeProjectKMSWrapper' => 'KBC::BranchTypeSecure::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#BranchTypeProjectWideAKVWrapper' => 'KBC::BranchTypeSecureKV::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#BranchTypeProjectWideGKMSWrapper' => 'KBC::BranchTypeSecureGKMS::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#BranchTypeProjectWideKMSWrapper' => 'KBC::BranchTypeSecure::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#BranchTypeConfigurationAKVWrapper' => 'KBC::BranchTypeConfigSecureKV::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#BranchTypeConfigurationGKMSWrapper' => 'KBC::BranchTypeConfigSecureGKMS::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#BranchTypeConfigurationKMSWrapper' => 'KBC::BranchTypeConfigSecure::aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#Similar' => 'KBC::ConfigSecureKVaaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#Legacy1' => 'KBC::Encrypted==aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#Legacy2' => 'KBC::ComponentEncrypted==aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#Legacy3' => 'KBC::ComponentProjectEncrypted==aaaaaaaaaaaaaaaaaaaaaaaaaa',
            '#LegacySimilar' => 'KBC::Encryptedaaaaaaaaaaaaaaaaaaaaaaaaaa',
        ];
        $encryptedValue = $encryptor->encryptForComponent($data, 'my-component');
        self::assertIsArray($encryptedValue);
        // these two keys do not match exactly, and therefore are re-encrypted
        self::assertStringStartsWith('KBC::ComponentSecureKV::', (string) $encryptedValue['#Similar']);
        self::assertStringStartsWith('KBC::ComponentSecureKV::', (string) $encryptedValue['#LegacySimilar']);

        // decrypt the two encrypted values, everything else should remain identical
        self::assertSame(
            'KBC::ConfigSecureKVaaaaaaaaaaaaaaaaaaaaaaaaaa',
            $encryptor->decryptForComponent($encryptedValue['#Similar'], 'my-component')
        );
        self::assertSame(
            'KBC::Encryptedaaaaaaaaaaaaaaaaaaaaaaaaaa',
            $encryptor->decryptForComponent($encryptedValue['#LegacySimilar'], 'my-component')
        );
        unset($data['#LegacySimilar']);
        unset($data['#Similar']);
        unset($encryptedValue['#LegacySimilar']);
        unset($encryptedValue['#Similar']);
        self::assertSame($data, $encryptedValue);
    }

    public function testEncryptorSimpleArray(): void
    {
        $encryptor = $this->getEncryptor();
        $array = [
            'key1' => 'value1',
            '#key2' => 'value2',
        ];
        $result = $encryptor->encryptForComponent($array, 'my-component');
        self::assertIsArray($result);
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('#key2', $result);
        self::assertEquals('value1', $result['key1']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['#key2']);

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsArray($decrypted);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('#key2', $decrypted);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('value2', $decrypted['#key2']);
    }

    public function testEncryptorSimpleObject(): void
    {
        $encryptor = $this->getEncryptor();
        $object = new stdClass();
        $object->key1 = 'value1';
        $object->{'#key2'} = 'value2';

        $result = $encryptor->encryptForComponent($object, 'my-component');
        self::assertIsObject($result);
        self::assertTrue(property_exists($result, 'key1'));
        self::assertTrue(property_exists($result, '#key2'));
        self::assertEquals('value1', $result->key1);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key2'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
        self::assertTrue(property_exists($decrypted, 'key1'));
        self::assertTrue(property_exists($decrypted, '#key2'));
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->{'#key2'});
    }

    public function testEncryptorSimpleArrayScalars(): void
    {
        $encryptor = $this->getEncryptor();
        $array = [
            'key1' => 'value1',
            '#key2' => 'value2',
            '#key3' => true,
            '#key4' => 1,
            '#key5' => 1.5,
            '#key6' => null,
            'key7' => null,
        ];
        $result = $encryptor->encryptForComponent($array, 'my-component');
        self::assertIsArray($result);
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('#key2', $result);
        self::assertEquals('value1', $result['key1']);
        self::assertStringStartsWith('KBC::ComponentSecure', (string) $result['#key2']);
        self::assertStringStartsWith('KBC::ComponentSecure', (string) $result['#key3']);
        self::assertStringStartsWith('KBC::ComponentSecure', (string) $result['#key4']);
        self::assertStringStartsWith('KBC::ComponentSecure', (string) $result['#key5']);
        self::assertStringStartsWith('KBC::ComponentSecure', (string) $result['#key6']);

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsArray($decrypted);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('#key2', $decrypted);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('value2', $decrypted['#key2']);
        self::assertEquals(true, $decrypted['#key3']);
        self::assertEquals(1, $decrypted['#key4']);
        self::assertEquals(1.5, $decrypted['#key5']);
        self::assertEquals(null, $decrypted['#key6']);
        self::assertEquals(null, $decrypted['key7']);
    }

    public function testEncryptorSimpleObjectScalars(): void
    {
        $encryptor = $this->getEncryptor();
        $object = new stdClass();
        $object->key1 = 'value1';
        $object->{'#key2'} = 'value2';
        $object->{'#key3'} = true;
        $object->{'#key4'} = 1;
        $object->{'#key5'} = 1.5;
        $object->{'#key6'} = null;
        $object->key7 = null;

        $result = $encryptor->encryptForComponent($object, 'my-component');
        self::assertIsObject($result);
        self::assertTrue(property_exists($result, 'key1'));
        self::assertTrue(property_exists($result, '#key2'));
        self::assertEquals('value1', $result->key1);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key2'});
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key3'});
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key4'});
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key5'});
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key6'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
        self::assertTrue(property_exists($decrypted, 'key1'));
        self::assertTrue(property_exists($decrypted, '#key2'));
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->{'#key2'});
        self::assertEquals(true, $decrypted->{'#key3'});
        self::assertEquals(1, $decrypted->{'#key4'});
        self::assertEquals(1.5, $decrypted->{'#key5'});
        self::assertEquals(null, $decrypted->{'#key6'});
        self::assertEquals(null, $decrypted->{'key7'});
    }

    public function testEncryptorSimpleArrayEncrypted(): void
    {
        $encryptor = $this->getEncryptor();
        $encryptedValue = $encryptor->encryptForComponent('test', 'my-component');
        $array = [
            'key1' => 'value1',
            '#key2' => $encryptedValue,
        ];
        $result = $encryptor->encryptForComponent($array, 'my-component');
        self::assertIsArray($result);
        self::assertArrayHasKey('key1', $result);
        self::assertArrayHasKey('#key2', $result);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals($encryptedValue, $result['#key2']);

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsArray($decrypted);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('#key2', $decrypted);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('test', $decrypted['#key2']);
    }

    public function testEncryptorSimpleObjectEncrypted(): void
    {
        $encryptor = $this->getEncryptor();
        $encryptedValue = $encryptor->encryptForComponent('test', 'my-component');
        $object = new stdClass();
        $object->key1 = 'value1';
        $object->{'#key2'} = $encryptedValue;

        $result = $encryptor->encryptForComponent($object, 'my-component');
        self::assertIsObject($result);
        self::assertTrue(property_exists($result, 'key1'));
        self::assertTrue(property_exists($result, '#key2'));
        self::assertEquals('value1', $result->key1);
        self::assertEquals($encryptedValue, $result->{'#key2'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
        self::assertTrue(property_exists($decrypted, 'key1'));
        self::assertTrue(property_exists($decrypted, '#key2'));
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('test', $decrypted->{'#key2'});
    }

    public function testEncryptorNestedArray(): void
    {
        $encryptor = $this->getEncryptor();
        $array = [
            'key1' => 'value1',
            'key2' => [
                'nestedKey1' => 'value2',
                'nestedKey2' => [
                    '#finalKey' => 'value3',
                ],
            ],
        ];
        $result = $encryptor->encryptForComponent($array, 'my-component');
        self::assertIsArray($result);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('value2', $result['key2']['nestedKey1']);
        self::assertStringStartsWith('KBC::ComponentSecureKV::', $result['key2']['nestedKey2']['#finalKey']);

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsArray($decrypted);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('key2', $decrypted);
        self::assertArrayHasKey('nestedKey1', $decrypted['key2']);
        self::assertArrayHasKey('nestedKey2', $decrypted['key2']);
        self::assertArrayHasKey('#finalKey', $decrypted['key2']['nestedKey2']);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('value2', $decrypted['key2']['nestedKey1']);
        self::assertEquals('value3', $decrypted['key2']['nestedKey2']['#finalKey']);
    }

    public function testEncryptorNestedObject(): void
    {
        $encryptor = $this->getEncryptor();
        $object = new stdClass();
        $nested1 = new stdClass();
        $nested2 = new stdClass();
        $nested2->{'#finalKey'} = 'value3';
        $nested1->nestedKey1 = 'value2';
        $nested1->nestedKey2 = $nested2;
        $object->key1 = 'value1';
        $object->key2 = $nested1;

        $result = $encryptor->encryptForComponent($object, 'my-component');
        self::assertIsObject($result);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2->nestedKey1);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->key2->nestedKey2->{'#finalKey'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
        self::assertTrue(property_exists($decrypted, 'key1'));
        self::assertTrue(property_exists($decrypted, 'key2'));
        self::assertTrue(property_exists($decrypted->key2, 'nestedKey1'));
        self::assertTrue(property_exists($decrypted->key2, 'nestedKey2'));
        self::assertTrue(property_exists($decrypted->key2->nestedKey2, '#finalKey'));
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->key2->nestedKey1);
        self::assertEquals('value3', $decrypted->key2->nestedKey2->{'#finalKey'});
    }

    public function testEncryptorNestedArrayWithArrayKeyHashmark(): void
    {
        $encryptor = $this->getEncryptor();
        $array = [
            'key1' => 'value1',
            'key2' => [
                'nestedKey1' => 'value2',
                'nestedKey2' => [
                    '#finalKey' => 'value3',
                ],
            ],
            '#key3' => [
                'anotherNestedKey' => 'someValue',
                '#encryptedNestedKey' => 'someValue2',
                '#encryptedVariable' => '{{ variable }}',
            ],
        ];
        $result = $encryptor->encryptForComponent($array, 'my-component');
        self::assertIsArray($result);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('value2', $result['key2']['nestedKey1']);
        self::assertEquals('someValue', $result['#key3']['anotherNestedKey']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['#key3']['#encryptedNestedKey']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['key2']['nestedKey2']['#finalKey']);
        self::assertEquals('{{ variable }}', $result['#key3']['#encryptedVariable']);

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsArray($decrypted);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('key2', $decrypted);
        self::assertArrayHasKey('#key3', $decrypted);
        self::assertArrayHasKey('nestedKey1', $decrypted['key2']);
        self::assertArrayHasKey('nestedKey2', $decrypted['key2']);
        self::assertArrayHasKey('#finalKey', $decrypted['key2']['nestedKey2']);
        self::assertArrayHasKey('anotherNestedKey', $decrypted['#key3']);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('value2', $decrypted['key2']['nestedKey1']);
        self::assertEquals('value3', $decrypted['key2']['nestedKey2']['#finalKey']);
        self::assertEquals('someValue', $decrypted['#key3']['anotherNestedKey']);
        self::assertEquals('someValue2', $decrypted['#key3']['#encryptedNestedKey']);
        self::assertEquals('{{ variable }}', $result['#key3']['#encryptedVariable']);
    }

    public function testEncryptorNestedObjectWithArrayKeyHashmark(): void
    {
        $encryptor = $this->getEncryptor();
        $object = new stdClass();
        $nested1 = new stdClass();
        $nested2 = new stdClass();
        $nested2->{'#finalKey'} = 'value3';
        $nested1->nestedKey1 = 'value2';
        $nested1->nestedKey2 = $nested2;
        $object->key1 = 'value1';
        $object->key2 = $nested1;
        $nested3 = new stdClass();
        $nested3->anotherNestedKey = 'someValue';
        $nested3->{'#encryptedNestedKey'} = 'someValue2';
        $object->{'#key3'} = $nested3;

        $result = $encryptor->encryptForComponent($object, 'my-component');
        self::assertIsObject($result);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2->nestedKey1);
        self::assertEquals('someValue', $result->{'#key3'}->anotherNestedKey);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->{'#key3'}->{'#encryptedNestedKey'});
        self::assertStringStartsWith('KBC::ComponentSecure', $result->key2->nestedKey2->{'#finalKey'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
        self::assertTrue(property_exists($decrypted, 'key1'));
        self::assertTrue(property_exists($decrypted, 'key2'));
        self::assertTrue(property_exists($decrypted, '#key3'));
        self::assertTrue(property_exists($decrypted->key2, 'nestedKey1'));
        self::assertTrue(property_exists($decrypted->key2, 'nestedKey2'));
        self::assertTrue(property_exists($decrypted->key2->nestedKey2, '#finalKey'));
        self::assertTrue(property_exists($decrypted->{'#key3'}, 'anotherNestedKey'));
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->key2->nestedKey1);
        self::assertEquals('value3', $decrypted->key2->nestedKey2->{'#finalKey'});
        self::assertEquals('someValue', $decrypted->{'#key3'}->anotherNestedKey);
        self::assertEquals('someValue2', $decrypted->{'#key3'}->{'#encryptedNestedKey'});
    }

    public function testEncryptorNestedArrayEncrypted(): void
    {
        $encryptor = $this->getEncryptor();
        $encryptedValue = $encryptor->encryptForComponent('test', 'my-component');
        $array = [
            'key1' => 'value1',
            'key2' => [
                'nestedKey1' => 'value2',
                'nestedKey2' => [
                    '#finalKey' => 'value3',
                    '#finalKeyEncrypted' => $encryptedValue,
                ],
            ],
        ];

        $result = $encryptor->encryptForComponent($array, 'my-component');
        self::assertIsArray($result);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('value2', $result['key2']['nestedKey1']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['key2']['nestedKey2']['#finalKey']);
        self::assertEquals($encryptedValue, $result['key2']['nestedKey2']['#finalKeyEncrypted']);

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsArray($decrypted);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('key2', $decrypted);
        self::assertArrayHasKey('nestedKey1', $decrypted['key2']);
        self::assertArrayHasKey('nestedKey2', $decrypted['key2']);
        self::assertArrayHasKey('#finalKey', $decrypted['key2']['nestedKey2']);
        self::assertArrayHasKey('#finalKeyEncrypted', $decrypted['key2']['nestedKey2']);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('value2', $decrypted['key2']['nestedKey1']);
        self::assertEquals('value3', $decrypted['key2']['nestedKey2']['#finalKey']);
        self::assertEquals('test', $decrypted['key2']['nestedKey2']['#finalKeyEncrypted']);
    }

    public function testEncryptorNestedObjectEncrypted(): void
    {
        $encryptor = $this->getEncryptor();
        $encryptedValue = $encryptor->encryptForComponent('test', 'my-component');

        $object = new stdClass();
        $object->key1 = 'value1';
        $nested1 = new stdClass();
        $nested1->nestedKey1 = 'value2';
        $nested2 = new stdClass();
        $nested2->{'#finalKey'} = 'value3';
        $nested2->{'#finalKeyEncrypted'} = $encryptedValue;
        $nested1->nestedKey2 = $nested2;
        $object->key2 = $nested1;

        $result = $encryptor->encryptForComponent($object, 'my-component');
        self::assertIsObject($result);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2->nestedKey1);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->key2->nestedKey2->{'#finalKey'});
        self::assertEquals($encryptedValue, $result->key2->nestedKey2->{'#finalKeyEncrypted'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
        self::assertTrue(property_exists($decrypted, 'key1'));
        self::assertTrue(property_exists($decrypted, 'key2'));
        self::assertTrue(property_exists($decrypted->key2, 'nestedKey1'));
        self::assertTrue(property_exists($decrypted->key2, 'nestedKey2'));
        self::assertTrue(property_exists($decrypted->key2->nestedKey2, '#finalKey'));
        self::assertTrue(property_exists($decrypted->key2->nestedKey2, '#finalKeyEncrypted'));
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->key2->nestedKey1);
        self::assertEquals('value3', $decrypted->key2->nestedKey2->{'#finalKey'});
        self::assertEquals('test', $decrypted->key2->nestedKey2->{'#finalKeyEncrypted'});
    }

    public function testEncryptorNestedArrayWithArray(): void
    {
        $encryptor = $this->getEncryptor();
        $array = [
            'key1' => 'value1',
            'key2' => [
                ['nestedKey1' => 'value2'],
                ['nestedKey2' => ['#finalKey' => 'value3']],
            ],
        ];
        $result = $encryptor->encryptForComponent($array, 'my-component');
        self::assertIsArray($result);
        self::assertEquals('value1', $result['key1']);
        self::assertEquals('value2', $result['key2'][0]['nestedKey1']);
        self::assertStringStartsWith('KBC::ComponentSecure', $result['key2'][1]['nestedKey2']['#finalKey']);

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsArray($decrypted);
        self::assertArrayHasKey('key1', $decrypted);
        self::assertArrayHasKey('key2', $decrypted);
        self::assertCount(2, $result['key2']);
        self::assertArrayHasKey('nestedKey1', $decrypted['key2'][0]);
        self::assertArrayHasKey('nestedKey2', $decrypted['key2'][1]);
        self::assertArrayHasKey('#finalKey', $decrypted['key2'][1]['nestedKey2']);
        self::assertEquals('value1', $decrypted['key1']);
        self::assertEquals('value2', $decrypted['key2'][0]['nestedKey1']);
        self::assertEquals('value3', $decrypted['key2'][1]['nestedKey2']['#finalKey']);
    }

    public function testEncryptorNestedObjectWithArray(): void
    {
        $encryptor = $this->getEncryptor();
        $object = new stdClass();
        $object->key1 = 'value1';
        $object->key2 = [];
        $nested1 = new stdClass();
        $nested1->nestedKey1 = 'value2';
        $object->key2[] = $nested1;
        $nested2 = new stdClass();
        $nested3 = new stdClass();
        $nested3->{'#finalKey'} = 'value3';
        $nested2->nestedKey2 = $nested3;
        $object->key2[] = $nested2;

        $result = $encryptor->encryptForComponent($object, 'my-component');
        self::assertIsObject($result);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2[0]->nestedKey1);
        self::assertStringStartsWith('KBC::ComponentSecure', $result->key2[1]->nestedKey2->{'#finalKey'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
        self::assertTrue(property_exists($decrypted, 'key1'));
        self::assertTrue(property_exists($decrypted, 'key2'));
        self::assertCount(2, $result->key2);
        self::assertTrue(property_exists($decrypted->key2[0], 'nestedKey1'));
        self::assertTrue(property_exists($decrypted->key2[1], 'nestedKey2'));
        self::assertTrue(property_exists($decrypted->key2[1]->nestedKey2, '#finalKey'));
        self::assertEquals('value1', $decrypted->key1);
        self::assertEquals('value2', $decrypted->key2[0]->nestedKey1);
        self::assertEquals('value3', $decrypted->key2[1]->nestedKey2->{'#finalKey'});
    }

    public function testMixedCryptoWrappersDecryptArray(): void
    {
        $encryptor = $this->getEncryptor();
        $array = [
            '#key1' => $encryptor->encryptForComponent('value1', 'my-component'),
            '#key2' => $encryptor->encryptForProject('value2', 'my-component', 'my-project'),
        ];
        self::assertStringStartsWith('KBC::ComponentSecure', $array['#key1']);
        self::assertStringStartsWith('KBC::ProjectSecureKV::', $array['#key2']);

        $decrypted = $encryptor->decryptForProject($array, 'my-component', 'my-project');
        self::assertArrayHasKey('#key1', $decrypted);
        self::assertArrayHasKey('#key2', $decrypted);
        self::assertCount(2, $decrypted);
        self::assertEquals('value1', $decrypted['#key1']);
        self::assertEquals('value2', $decrypted['#key2']);
    }

    public function testMixedCryptoWrappersDecryptObject(): void
    {
        $encryptor = $this->getEncryptor();
        $object = new stdClass();
        $object->{'#key1'} = $encryptor->encryptForComponent('value1', 'my-component');
        $object->{'#key2'} = $encryptor->encryptForProject('value2', 'my-component', 'my-project');

        self::assertStringStartsWith('KBC::ComponentSecureKV::', $object->{'#key1'});
        self::assertStringStartsWith('KBC::ProjectSecureKV::', $object->{'#key2'});

        $decrypted = $encryptor->decryptForProject($object, 'my-component', 'my-project');
        self::assertTrue(property_exists($decrypted, '#key1'));
        self::assertTrue(property_exists($decrypted, '#key2'));
        self::assertEquals('value1', $decrypted->{'#key1'});
        self::assertEquals('value2', $decrypted->{'#key2'});
    }

    public function testEncryptEmptyArray(): void
    {
        $encryptor = $this->getEncryptor();
        $array = [];
        $encrypted = $encryptor->encryptForComponent($array, 'my-component');
        self::assertEquals([], $encrypted);
        self::assertEquals([], $encryptor->decryptForComponent($encrypted, 'my-component'));
    }

    public function testEncryptEmptyObject(): void
    {
        $encryptor = $this->getEncryptor();
        $object = new stdClass();
        $encrypted = $encryptor->encryptForComponent($object, 'my-component');
        self::assertEquals(stdClass::class, get_class($encrypted));
        self::assertEquals(
            stdClass::class,
            get_class($encryptor->decryptForComponent($encrypted, 'my-component'))
        );
    }

    public function testEncryptorDecodedJSONObject(): void
    {
        $encryptor = $this->getEncryptor();
        $json = '{
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
            "emptyObject": {},
            "#key4": "{{ variable }}"
        }';

        $result = $encryptor->encryptForComponent(json_decode($json), 'my-component');
        self::assertIsObject($result);
        self::assertEquals('value1', $result->key1);
        self::assertEquals('value2', $result->key2->nestedKey1);
        self::assertEquals('someValue', $result->{'#key3'}->anotherNestedKey);
        self::assertEquals('{{ variable }}', $result->{'#key4'});
        self::assertStringStartsWith('KBC::ComponentSecureKV::', $result->{'#key3'}->{'#encryptedNestedKey'});
        self::assertStringStartsWith('KBC::ComponentSecureKV::', $result->key2->nestedKey2->{'#finalKey'});

        $decrypted = $encryptor->decryptForComponent($result, 'my-component');
        self::assertIsObject($decrypted);
        self::assertTrue(property_exists($decrypted, 'key1'));
        self::assertTrue(property_exists($decrypted, 'key2'));
        self::assertTrue(property_exists($decrypted, '#key3'));
        self::assertTrue(property_exists($decrypted, '#key4'));
        self::assertTrue(property_exists($decrypted, 'array'));
        self::assertTrue(property_exists($decrypted, 'emptyArray'));
        self::assertTrue(property_exists($decrypted, 'emptyObject'));
        self::assertTrue(property_exists($decrypted->key2, 'nestedKey1'));
        self::assertTrue(property_exists($decrypted->key2, 'nestedKey2'));
        self::assertTrue(property_exists($decrypted->key2->nestedKey2, '#finalKey'));

        self::assertIsArray($decrypted->array);
        self::assertIsArray($decrypted->emptyArray);
        self::assertIsObject($decrypted->emptyObject);
        self::assertIsObject($decrypted->key2);
        self::assertTrue(property_exists($decrypted->{'#key3'}, 'anotherNestedKey'));
        self::assertIsObject($decrypted->{'#key3'});
        self::assertEquals('value1', $decrypted->key1);
        self::assertTrue(property_exists($decrypted->key2, 'nestedKey1'));
        self::assertEquals('value2', $decrypted->key2->nestedKey1);
        self::assertTrue(property_exists($decrypted->{'#key3'}, 'anotherNestedKey'));
        self::assertEquals('someValue', $decrypted->{'#key3'}->{'anotherNestedKey'});
        self::assertTrue(property_exists($decrypted->{'#key3'}, '#encryptedNestedKey'));
        self::assertEquals('someValue2', $decrypted->{'#key3'}->{'#encryptedNestedKey'});
        self::assertTrue(property_exists($decrypted->key2, 'nestedKey2'));
        self::assertEquals('value3', $decrypted->key2->nestedKey2->{'#finalKey'});
        self::assertEquals('{{ variable }}', $decrypted->{'#key4'});

        self::assertEquals(json_encode($decrypted), json_encode(json_decode($json)));
    }

    public function cloudEncryptorProvider(): Generator
    {
        yield 'akv' => [
            'encryptor' => ObjectEncryptorFactory::getAzureEncryptor(
                'my-stack',
                self::getAkvUrl(),
            ),
            'genericPrefix' => 'KBC::SecureKV::',
            'componentPrefix' => 'KBC::ComponentSecureKV::',
            'projectPrefix' => 'KBC::ProjectSecureKV::',
            'configurationPrefix' => 'KBC::ConfigSecureKV::',
            'projectWidePrefix' => 'KBC::ProjectWideSecureKV::',
            'branchTypePrefix' => 'KBC::BranchTypeSecureKV::',
            'projectWideBranchTypePrefix' => 'KBC::ProjectWideBranchTypeSecureKV::',
            'branchTypeConfigurationPrefix' => 'KBC::BranchTypeConfigSecureKV::',
        ];
        yield 'gkms' => [
            'encryptor' => ObjectEncryptorFactory::getGcpEncryptor(
                'my-stack',
                self::getGkmsKeyId(),
            ),
            'genericPrefix' => 'KBC::SecureGKMS::',
            'componentPrefix' => 'KBC::ComponentSecureGKMS::',
            'projectPrefix' => 'KBC::ProjectSecureGKMS::',
            'configurationPrefix' => 'KBC::ConfigSecureGKMS::',
            'projectWidePrefix' => 'KBC::ProjectWideSecureGKMS::',
            'branchTypePrefix' => 'KBC::BranchTypeSecureGKMS::',
            'projectWideBranchTypePrefix' => 'KBC::ProjectWideBranchTypeSecureGKMS::',
            'branchTypeConfigurationPrefix' => 'KBC::BranchTypeConfigSecureGKMS::',
        ];
        yield 'kms' => [
            'encryptor' => ObjectEncryptorFactory::getAwsEncryptor(
                'my-stack',
                self::getKmsKeyId(),
                self::getKmsRegion(),
                null,
            ),
            'genericPrefix' => 'KBC::Secure::',
            'componentPrefix' => 'KBC::ComponentSecure::',
            'projectPrefix' => 'KBC::ProjectSecure::',
            'configurationPrefix' => 'KBC::ConfigSecure::',
            'projectWidePrefix' => 'KBC::ProjectWideSecure::',
            'branchTypePrefix' => 'KBC::BranchTypeSecure::',
            'projectWideBranchTypePrefix' => 'KBC::ProjectWideBranchTypeSecure::',
            'branchTypeConfigurationPrefix' => 'KBC::BranchTypeConfigSecure::',
        ];
    }

    /**
     * @dataProvider cloudEncryptorProvider
     */
    public function testGetRegisteredWrapperEncryptors(
        ObjectEncryptor $encryptor,
        string $genericPrefix,
        string $componentPrefix,
        string $projectPrefix,
        string $configurationPrefix,
        string $projectWidePrefix,
        string $branchTypePrefix,
        string $projectWideBranchTypePrefix,
        string $branchTypeConfigurationPrefix,
    ): void {
        $encryptedGeneric = $encryptor->encryptGeneric('secret1');
        self::assertStringStartsWith($genericPrefix, $encryptedGeneric);
        self::assertEquals('secret1', $encryptor->decryptGeneric($encryptedGeneric));

        $encryptedComponent = $encryptor->encryptForComponent('secret2', 'my-component');
        self::assertStringStartsWith($componentPrefix, $encryptedComponent);
        self::assertEquals('secret1', $encryptor->decryptForComponent($encryptedGeneric, 'my-component'));
        self::assertEquals('secret2', $encryptor->decryptForComponent($encryptedComponent, 'my-component'));

        $encryptedProject = $encryptor->encryptForProject('secret3', 'my-component', 'my-project');
        self::assertStringStartsWith($projectPrefix, $encryptedProject);
        self::assertEquals(
            'secret1',
            $encryptor->decryptForProject($encryptedGeneric, 'my-component', 'my-project')
        );
        self::assertEquals(
            'secret2',
            $encryptor->decryptForProject($encryptedComponent, 'my-component', 'my-project')
        );
        self::assertEquals(
            'secret3',
            $encryptor->decryptForProject($encryptedProject, 'my-component', 'my-project')
        );

        $encryptedConfiguration = $encryptor->encryptForConfiguration(
            'secret4',
            'my-component',
            'my-project',
            'my-configuration'
        );
        self::assertStringStartsWith($configurationPrefix, $encryptedConfiguration);
        self::assertEquals(
            'secret1',
            $encryptor->decryptForConfiguration(
                $encryptedGeneric,
                'my-component',
                'my-project',
                'my-configuration'
            )
        );
        self::assertEquals(
            'secret2',
            $encryptor->decryptForConfiguration(
                $encryptedComponent,
                'my-component',
                'my-project',
                'my-configuration'
            )
        );
        self::assertEquals(
            'secret3',
            $encryptor->decryptForConfiguration(
                $encryptedProject,
                'my-component',
                'my-project',
                'my-configuration'
            )
        );
        self::assertEquals(
            'secret4',
            $encryptor->decryptForConfiguration(
                $encryptedConfiguration,
                'my-component',
                'my-project',
                'my-configuration'
            )
        );

        $encryptedProjectWide = $encryptor->encryptForProjectWide('secret2', 'my-project');
        self::assertStringStartsWith($projectWidePrefix, $encryptedProjectWide);
        self::assertEquals('secret1', $encryptor->decryptForProjectWide($encryptedGeneric, 'my-project'));
        self::assertEquals('secret2', $encryptor->decryptForProjectWide($encryptedProjectWide, 'my-project'));

        $encryptedBranchType = $encryptor->encryptForBranchType(
            'secret5',
            'my-component',
            'my-project',
            ObjectEncryptor::BRANCH_TYPE_DEFAULT,
        );
        self::assertStringStartsWith($branchTypePrefix, $encryptedBranchType);
        self::assertEquals(
            'secret1',
            $encryptor->decryptForBranchType(
                $encryptedGeneric,
                'my-component',
                'my-project',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            'secret2',
            $encryptor->decryptForBranchType(
                $encryptedComponent,
                'my-component',
                'my-project',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            'secret3',
            $encryptor->decryptForBranchType(
                $encryptedProject,
                'my-component',
                'my-project',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            'secret5',
            $encryptor->decryptForBranchType(
                $encryptedBranchType,
                'my-component',
                'my-project',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );

        $encryptedProjectWideBranchType = $encryptor->encryptForProjectWideBranchType(
            'secret6',
            'my-project',
            ObjectEncryptor::BRANCH_TYPE_DEFAULT
        );
        self::assertStringStartsWith($projectWideBranchTypePrefix, $encryptedProjectWideBranchType);
        self::assertEquals(
            'secret1',
            $encryptor->decryptForProjectWideBranchType(
                $encryptedGeneric,
                'my-project',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            'secret6',
            $encryptor->decryptForProjectWideBranchType(
                $encryptedProjectWideBranchType,
                'my-project',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );

        $encryptedBranchTypeConfiguration = $encryptor->encryptForBranchTypeConfiguration(
            'secret7',
            'my-component',
            'my-project',
            'my-configuration',
            ObjectEncryptor::BRANCH_TYPE_DEFAULT,
        );
        self::assertStringStartsWith($branchTypeConfigurationPrefix, $encryptedBranchTypeConfiguration);
        self::assertEquals(
            'secret1',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedGeneric,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            'secret2',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedComponent,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            'secret3',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedProject,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            'secret4',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedConfiguration,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            'secret5',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedBranchType,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            'secret2',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedProjectWide,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            'secret6',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedProjectWideBranchType,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            'secret7',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedBranchTypeConfiguration,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
    }

    /**
     * @dataProvider cloudEncryptorProvider
     */
    public function testIgnoreVariables(ObjectEncryptor $encryptor): void
    {
        $encryptedGeneric = $encryptor->encryptGeneric('{{ my_variable }}');
        self::assertEquals('{{ my_variable }}', $encryptedGeneric);
        self::assertEquals('{{ my_variable }}', $encryptor->decryptGeneric($encryptedGeneric));

        $encryptedComponent = $encryptor->encryptForComponent('{{ my_variable-2 }}', 'my-component');
        self::assertEquals('{{ my_variable-2 }}', $encryptedComponent);
        self::assertEquals('{{ my_variable }}', $encryptor->decryptForComponent($encryptedGeneric, 'my-component'));
        self::assertEquals('{{ my_variable-2 }}', $encryptor->decryptForComponent($encryptedComponent, 'my-component'));

        $encryptedProject = $encryptor->encryptForProject('{{ my_variable-3 }}', 'my-component', 'my-project');
        self::assertEquals('{{ my_variable-3 }}', $encryptedProject);
        self::assertEquals(
            '{{ my_variable }}',
            $encryptor->decryptForProject($encryptedGeneric, 'my-component', 'my-project')
        );
        self::assertEquals(
            '{{ my_variable-2 }}',
            $encryptor->decryptForProject($encryptedComponent, 'my-component', 'my-project')
        );
        self::assertEquals(
            '{{ my_variable-3 }}',
            $encryptor->decryptForProject($encryptedProject, 'my-component', 'my-project')
        );

        $encryptedConfiguration = $encryptor->encryptForConfiguration(
            '{{ my_variable-4 }}',
            'my-component',
            'my-project',
            'my-configuration'
        );
        self::assertEquals('{{ my_variable-4 }}', $encryptedConfiguration);
        self::assertEquals(
            '{{ my_variable }}',
            $encryptor->decryptForConfiguration(
                $encryptedGeneric,
                'my-component',
                'my-project',
                'my-configuration'
            )
        );
        self::assertEquals(
            '{{ my_variable-2 }}',
            $encryptor->decryptForConfiguration(
                $encryptedComponent,
                'my-component',
                'my-project',
                'my-configuration'
            )
        );
        self::assertEquals(
            '{{ my_variable-3 }}',
            $encryptor->decryptForConfiguration(
                $encryptedProject,
                'my-component',
                'my-project',
                'my-configuration'
            )
        );
        self::assertEquals(
            '{{ my_variable-4 }}',
            $encryptor->decryptForConfiguration(
                $encryptedConfiguration,
                'my-component',
                'my-project',
                'my-configuration'
            )
        );

        $encryptedProjectWide = $encryptor->encryptForProjectWide('{{ my_variable-2 }}', 'my-project');
        self::assertEquals('{{ my_variable-2 }}', $encryptedProjectWide);
        self::assertEquals(
            '{{ my_variable }}',
            $encryptor->decryptForProjectWide($encryptedGeneric, 'my-project')
        );
        self::assertEquals(
            '{{ my_variable-2 }}',
            $encryptor->decryptForProjectWide($encryptedProjectWide, 'my-project')
        );

        $encryptedBranchType = $encryptor->encryptForBranchType(
            '{{ my_variable-5 }}',
            'my-component',
            'my-project',
            ObjectEncryptor::BRANCH_TYPE_DEFAULT,
        );
        self::assertEquals('{{ my_variable-5 }}', $encryptedBranchType);
        self::assertEquals(
            '{{ my_variable }}',
            $encryptor->decryptForBranchType(
                $encryptedGeneric,
                'my-component',
                'my-project',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            '{{ my_variable-2 }}',
            $encryptor->decryptForBranchType(
                $encryptedComponent,
                'my-component',
                'my-project',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            '{{ my_variable-3 }}',
            $encryptor->decryptForBranchType(
                $encryptedProject,
                'my-component',
                'my-project',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            '{{ my_variable-5 }}',
            $encryptor->decryptForBranchType(
                $encryptedBranchType,
                'my-component',
                'my-project',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );

        $encryptedProjectWideBranchType = $encryptor->encryptForProjectWideBranchType(
            '{{ my_variable-6 }}',
            'my-project',
            ObjectEncryptor::BRANCH_TYPE_DEFAULT
        );
        self::assertEquals('{{ my_variable-6 }}', $encryptedProjectWideBranchType);
        self::assertEquals(
            '{{ my_variable }}',
            $encryptor->decryptForProjectWideBranchType(
                $encryptedGeneric,
                'my-project',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            '{{ my_variable-6 }}',
            $encryptor->decryptForProjectWideBranchType(
                $encryptedProjectWideBranchType,
                'my-project',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );

        $encryptedBranchTypeConfiguration = $encryptor->encryptForBranchTypeConfiguration(
            '{{ my_variable-7 }}',
            'my-component',
            'my-project',
            'my-configuration',
            ObjectEncryptor::BRANCH_TYPE_DEFAULT,
        );
        self::assertEquals('{{ my_variable-7 }}', $encryptedBranchTypeConfiguration);
        self::assertEquals(
            '{{ my_variable }}',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedGeneric,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            '{{ my_variable-2 }}',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedComponent,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            '{{ my_variable-3 }}',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedProject,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            '{{ my_variable-4 }}',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedConfiguration,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            '{{ my_variable-5 }}',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedBranchType,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            '{{ my_variable-2 }}',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedProjectWide,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            '{{ my_variable-6 }}',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedProjectWideBranchType,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
        self::assertEquals(
            '{{ my_variable-7 }}',
            $encryptor->decryptForBranchTypeConfiguration(
                $encryptedBranchTypeConfiguration,
                'my-component',
                'my-project',
                'my-configuration',
                ObjectEncryptor::BRANCH_TYPE_DEFAULT,
            )
        );
    }
}
