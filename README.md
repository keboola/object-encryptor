[![Build Status](https://travis-ci.org/keboola/object-encryptor.svg?branch=master)](https://travis-ci.org/keboola/object-encryptor)
[![Test Coverage](https://api.codeclimate.com/v1/badges/a08caf5f9ff2116fd497/test_coverage)](https://codeclimate.com/github/keboola/object-encryptor/test_coverage)
[![Maintainability](https://api.codeclimate.com/v1/badges/a08caf5f9ff2116fd497/maintainability)](https://codeclimate.com/github/keboola/object-encryptor/maintainability)

# Object Encryptor
Library provides interface for encrypting PHP arrays, stdclass objects and scalars. A cipher may contain additional metadata
which limits the conditions under which it may be decrypted. The library supports three encryption methods:

- [keboola/php-encryption](https://github.com/keboola/php-encryption) -- legacy, allows only deciphering
- [keboola-legacy/php-encryption](https://github.com/keboola/legacy-php-encryption) -- legacy version of [defuse/php-encryption](https://github.com/defuse/php-encryption), currently default
- [defuse/php-encryption](https://github.com/defuse/php-encryption) -- future encryption method with KMS managed keys

## Requirements
The library requires PHP 5.6 or PHP 7.0. Versions 7.1+ are not supported until legacy mcrypt is dropped.

## Usage
Entry point to the library is the `ObjectEncryptorFactory` class which creates instances of `ObjectEncryptor` class which
has `encrypt` and `decrypt` methods. The actual encryption and decryption mechanisms are implemented using **Crypto Wrappers**.
Crypto wrappers implement different verification methods using cypher metadata.

### Initialization
Initialize the library using the factory class:

```
$kmsKeyId = 'alias/my-key';
$kmsRegion = 'us-east-1';
$keyVersion1 = '1234567890123456';
$keyVersion0 = '123456789012345678901234567890ab';
$factory = new ObjectEncryptorFactory($kmsKeyId, $kmsRegion, $keyVersion1, $keyVersion0);
```

Additional parameteters may be set with `setComponentId`, `setConfigurationId`, `setProjectId` and `setStackId` methods.

### Wrappers
Depending on the provided keys and parameters, the following wrappers will be available:

- `Encryptor` - legacy decryptor for unprefixed ciphers, requires `keyVersion0` 
- `BaseWrapper` - legacy wrapper for `KBC::Encrypted` ciphers, requires `keyVersion1`
- `ComponentWrapper` - legacy wrapper for `KBC::ComponentEncrypted==` ciphers, requires `keyVersion1` and `componentId`
- `ComponentProjectWrapper` - legacy wrapper for `KBC::ComponentProjectEncrypted==` ciphers, requires `keyVersion1` and `componentId` and `projectId`
- `GenericKMSWrapper` - current wrapper for `KBC::Secure::` ciphers, requires `kmsKeyId` and `kmsRegion`. Also the runner must have AWS credentials avaialable (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- `ComponentWrapper` - current wrapper for `KBC::ComponentSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId` and `componentId`
- `ProjectWrapper` - current wrapper for `KBC::ProjectSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId`, `componentId` and `projectId`.
- `ConfigurationWrapper` - current wrapper for `KBC::ConfigSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId`, `componentId`, `projectId` and `configurationId`.

During encryption, the wrapper has to be specified (or `BaseWrapper` is used). During decryption, the wrapper is chosen automatically by the 
cipher prefix. If the wrapper is not available (key or parameters are not set or equal to those in the cipher), the value cannot be deciphered.

## Usage

```
// intialize factory
putenv('AWS_ACCESS_KEY_ID=AKIA...');
putenv('AWS_SECRET_ACCESS_KEY=secret);
$keyId = 'alias/some-key';
$keyRegion = 'us-east-1';
$legacyKey = '1234567890123456';
$factory = new ObjectEncryptorFactory($keyId, $keyRegion, $legacyKey, '');
$factory->setComponentId('dummy-component');
// get encryptor
$factory->getEncryptor()->encrypt('secret', GenericWrapper::class);
$secret = $factory->getEncryptor()->decrypt($encrypted);
```
