[![Build Status](https://travis-ci.org/keboola/object-encryptor.svg?branch=master)](https://travis-ci.org/keboola/object-encryptor)
[![Test Coverage](https://api.codeclimate.com/v1/badges/a08caf5f9ff2116fd497/test_coverage)](https://codeclimate.com/github/keboola/object-encryptor/test_coverage)
[![Maintainability](https://api.codeclimate.com/v1/badges/a08caf5f9ff2116fd497/maintainability)](https://codeclimate.com/github/keboola/object-encryptor/maintainability)

# Object Encryptor
Library provides interface for encrypting PHP arrays, stdclass objects and scalars. A cipher may contain additional metadata
which limits the conditions under which it may be decrypted. The library supports three encryption methods:

- [keboola/php-encryption](https://github.com/keboola/php-encryption) -- legacy, allows only deciphering.
- [keboola-legacy/php-encryption](https://github.com/keboola/legacy-php-encryption) -- legacy version of [defuse/php-encryption](https://github.com/defuse/php-encryption), currently default.
- [defuse/php-encryption](https://github.com/defuse/php-encryption) -- current encryption method with AWS KMS or Azure Key Vault managed keys.

## Requirements
The library supports PHP 5.6, 7.4. Versions 7.1+ are supported through mcrypt polyfill.

## Usage
Entry point to the library is the `ObjectEncryptorFactory` class which creates instances of `ObjectEncryptor` class which
has `encrypt` and `decrypt` methods. The actual encryption and decryption mechanisms are implemented using **Crypto Wrappers**.
Crypto wrappers implement different verification methods using cypher metadata.

### Initialization
Initialize the library using the factory class:

```
$kmsKeyId = 'alias/my-key';
$kmsRegion = 'us-east-1';
$akvUrl = 'https://my-test.vault.azure.net
$keyVersion1 = '1234567890123456';
$keyVersion0 = '123456789012345678901234567890ab';
$factory = new ObjectEncryptorFactory($kmsKeyId, $kmsRegion, $keyVersion1, $keyVersion0);
```

Additional parameters may be set with `setComponentId`, `setConfigurationId`, `setProjectId` and `setStackId` methods.

### Wrappers
Depending on the provided keys and parameters, the following wrappers will be available:

- `Encryptor` - legacy decryptor for un-prefixed ciphers, requires `keyVersion0` 
- `BaseWrapper` - legacy wrapper for `KBC::Encrypted` ciphers, requires `keyVersion1`
- `ComponentWrapper` - legacy wrapper for `KBC::ComponentEncrypted==` ciphers, requires `keyVersion1` and `componentId`
- `ComponentProjectWrapper` - legacy wrapper for `KBC::ComponentProjectEncrypted==` ciphers, requires `keyVersion1` and `componentId` and `projectId`
- `GenericKMSWrapper` - current AWS wrapper for `KBC::Secure::` ciphers, requires `kmsKeyId` and `kmsRegion`. Also, the runner must have AWS credentials available (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- `ComponentKMSWrapper` - current AWS wrapper for `KBC::ComponentSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId` and `componentId`
- `ProjectKMSWrapper` - current AWS wrapper for `KBC::ProjectSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId`, `componentId` and `projectId`.
- `ConfigurationKMSWrapper` - current AWS wrapper for `KBC::ConfigSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId`, `componentId`, `projectId` and `configurationId`.
- `GenericAKVWrapper` - current Azure wrapper for `KBC::SecureKV::` ciphers, requires `akvUrl`. Also, the runner must have AWS credentials available (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- `ComponentAKVWrapper` - current Azure wrapper for `KBC::ComponentSecureKV::` ciphers, requires `akvUrl`, `stackId` and `componentId`
- `ProjectAKVWrapper` - current Azure wrapper for `KBC::ProjectSecureKV::` ciphers, requires `akvUrl`, `stackId`, `componentId` and `projectId`.
- `ConfigurationAKVWrapper` - current Azure wrapper for `KBC::ConfigSecureKV::` ciphers, requires `akvUrl`, `stackId`, `componentId`, `projectId` and `configurationId`.

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

## Development

### Azure
Create a resource group:

	az group create --name testing-object-encryptor --location "East US"

Create a service principal:

	az ad sp create-for-rbac --name testing-object-encryptor

Use the response to set values `TEST_CLIENT_ID`, `TEST_CLIENT_SECRET` and `TEST_TENANT_ID` in the `.env.` file:

```json	
{
  "appId": "268a6f05-xxxxxxxxxxxxxxxxxxxxxxxxxxx", //-> TEST_CLIENT_ID
  "displayName": "testing-azure-key-vault-php-client",
  "name": "http://testing-azure-key-vault-php-client",
  "password": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", //-> TEST_CLIENT_SECRET
  "tenant": "9b85ee6f-xxxxxxxxxxxxxxxxxxxxxxxxxxx" //-> TEST_TENANT_ID
}
```

Get ID of the service principal:

	az ad sp list --filter "displayname eq 'testing-object-sencryptor'" --query [].objectId

Get ID of a group to which the current user belongs (e.g. "Developers"):

	az ad group list --filter "displayname eq 'Developers'" --query [].objectId

Deploy the key vault, provide tenant ID, service principal ID and group ID from the previous commands:

	az deployment group create --resource-group testing-object-encryptor --template-file arm-template.json --parameters vault_name=testing-object-encryptor tenant_id=9b85ee6f-xxxxxxxxxxxxxxxxxxxxxxxxxxx service_principal_object_id=7f7a8a4c-xxxxxxxxxxxxxxxxxxxxxxxxxxx group_object_id=a1e8da73-xxxxxxxxxxxxxxxxxxxxxxxxxxx

Set the key vault URL - e.g. `https://testing-object-encryptor.vault.azure.net/` as `TEST_KEY_VAULT_URL` environment variable.

### AWS
Use the `test-cf-stack.json` CloudFormation template to create a new resource stack. Use the Stack outputs `KeyId` and `Region` to
set the environment values `TEST_AWS_KMS_KEY_ID` and `TEST_AWS_REGION` respectively. Go the user created by the stack (`ObjectEncryptorUser`) 
and generate new Access key (Security Credentials) for the user. Use it to set the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables.

### Run Tests
Run tests with:

    docker-compose --env-file=.env.local run tests56

or

    docker-compose --env-file=.env.local run tests74
