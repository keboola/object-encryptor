[![GitHub Actions](https://github.com/keboola/object-encryptor/actions/workflows/push.yml/badge.svg)](https://github.com/keboola/object-encryptor/actions/workflows/push.yml)

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
Prerequisites:
* configured `az` and `aws` CLI tools (run `az login` and `aws configure --profile keboola-dev-platform-services`)
* installed `terraform` (https://www.terraform.io) and `jq` (https://stedolan.github.io/jq) to setup local env
* intalled `docker` and `docker-compose` to run & develop the app

```
cat <<EOF > ./provisioning/local/terraform.tfvars
name_prefix = "name" # your name/nickname to make your resource unique & recognizable
EOF

terraform -chdir=./provisioning/local init
terraform -chdir=./provisioning/local apply
./provisioning/local/update-env.sh aws # or azure

docker-compose run --rm tests
```

## License

MIT licensed, see [LICENSE](./LICENSE) file.
