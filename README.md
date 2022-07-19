[![GitHub Actions](https://github.com/keboola/object-encryptor/actions/workflows/push.yml/badge.svg)](https://github.com/keboola/object-encryptor/actions/workflows/push.yml)

# Object Encryptor
Library provides interface for encrypting PHP arrays, stdclass objects and scalars. A cipher may contain additional metadata
which limits the conditions under which it may be decrypted. The library uses the 
[defuse/php-encryption](https://github.com/defuse/php-encryption) encryption method with AWS KMS or Azure Key 
Vault managed keys.

## Requirements
The library supports PHP 7.4+.

## Usage
Entry point to the library is the `ObjectEncryptorFactory` class which creates instances of `ObjectEncryptor` class which
has `encryptGeneric`, `encryptForComponent`, `encryptForProject`, `encryptForConfiguration` and corresponding `decryptXXX` 
methods. The actual encryption and decryption mechanisms are implemented using **Crypto Wrappers**.
Crypto wrappers implement different verification methods using cypher metadata.

### Usage
Initialize the library using the factory class:

```
$encryptor = ObjectEncryptorFactory::getEncryptor(
    new EncryptorOptions(
        'my-stack',
        $kmsKeyId,
        $kmsRegion,
        $akvUrl
    )
);
$encryptor->encryptForComponent('secret', 'my-component');
```

Alternatively, you can use `getAwsEncryptor` and `getAzureEncryptor` to get cloud specific object encryptors.

### Wrappers
Depending on the provided keys and parameters, the following wrappers will be available:

- `GenericKMSWrapper` - current AWS wrapper for `KBC::Secure::` ciphers, requires `kmsKeyId` and `kmsRegion`. Also, the runner must have AWS credentials available (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- `ComponentKMSWrapper` - current AWS wrapper for `KBC::ComponentSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId` and `componentId`
- `ProjectKMSWrapper` - current AWS wrapper for `KBC::ProjectSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId`, `componentId` and `projectId`.
- `ConfigurationKMSWrapper` - current AWS wrapper for `KBC::ConfigSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId`, `componentId`, `projectId` and `configurationId`.
- `GenericAKVWrapper` - current Azure wrapper for `KBC::SecureKV::` ciphers, requires `akvUrl`. Also, the runner must have AWS credentials available (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- `ComponentAKVWrapper` - current Azure wrapper for `KBC::ComponentSecureKV::` ciphers, requires `akvUrl`, `stackId` and `componentId`
- `ProjectAKVWrapper` - current Azure wrapper for `KBC::ProjectSecureKV::` ciphers, requires `akvUrl`, `stackId`, `componentId` and `projectId`.
- `ConfigurationAKVWrapper` - current Azure wrapper for `KBC::ConfigSecureKV::` ciphers, requires `akvUrl`, `stackId`, `componentId`, `projectId` and `configurationId`.

During encryption, the wrapper has to be specified (each `encryptXXX` method uses one). During decryption, 
the wrapper is chosen automatically by the cipher prefix. This means that `decryptForConfiguration` method is also
capable of decrypting ciphers created by `encryptForComponent` or `encryptForProject` ciphers. 
If the wrapper is not available (key or parameters are not set or equal to those in the cipher), 
the value cannot be deciphered and an exception is thrown.

## Development
Prerequisites:
* configured `az` and `aws` CLI tools (run `az login` and `aws configure --profile keboola-dev-platform-services`)
* installed `terraform` (https://www.terraform.io) and `jq` (https://stedolan.github.io/jq) to setup local env
* installed `docker` and `docker-compose` to run & develop the app

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
