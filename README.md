[![GitHub Actions](https://github.com/keboola/object-encryptor/actions/workflows/push.yml/badge.svg)](https://github.com/keboola/object-encryptor/actions/workflows/push.yml)

# Object Encryptor
Library provides interface for encrypting PHP arrays, stdclass objects and scalars. A cipher may contain additional metadata
which limits the conditions under which it may be decrypted. The library uses the 
[defuse/php-encryption](https://github.com/defuse/php-encryption) encryption method with AWS KMS or Azure Key 
Vault managed keys or Google Cloud KMS.

## Requirements
The library supports PHP 8.1+.

## Usage
Entry point to the library is the `ObjectEncryptorFactory` class which creates instances of `ObjectEncryptor` class which
has `encryptGeneric`, `encryptForComponent`, `encryptForProject`, `encryptForConfiguration`, `encryptForProjectWide` 
`encryptForBranchType`, `encryptForBranchTypeConfiguration`, `encryptForProjectWideBranchType` and corresponding `decryptXXX` 
methods. The actual encryption and decryption mechanisms are implemented using **Crypto Wrappers**.
Crypto wrappers implement different verification methods using cypher metadata.

### Usage
Initialize the library using the factory class:

```php
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

Alternatively, you can use `getAwsEncryptor` and `getAzureEncryptor` and `getGcpEncryptor` to get cloud specific object encryptors.

### Wrappers
Depending on the provided keys and parameters, the following wrappers will be available:

- `GenericKMSWrapper` - AWS KMS wrapper for `KBC::Secure::` ciphers, requires `kmsKeyId` and `kmsRegion`. Also, the runner must have AWS credentials available (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- `ComponentKMSWrapper` - AWS KMS wrapper for `KBC::ComponentSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId` and `componentId`
- `ProjectKMSWrapper` - AWS KMS wrapper for `KBC::ProjectSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId`, `componentId` and `projectId`.
- `ConfigurationKMSWrapper` - AWS KMS wrapper for `KBC::ConfigSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId`, `componentId`, `projectId` and `configurationId`.
- `ProjectWideKMSWrapper` - AWS KMS wrapper `KBC::ProjectWideSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId`, and `projectId`.
- `BranchTypeProjectKMSWrapper` - AWS KMS wrapper `KBC::BranchTypeSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId`, `componentId`, projectId` and `branchType`.
- `BranchTypeConfigurationKMSWrapper` - AWS KMS wrapper `KBC::BranchTypeConfigSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId`, `componentId`, `projectId`, `configurationId` and `branchType`.
- `BranchTypeProjectWideKMSWrapper` - AWS KMS wrapper `KBC::ProjectWideBranchTypeSecure::` ciphers, requires `kmsKeyId`, `kmsRegion`, `stackId`, `projectId` and `branchType`.
- `GenericAKVWrapper` - Azure Key Vault wrapper for `KBC::SecureKV::` ciphers, requires `akvUrl`. Also, the runner must have AWS credentials available (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- `ComponentAKVWrapper` - Azure Key Vault wrapper for `KBC::ComponentSecureKV::` ciphers, requires `akvUrl`, `stackId` and `componentId`
- `ProjectAKVWrapper` - Azure Key Vault wrapper for `KBC::ProjectSecureKV::` ciphers, requires `akvUrl`, `stackId`, `componentId` and `projectId`.
- `ConfigurationAKVWrapper` - Azure Key Vault wrapper for `KBC::ConfigSecureKV::` ciphers, requires `akvUrl`, `stackId`, `componentId`, `projectId` and `configurationId`.
- `ProjectWideAKVWrapper` - Azure Key Vault wrapper `KBC::ProjectWideSecureKV::` ciphers, requires `akvUrl`, `stackId`, and `projectId`.
- `BranchTypeProjectAKVWrapper` - Azure Key Vault wrapper `KBC::BranchTypeSecureKV::` ciphers, requires `akvUrl`, `stackId`, `componentId`, projectId` and `branchType`.
- `BranchTypeConfigurationAKVWrapper` - Azure Key Vault wrapper `KBC::BranchTypeConfigSecureKV::` ciphers, requires `akvUrl`, `stackId`, `componentId`, `projectId`, `configurationId` and `branchType`.
- `BranchTypeProjectWideAKVWrapper` - Azure Key Vault wrapper `KBC::ProjectWideBranchTypeSecureKV::` ciphers, requires `akvUrl`, `stackId`, `projectId` and `branchType`.
- `GenericGKMSWrapper` - Google KMS wrapper for `KBC::SecureGKMS::` ciphers, requires `gkmsKeyId`. Also, the runner must have AWS credentials available (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- `ComponentGKMSWrapper` - Google KMS wrapper for `KBC::ComponentSecureGKMS::` ciphers, requires `gkmsKeyId`, `stackId` and `componentId`
- `ProjectGKMSWrapper` - Google KMS wrapper for `KBC::ProjectSecureGKMS::` ciphers, requires `gkmsKeyId`, `stackId`, `componentId` and `projectId`.
- `ConfigurationGKMSWrapper` - Google KMS wrapper for `KBC::ConfigSecureGKMS::` ciphers, requires `gkmsKeyId`, `stackId`, `componentId`, `projectId` and `configurationId`.
- `ProjectWideGKMSWrapper` - Google KMS wrapper `KBC::ProjectWideSecureGKMS::` ciphers, requires `gkmsKeyId`, `stackId`, and `projectId`.
- `BranchTypeProjectGKMSWrapper` - Google KMS wrapper `KBC::BranchTypeSecureGKMS::` ciphers, requires `gkmsKeyId`, `stackId`, `componentId`, projectId` and `branchType`.
- `BranchTypeConfigurationGKMSWrapper` - Google KMS wrapper `KBC::BranchTypeConfigSecureGKMS::` ciphers, requires `gkmsKeyId`, `stackId`, `componentId`, `projectId`, `configurationId` and `branchType`.
- `BranchTypeProjectWideGKMSWrapper` - Google KMS wrapper `KBC::ProjectWideBranchTypeSecureGKMS::` ciphers, requires `gkmsKeyId`, `stackId`, `projectId` and `branchType`.

During encryption, the wrapper has to be specified (each `encryptXXX` method uses one). During decryption, 
the wrapper is chosen automatically by the cipher prefix. This means that `decryptForConfiguration` method is also
capable of decrypting ciphers created by `encryptForComponent` or `encryptForProject` ciphers. 
If the wrapper is not available (key or parameters are not set or equal to those in the cipher), 
the value cannot be deciphered and an exception is thrown.

## Development
Prerequisites:
* configured access to cloud providers
  * installed Azure CLI `az` (and run `az login`) 
  * installed AWS CLI `aws` (and run `aws configure --profile YOUR_AWS_PROFILE_NAME`)
  * installed GCP CLI `gcloud` (and run `gcloud auth login` or `gcloud auth application-default login`)
* installed `terraform` (https://www.terraform.io) and `jq` (https://stedolan.github.io/jq) to setup local env
* installed `docker` and `docker-compose` to run & develop the app

```bash
export NAME_PREFIX= # your name/nickname to make your resource unique & recognizable
export AWS_PROFILE= # your AWS profile name e.g. Keboola-Dev-Platform-Services-AWSAdministratorAccess

cat <<EOF > ./provisioning/local/terraform.tfvars
name_prefix = "${NAME_PREFIX}"
EOF

terraform -chdir=./provisioning/local init -backend-config="key=object-encryptor/${NAME_PREFIX}.tfstate"
terraform -chdir=./provisioning/local apply
./provisioning/local/update-env.sh aws # or azure or gcp

docker-compose run --rm tests
```

## License

MIT licensed, see [LICENSE](./LICENSE) file.
