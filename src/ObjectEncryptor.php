<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor;

use Aws\Kms\KmsClient;
use Google\Cloud\Kms\V1\KeyManagementServiceClient;
use Keboola\ObjectEncryptor\Exception\ApplicationException;
use Keboola\ObjectEncryptor\Exception\UserException;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeConfigurationGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeConfigurationKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeProjectGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeProjectKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeProjectWideAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeProjectWideGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\BranchTypeProjectWideKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ComponentKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ConfigurationKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\CryptoWrapperInterface;
use Keboola\ObjectEncryptor\Wrapper\GenericAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\GenericKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\GkmsClientFactory;
use Keboola\ObjectEncryptor\Wrapper\KmsClientFactory;
use Keboola\ObjectEncryptor\Wrapper\ProjectAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectWideAKVWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectWideGKMSWrapper;
use Keboola\ObjectEncryptor\Wrapper\ProjectWideKMSWrapper;
use stdClass;
use Throwable;

class ObjectEncryptor
{
    public const BRANCH_TYPE_DEFAULT = 'default';
    public const BRANCH_TYPE_DEV = 'dev';

    private EncryptorOptions $encryptorOptions;
    private ?KmsClient $kmsClient = null;
    private ?KeyManagementServiceClient $gkmsClient = null;

    public function __construct(EncryptorOptions $encryptorOptions)
    {
        $this->encryptorOptions = $encryptorOptions;
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function encryptGeneric($data)
    {
        if ($this->encryptorOptions->getAkvUrl()) {
            $className = GenericAKVWrapper::class;
        } elseif ($this->encryptorOptions->getGkmsKeyId()) {
            $className = GenericGKMSWrapper::class;
        } else {
            $className = GenericKMSWrapper::class;
        }

        $wrappers = $this->getWrappers(null, null, null, null);
        return $this->encrypt($data, $wrappers, $className);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function encryptForComponent($data, string $componentId)
    {
        if ($this->encryptorOptions->getAkvUrl()) {
            $className = ComponentAKVWrapper::class;
        } elseif ($this->encryptorOptions->getGkmsKeyId()) {
            $className = ComponentGKMSWrapper::class;
        } else {
            $className = ComponentKMSWrapper::class;
        }

        $wrappers = $this->getWrappers($componentId, null, null, null);
        return $this->encrypt($data, $wrappers, $className);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function encryptForProject($data, string $componentId, string $projectId)
    {
        if ($this->encryptorOptions->getAkvUrl()) {
            $className = ProjectAKVWrapper::class;
        } elseif ($this->encryptorOptions->getGkmsKeyId()) {
            $className = ProjectGKMSWrapper::class;
        } else {
            $className = ProjectKMSWrapper::class;
        }

        $wrappers = $this->getWrappers($componentId, $projectId, null, null);
        return $this->encrypt($data, $wrappers, $className);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function encryptForConfiguration($data, string $componentId, string $projectId, string $configurationId)
    {
        if ($this->encryptorOptions->getAkvUrl()) {
            $className = ConfigurationAKVWrapper::class;
        } elseif ($this->encryptorOptions->getGkmsKeyId()) {
            $className = ConfigurationGKMSWrapper::class;
        } else {
            $className = ConfigurationKMSWrapper::class;
        }

        $wrappers = $this->getWrappers($componentId, $projectId, $configurationId, null);
        return $this->encrypt($data, $wrappers, $className);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function encryptForProjectWide($data, string $projectId)
    {
        if ($this->encryptorOptions->getAkvUrl()) {
            $className = ProjectWideAKVWrapper::class;
        } elseif ($this->encryptorOptions->getGkmsKeyId()) {
            $className = ProjectWideGKMSWrapper::class;
        } else {
            $className = ProjectWideKMSWrapper::class;
        }

        $wrappers = $this->getWrappers(null, $projectId, null, null);
        return $this->encrypt($data, $wrappers, $className);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @param self::BRANCH_TYPE_DEFAULT | self::BRANCH_TYPE_DEV $branchType
     * @return T
     */
    public function encryptForBranchType($data, string $componentId, string $projectId, string $branchType)
    {
        if ($this->encryptorOptions->getAkvUrl()) {
            $className = BranchTypeProjectAKVWrapper::class;
        } elseif ($this->encryptorOptions->getGkmsKeyId()) {
            $className = BranchTypeProjectGKMSWrapper::class;
        } else {
            $className = BranchTypeProjectKMSWrapper::class;
        }

        $wrappers = $this->getWrappers($componentId, $projectId, null, $branchType);
        return $this->encrypt($data, $wrappers, $className);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @param self::BRANCH_TYPE_DEFAULT | self::BRANCH_TYPE_DEV $branchType
     * @return T
     */
    public function encryptForBranchTypeConfiguration(
        $data,
        string $componentId,
        string $projectId,
        string $configurationId,
        string $branchType,
    ) {
        if ($this->encryptorOptions->getAkvUrl()) {
            $className = BranchTypeConfigurationAKVWrapper::class;
        } elseif ($this->encryptorOptions->getGkmsKeyId()) {
            $className = BranchTypeConfigurationGKMSWrapper::class;
        } else {
            $className = BranchTypeConfigurationKMSWrapper::class;
        }

        $wrappers = $this->getWrappers($componentId, $projectId, $configurationId, $branchType);
        return $this->encrypt($data, $wrappers, $className);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @param self::BRANCH_TYPE_DEFAULT | self::BRANCH_TYPE_DEV $branchType
     * @return T
     */
    public function encryptForProjectWideBranchType($data, string $projectId, string $branchType)
    {
        if ($this->encryptorOptions->getAkvUrl()) {
            $className = BranchTypeProjectWideAKVWrapper::class;
        } elseif ($this->encryptorOptions->getGkmsKeyId()) {
            $className = BranchTypeProjectWideGKMSWrapper::class;
        } else {
            $className = BranchTypeProjectWideKMSWrapper::class;
        }

        $wrappers = $this->getWrappers(null, $projectId, null, $branchType);
        return $this->encrypt($data, $wrappers, $className);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function decryptGeneric($data)
    {
        $wrappers = $this->getWrappers(null, null, null, null);
        return $this->decrypt($data, $wrappers);
    }


    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function decryptForComponent($data, string $componentId)
    {
        $wrappers = $this->getWrappers($componentId, null, null, null);
        return $this->decrypt($data, $wrappers);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function decryptForProject($data, string $componentId, string $projectId)
    {
        $wrappers = $this->getWrappers($componentId, $projectId, null, null);
        return $this->decrypt($data, $wrappers);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function decryptForConfiguration($data, string $componentId, string $projectId, string $configurationId)
    {
        $wrappers = $this->getWrappers($componentId, $projectId, $configurationId, null);
        return $this->decrypt($data, $wrappers);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     */
    public function decryptForProjectWide($data, string $projectId)
    {
        $wrappers = $this->getWrappers(null, $projectId, null, null);
        return $this->decrypt($data, $wrappers);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @param self::BRANCH_TYPE_DEFAULT | self::BRANCH_TYPE_DEV $branchType
     * @return T
     */
    public function decryptForBranchType($data, string $componentId, string $projectId, string $branchType)
    {
        $wrappers = $this->getWrappers($componentId, $projectId, null, $branchType);
        return $this->decrypt($data, $wrappers);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @param self::BRANCH_TYPE_DEFAULT | self::BRANCH_TYPE_DEV $branchType
     * @return T
     */
    public function decryptForBranchTypeConfiguration(
        $data,
        string $componentId,
        string $projectId,
        string $configurationId,
        string $branchType,
    ) {
        $wrappers = $this->getWrappers($componentId, $projectId, $configurationId, $branchType);
        return $this->decrypt($data, $wrappers);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @param self::BRANCH_TYPE_DEFAULT | self::BRANCH_TYPE_DEV $branchType
     * @return T
     */
    public function decryptForProjectWideBranchType($data, string $projectId, string $branchType)
    {
        $wrappers = $this->getWrappers(null, $projectId, null, $branchType);
        return $this->decrypt($data, $wrappers);
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data Data to encrypt
     * @return T
     * @throws ApplicationException
     * @throws UserException
     */
    private function encrypt($data, array $wrappers, string $wrapperName)
    {
        foreach ($wrappers as $cryptoWrapper) {
            if (get_class($cryptoWrapper) === $wrapperName) {
                $wrapper = $cryptoWrapper;
                break;
            }
        }
        /** @var CryptoWrapperInterface $wrapper */
        if (empty($wrapper)) {
            throw new ApplicationException('Invalid crypto wrapper ' . $wrapperName);
        }
        if (is_scalar($data)) {
            return $this->encryptValue((string) $data, $wrappers, $wrapper);
        }
        if (is_array($data)) {
            return $this->encryptArray($data, $wrappers, $wrapper);
        }
        if ($data instanceof stdClass) {
            return $this->encryptObject($data, $wrappers, $wrapper);
        }
        // @phpstan-ignore-next-line
        throw new ApplicationException('Only stdClass, array and string are supported types for encryption.');
    }

    /**
     * @template T of array|stdClass|string
     * @param T $data
     * @return T
     * @throws ApplicationException
     * @throws UserException
     */
    private function decrypt($data, array $wrappers)
    {
        if (is_scalar($data)) {
            return $this->decryptValue($data, $wrappers);
        }
        if (is_array($data)) {
            return $this->decryptArray($data, $wrappers);
        }
        if ($data instanceof stdClass) {
            return $this->decryptObject($data, $wrappers);
        }
        // @phpstan-ignore-next-line
        throw new ApplicationException('Only stdClass, array and string are supported types for decryption.');
    }

    private function findWrapper(string $value, array $wrappers): ?CryptoWrapperInterface
    {
        $selectedWrapper = null;
        foreach ($wrappers as $wrapper) {
            if (str_starts_with($value, $wrapper->getPrefix())) {
                $selectedWrapper = $wrapper;
            }
        }
        return $selectedWrapper;
    }

    private function decryptValue(string $value, array $wrappers): string
    {
        if (RegexHelper::matchesVariable($value)) {
            return $value;
        }

        $wrapper = $this->findWrapper($value, $wrappers);
        if (!$wrapper) {
            throw new UserException(sprintf('Value "%s" is not an encrypted value.', $value), 0);
        } else {
            try {
                return $wrapper->decrypt(substr($value, mb_strlen($wrapper->getPrefix())));
            } catch (UserException $e) {
                throw new UserException(sprintf('Value "%s" is not an encrypted value.', $value), $e->getCode(), $e);
            } catch (Throwable $e) {
                // decryption failed for more serious reasons
                throw new ApplicationException('Decryption failed: ' . $e->getMessage(), $e->getCode(), $e);
            }
        }
    }

    /**
     * @param string|int $key
     * @param mixed $value Value to encrypt.
     * @return array|bool|float|int|stdClass|string|null
     */
    private function encryptItem($key, $value, array $wrappers, CryptoWrapperInterface $wrapper)
    {
        if (is_scalar($value) || is_null($value)) {
            if (str_starts_with((string) $key, '#')) {
                return $this->encryptValue((string) $value, $wrappers, $wrapper);
            } else {
                return $value;
            }
        } elseif (is_array($value)) {
            return $this->encryptArray($value, $wrappers, $wrapper);
        } elseif ($value instanceof stdClass) {
            return $this->encryptObject($value, $wrappers, $wrapper);
        } else {
            throw new ApplicationException(
                'Invalid item $key - only stdClass, array and scalar can be encrypted.',
            );
        }
    }

    private function getKnownWrapperPrefixes(): array
    {
        return [
            GenericAKVWrapper::getPrefix(),
            GenericGKMSWrapper::getPrefix(),
            GenericKMSWrapper::getPrefix(),
            ComponentAKVWrapper::getPrefix(),
            ComponentGKMSWrapper::getPrefix(),
            ComponentKMSWrapper::getPrefix(),
            ProjectAKVWrapper::getPrefix(),
            ProjectGKMSWrapper::getPrefix(),
            ProjectKMSWrapper::getPrefix(),
            ConfigurationAKVWrapper::getPrefix(),
            ConfigurationGKMSWrapper::getPrefix(),
            ConfigurationKMSWrapper::getPrefix(),
            ProjectWideAKVWrapper::getPrefix(),
            ProjectWideGKMSWrapper::getPrefix(),
            ProjectWideKMSWrapper::getPrefix(),
            BranchTypeProjectAKVWrapper::getPrefix(),
            BranchTypeProjectGKMSWrapper::getPrefix(),
            BranchTypeProjectKMSWrapper::getPrefix(),
            BranchTypeProjectWideAKVWrapper::getPrefix(),
            BranchTypeProjectWideGKMSWrapper::getPrefix(),
            BranchTypeProjectWideKMSWrapper::getPrefix(),
            BranchTypeConfigurationAKVWrapper::getPrefix(),
            BranchTypeConfigurationGKMSWrapper::getPrefix(),
            BranchTypeConfigurationKMSWrapper::getPrefix(),
            // legacy wrappers that are no longer implemented, but still exist in the real world
            'KBC::Encrypted==',
            'KBC::ComponentEncrypted==',
            'KBC::ComponentProjectEncrypted==',
        ];
    }

    private function isKnownWrapper(string $value): bool
    {
        foreach ($this->getKnownWrapperPrefixes() as $prefix) {
            if (str_starts_with($value, $prefix)) {
                return true;
            }
        }
        return false;
    }

    private function encryptValue(string $value, array $wrappers, CryptoWrapperInterface $wrapper): string
    {
        if (RegexHelper::matchesVariable($value)) {
            return $value;
        }

        // return self if already encrypted with any wrapper
        if ($this->isKnownWrapper($value)) {
            return $value;
        }

        try {
            return $wrapper->getPrefix() . $wrapper->encrypt($value);
        } catch (Throwable $e) {
            throw new ApplicationException('Encryption failed: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }

    private function encryptArray(array $data, array $wrappers, CryptoWrapperInterface $wrapper): array
    {
        $result = [];
        foreach ($data as $key => $value) {
            $result[$key] = $this->encryptItem($key, $value, $wrappers, $wrapper);
        }
        return $result;
    }

    private function encryptObject(stdClass $data, array $wrappers, CryptoWrapperInterface $wrapper): stdClass
    {
        $result = new stdClass();
        foreach (get_object_vars($data) as $key => $value) {
            $result->{$key} = $this->encryptItem($key, $value, $wrappers, $wrapper);
        }
        return $result;
    }

    /**
     * @param string|int $key
     * @param mixed $value Value to decrypt.
     * @return array|bool|float|int|stdClass|string|null Decrypted value.
     */
    private function decryptItem($key, $value, array $wrappers)
    {
        if (is_scalar($value) || is_null($value)) {
            if (substr((string) $key, 0, 1) === '#') {
                try {
                    return $this->decryptValue((string) $value, $wrappers);
                } catch (UserException $e) {
                    throw new UserException("Invalid cipher text for key $key " . $e->getMessage(), $e->getCode(), $e);
                }
            } else {
                return $value;
            }
        } elseif (is_array($value)) {
            return $this->decryptArray($value, $wrappers);
        } elseif ($value instanceof stdClass) {
            return $this->decryptObject($value, $wrappers);
        } else {
            throw new ApplicationException(
                "Invalid item $key - only stdClass, array and scalar can be decrypted.",
            );
        }
    }

    private function decryptObject(stdClass $data, array $wrappers): stdClass
    {
        $result = new stdClass();
        foreach (get_object_vars($data) as $key => $value) {
            $result->{$key} = $this->decryptItem($key, $value, $wrappers);
        }
        return $result;
    }

    private function decryptArray(array $data, array $wrappers): array
    {
        $result = [];
        foreach ($data as $key => $value) {
            $result[$key] = $this->decryptItem($key, $value, $wrappers);
        }
        return $result;
    }

    /**
     * @param self::BRANCH_TYPE_DEFAULT | self::BRANCH_TYPE_DEV | null $branchType
     */
    private function getKMSWrappers(
        ?string $componentId,
        ?string $projectId,
        ?string $configurationId,
        ?string $branchType,
    ): array {
        if ($this->kmsClient === null) {
            $this->kmsClient = (new KmsClientFactory())->createClient($this->encryptorOptions);
        }

        $wrappers = [];
        $wrapper = new GenericKMSWrapper($this->kmsClient, $this->encryptorOptions);
        $wrappers[] = $wrapper;

        if ($this->encryptorOptions->getStackId()) {
            if ($projectId) {
                $wrapper = new ProjectWideKMSWrapper($this->kmsClient, $this->encryptorOptions);
                $wrapper->setProjectId($projectId);
                $wrappers[] = $wrapper;
                if ($branchType) {
                    $wrapper = new BranchTypeProjectWideKMSWrapper($this->kmsClient, $this->encryptorOptions);
                    $wrapper->setProjectId($projectId);
                    $wrapper->setBranchType($branchType);
                    $wrappers[] = $wrapper;
                }
            }
            if ($componentId) {
                $wrapper = new ComponentKMSWrapper($this->kmsClient, $this->encryptorOptions);
                $wrapper->setComponentId($componentId);
                $wrappers[] = $wrapper;
                if ($projectId) {
                    $wrapper = new ProjectKMSWrapper($this->kmsClient, $this->encryptorOptions);
                    $wrapper->setComponentId($componentId);
                    $wrapper->setProjectId($projectId);
                    $wrappers[] = $wrapper;
                    if ($configurationId) {
                        $wrapper = new ConfigurationKMSWrapper($this->kmsClient, $this->encryptorOptions);
                        $wrapper->setComponentId($componentId);
                        $wrapper->setProjectId($projectId);
                        $wrapper->setConfigurationId($configurationId);
                        $wrappers[] = $wrapper;
                        if ($branchType) {
                            $wrapper = new BranchTypeConfigurationKMSWrapper($this->kmsClient, $this->encryptorOptions);
                            $wrapper->setComponentId($componentId);
                            $wrapper->setProjectId($projectId);
                            $wrapper->setConfigurationId($configurationId);
                            $wrapper->setBranchType($branchType);
                            $wrappers[] = $wrapper;
                        }
                    }
                    if ($branchType) {
                        $wrapper = new BranchTypeProjectKMSWrapper($this->kmsClient, $this->encryptorOptions);
                        $wrapper->setComponentId($componentId);
                        $wrapper->setProjectId($projectId);
                        $wrapper->setBranchType($branchType);
                        $wrappers[] = $wrapper;
                    }
                }
            }
        }
        return $wrappers;
    }

    /**
     * @param self::BRANCH_TYPE_DEFAULT | self::BRANCH_TYPE_DEV | null $branchType
     */
    private function getAKVWrappers(
        ?string $componentId,
        ?string $projectId,
        ?string $configurationId,
        ?string $branchType,
    ): array {
        $wrappers = [];
        $wrapper = new GenericAKVWrapper($this->encryptorOptions);
        $wrappers[] = $wrapper;
        if ($this->encryptorOptions->getStackId()) {
            if ($projectId) {
                $wrapper = new ProjectWideAKVWrapper($this->encryptorOptions);
                $wrapper->setProjectId($projectId);
                $wrappers[] = $wrapper;
                if ($branchType) {
                    $wrapper = new BranchTypeProjectWideAKVWrapper($this->encryptorOptions);
                    $wrapper->setProjectId($projectId);
                    $wrapper->setBranchType($branchType);
                    $wrappers[] = $wrapper;
                }
            }
            if ($componentId) {
                $wrapper = new ComponentAKVWrapper($this->encryptorOptions);
                $wrapper->setComponentId($componentId);
                $wrappers[] = $wrapper;
                if ($projectId) {
                    $wrapper = new ProjectAKVWrapper($this->encryptorOptions);
                    $wrapper->setComponentId($componentId);
                    $wrapper->setProjectId($projectId);
                    $wrappers[] = $wrapper;
                    if ($configurationId) {
                        $wrapper = new ConfigurationAKVWrapper($this->encryptorOptions);
                        $wrapper->setComponentId($componentId);
                        $wrapper->setProjectId($projectId);
                        $wrapper->setConfigurationId($configurationId);
                        $wrappers[] = $wrapper;
                        if ($branchType) {
                            $wrapper = new BranchTypeConfigurationAKVWrapper($this->encryptorOptions);
                            $wrapper->setComponentId($componentId);
                            $wrapper->setProjectId($projectId);
                            $wrapper->setConfigurationId($configurationId);
                            $wrapper->setBranchType($branchType);
                            $wrappers[] = $wrapper;
                        }
                    }
                    if ($branchType) {
                        $wrapper = new BranchTypeProjectAKVWrapper($this->encryptorOptions);
                        $wrapper->setComponentId($componentId);
                        $wrapper->setProjectId($projectId);
                        $wrapper->setBranchType($branchType);
                        $wrappers[] = $wrapper;
                    }
                }
            }
        }
        return $wrappers;
    }

    /**
     * @param self::BRANCH_TYPE_DEFAULT | self::BRANCH_TYPE_DEV | null $branchType
     */
    private function getGMKSWrappers(
        ?string $componentId,
        ?string $projectId,
        ?string $configurationId,
        ?string $branchType,
    ): array {
        if ($this->gkmsClient === null) {
            $this->gkmsClient = (new GkmsClientFactory())->createClient($this->encryptorOptions);
        }

        $wrappers = [];
        $wrapper = new GenericGKMSWrapper($this->gkmsClient, $this->encryptorOptions);
        $wrappers[] = $wrapper;

        if ($this->encryptorOptions->getStackId()) {
            if ($projectId) {
                $wrapper = new ProjectWideGKMSWrapper($this->gkmsClient, $this->encryptorOptions);
                $wrapper->setProjectId($projectId);
                $wrappers[] = $wrapper;
                if ($branchType) {
                    $wrapper = new BranchTypeProjectWideGKMSWrapper($this->gkmsClient, $this->encryptorOptions);
                    $wrapper->setProjectId($projectId);
                    $wrapper->setBranchType($branchType);
                    $wrappers[] = $wrapper;
                }
            }
            if ($componentId) {
                $wrapper = new ComponentGKMSWrapper($this->gkmsClient, $this->encryptorOptions);
                $wrapper->setComponentId($componentId);
                $wrappers[] = $wrapper;
                if ($projectId) {
                    $wrapper = new ProjectGKMSWrapper($this->gkmsClient, $this->encryptorOptions);
                    $wrapper->setComponentId($componentId);
                    $wrapper->setProjectId($projectId);
                    $wrappers[] = $wrapper;
                    if ($configurationId) {
                        $wrapper = new ConfigurationGKMSWrapper($this->gkmsClient, $this->encryptorOptions);
                        $wrapper->setComponentId($componentId);
                        $wrapper->setProjectId($projectId);
                        $wrapper->setConfigurationId($configurationId);
                        $wrappers[] = $wrapper;
                        if ($branchType) {
                            $wrapper = new BranchTypeConfigurationGKMSWrapper(
                                $this->gkmsClient,
                                $this->encryptorOptions,
                            );
                            $wrapper->setComponentId($componentId);
                            $wrapper->setProjectId($projectId);
                            $wrapper->setConfigurationId($configurationId);
                            $wrapper->setBranchType($branchType);
                            $wrappers[] = $wrapper;
                        }
                    }
                    if ($branchType) {
                        $wrapper = new BranchTypeProjectGKMSWrapper($this->gkmsClient, $this->encryptorOptions);
                        $wrapper->setComponentId($componentId);
                        $wrapper->setProjectId($projectId);
                        $wrapper->setBranchType($branchType);
                        $wrappers[] = $wrapper;
                    }
                }
            }
        }

        return $wrappers;
    }

    /**
     * @param self::BRANCH_TYPE_DEFAULT | self::BRANCH_TYPE_DEV | null $branchType
     */
    private function getWrappers(
        ?string $componentId,
        ?string $projectId,
        ?string $configurationId,
        ?string $branchType,
    ): array {
        $wrappers = [];
        if ($this->encryptorOptions->getAkvUrl()) {
            $wrappers = array_merge(
                $wrappers,
                $this->getAKVWrappers($componentId, $projectId, $configurationId, $branchType),
            );
        }

        if ($this->encryptorOptions->getGkmsKeyId()) {
            $wrappers = array_merge(
                $wrappers,
                $this->getGMKSWrappers($componentId, $projectId, $configurationId, $branchType),
            );
        }

        if ($this->encryptorOptions->getKmsKeyRegion() && $this->encryptorOptions->getKmsKeyId()) {
            $wrappers = array_merge(
                $wrappers,
                $this->getKMSWrappers($componentId, $projectId, $configurationId, $branchType),
            );
        }
        return $wrappers;
    }
}
