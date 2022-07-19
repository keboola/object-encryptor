<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

class EncryptorOptions
{
    private ?string $kmsKeyId;
    private ?string $kmsKeyRegion;
    private ?string $akvUrl;
    private string $stackId;

    public function __construct(string $stackId, ?string $kmsKeyId, ?string $kmsRegion, ?string $akvUrl)
    {
        $this->stackId = $stackId;
        $this->kmsKeyId = $kmsKeyId;
        $this->kmsKeyRegion = $kmsRegion;
        $this->akvUrl = $akvUrl;
        $this->validateState();
    }

    public function getKmsKeyId(): ?string
    {
        return $this->kmsKeyId;
    }

    public function getKmsKeyRegion(): ?string
    {
        return $this->kmsKeyRegion;
    }

    public function getAkvUrl(): ?string
    {
        return $this->akvUrl;
    }

    public function getStackId(): string
    {
        return $this->stackId;
    }

    /**
     * @throws ApplicationException
     */
    private function validateState(): void
    {
        if (empty($this->stackId)) {
            throw new ApplicationException('Stack Id must not be empty.');
        }
        if (empty($this->kmsKeyId) && empty($this->kmsKeyRegion) && empty($this->akvUrl)) {
            throw new ApplicationException('Neither KMS, nor KeyVault configured.');
        }
    }
}
