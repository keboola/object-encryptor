<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

class EncryptorOptions
{
    private const DEFAULT_BACKOFF_MAX_TRIES = 3;

    /** @var non-empty-string|null */
    private ?string $kmsKeyId;
    /** @var non-empty-string|null */
    private ?string $kmsKeyRegion;
    /** @var non-empty-string|null */
    private ?string $akvUrl;
    /** @var non-empty-string|null */
    private ?string $gkmsKeyId;

    /** @var non-empty-string */
    private string $stackId;
    private ?string $kmsRole;
    private int $backoffMaxTries;

    /**
     * @param non-empty-string $stackId
     * @param non-empty-string|null $kmsKeyId
     * @param non-empty-string|null $kmsRegion
     * @param non-empty-string|null $kmsRole
     * @param non-empty-string|null $akvUrl
     * @param non-empty-string|null $gkmsKeyId
     * @param int|null $backoffMaxTries
     */
    public function __construct(
        string $stackId,
        ?string $kmsKeyId = null,
        ?string $kmsRegion = null,
        ?string $kmsRole = null,
        ?string $akvUrl = null,
        ?string $gkmsKeyId = null,
        ?int $backoffMaxTries = null,
    ) {
        $this->stackId = $stackId;
        $this->kmsKeyId = $kmsKeyId;
        $this->kmsKeyRegion = $kmsRegion;
        $this->kmsRole = $kmsRole;
        $this->akvUrl = $akvUrl;
        $this->gkmsKeyId = $gkmsKeyId;
        $this->backoffMaxTries = $backoffMaxTries ?? self::DEFAULT_BACKOFF_MAX_TRIES;
        $this->validateState();
    }

    /**
     * @return non-empty-string|null
     */
    public function getKmsKeyId(): ?string
    {
        return $this->kmsKeyId;
    }

    /**
     * @return non-empty-string|null
     */
    public function getKmsKeyRegion(): ?string
    {
        return $this->kmsKeyRegion;
    }

    public function getKmsRole(): ?string
    {
        return $this->kmsRole;
    }

    /**
     * @return non-empty-string|null
     */
    public function getAkvUrl(): ?string
    {
        return $this->akvUrl;
    }

    /**
     * @return non-empty-string|null
     */
    public function getGkmsKeyId(): ?string
    {
        return $this->gkmsKeyId;
    }

    /**
     * @return non-empty-string
     */
    public function getStackId(): string
    {
        return $this->stackId;
    }

    public function getBackoffMaxTries(): int
    {
        return $this->backoffMaxTries;
    }

    /**
     * @throws ApplicationException
     */
    private function validateState(): void
    {
        if (empty($this->kmsKeyId) && empty($this->kmsKeyRegion) && empty($this->akvUrl) && empty($this->gkmsKeyId)) {
            throw new ApplicationException('Neither AWS KMS, nor KeyVault, nor Google KMS is configured.');
        }
    }
}
