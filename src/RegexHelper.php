<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

class RegexHelper
{
    public static function matchesVariable(string $value): bool
    {
        $regex = '/^{{\s?[a-zA-Z][a-zA-Z0-9_\-]*\s?}}$/';
        $result = preg_match($regex, $value);

        if ($result === false) {
            throw new ApplicationException(
                sprintf('Variable regex matching error "%s"', preg_last_error_msg())
            );
        }

        return (bool) $result;
    }
}
