<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor;

use Keboola\ObjectEncryptor\Exception\ApplicationException;

class RegexHelper
{
    public static function matchesVariable(string $value): bool
    {
        // based on https://github.com/keboola/platform-libraries/blob/main/libs/configuration-variables-resolver/src/VariablesRenderer/RegexRenderer.php#L32
        // (?<!{) - do not match more than two opening braces
        // {{\s* - match opening braces and optional whitespaces
        // [a-zA-Z0-9_\-.]+ - match variable name (including prefix if supplied)
        // \s*}} - match optional whitespaces and closing braces
        $regex = '/^(?<!{){{\s*[a-zA-Z0-9_\-.]+\s*}}$/';
        $result = preg_match($regex, $value);

        if ($result === false) {
            throw new ApplicationException(
                sprintf('Variable regex matching error "%s"', preg_last_error_msg()),
            );
        }

        return (bool) $result;
    }
}
