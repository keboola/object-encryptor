<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

/**
 * Detects whether a crafted cipher managed to make unserialize() instantiate a class.
 *
 * __wakeup() is invoked by unserialize() only when it actually builds an instance of this
 * class, so it never fires for the instance the test creates when building the payload.
 * With ['allowed_classes' => false] the payload decodes to __PHP_Incomplete_Class instead
 * and __wakeup() is never called.
 */
class UnserializeCanary
{
    public static bool $wokenUp = false;

    public static function reset(): void
    {
        self::$wokenUp = false;
    }

    public function __wakeup(): void
    {
        self::$wokenUp = true;
    }
}
