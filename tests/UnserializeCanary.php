<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

/**
 * Detects whether a crafted cipher managed to make unserialize() instantiate a class.
 *
 * Both magic methods are needed. __wakeup() shows unserialize() built an instance, but the
 * gadget chains this protects against detonate from __destruct(), which fires even when the
 * wrapper's element-count guard rejects the payload - the object is released as the
 * exception unwinds. A canary with only __wakeup() would stay silent for a gadget class
 * that has just a destructor.
 *
 * With ['allowed_classes' => false] the payload decodes to __PHP_Incomplete_Class, so
 * neither method is ever called.
 */
class UnserializeCanary
{
    public static bool $wokenUp = false;

    public static bool $destructed = false;

    public static function reset(): void
    {
        self::$wokenUp = false;
        self::$destructed = false;
    }

    public function __wakeup(): void
    {
        self::$wokenUp = true;
    }

    public function __destruct()
    {
        self::$destructed = true;
    }
}
