<?php

declare(strict_types=1);

namespace Keboola\ObjectEncryptor\Tests;

use Keboola\ObjectEncryptor\RegexHelper;
use PHPUnit\Framework\TestCase;

class RegexHelperTest extends TestCase
{
    /** @dataProvider validVariableValueProvider */
    public function testMatchesVariable(string $variableValue): void
    {
        self::assertTrue(RegexHelper::matchesVariable($variableValue));
    }

    public function validVariableValueProvider(): iterable
    {
        yield 'simple' => [
            'variableValue' => '{{ simple }}',
        ];

        yield 'shorty' => [
            'variableValue' => '{{ s }}',
        ];

        yield 'uppercase' => [
            'variableValue' => '{{ UPPERCASE }}',
        ];

        yield 'with underscore' => [
            'variableValue' => '{{ under_score }}',
        ];

        yield 'with dash' => [
            'variableValue' => '{{ en-dash }}',
        ];

        yield 'with prefix' => [
            'variableValue' => '{{ vault.en-dash }}',
        ];

        yield 'no whitespaces' => [
            'variableValue' => '{{nowhitespace}}',
        ];

        yield 'multiple spaces' => [
            'variableValue' => '{{    whitespace   }}',
        ];

        yield 'tabs as spaces' => [
            'variableValue' => "{{\twhitespace\t}}",
        ];

        yield 'everything' => [
            'variableValue' => '{{ Ev3_RY-th1n8 }}',
        ];

        yield 'just numbers' => [
            'variableValue' => '{{ 123 }}',
        ];

        yield 'starts with underscore' => [
            'variableValue' => '{{ _underscore }}',
        ];

        yield 'just underscore' => [
            'variableValue' => '{{ _ }}',
        ];

        yield 'just dash' => [
            'variableValue' => '{{ - }}',
        ];
    }

    /** @dataProvider invalidVariableValueProvider */
    public function testMatchesVariableInvalid(string $variableValue): void
    {
        self::assertFalse(RegexHelper::matchesVariable($variableValue));
    }

    public function invalidVariableValueProvider(): iterable
    {
        yield 'no braces' => [
            'variableValue' => 'nobraces',
        ];

        yield 'single brace' => [
            'variableValue' => '{ single }',
        ];

        yield 'three braces' => [
            'variableValue' => '{{{ three }}}',
        ];

        yield 'braces in braces' => [
            'variableValue' => '{{ {{inception}} }}',
        ];

        yield 'not matching braces' => [
            'variableValue' => '{{ nomatch }}}',
        ];

        yield 'not matching braces 2' => [
            'variableValue' => '{{{ nomatch }}',
        ];

        yield 'not matching braces 3' => [
            'variableValue' => '{{{{ nomatch }}',
        ];

        yield 'not matching braces 4' => [
            'variableValue' => '{{ nomatch }}}}',
        ];

        yield 'with something before braces' => [
            'variableValue' => 'something {{ value }}',
        ];

        yield 'with something after braces' => [
            'variableValue' => '{{ value }} something',
        ];

        yield 'whitespace in the middle' => [
            'variableValue' => '{{ white space }}',
        ];

        yield 'just empty' => [
            'variableValue' => '{{ }}',
        ];

        yield 'weird characters' => [
            'variableValue' => '{{ $var }}',
        ];

        yield 'weird characters 2' => [
            'variableValue' => '{{ &var }}',
        ];

        yield 'weird characters 3' => [
            'variableValue' => '{{ var% }}',
        ];
    }
}
