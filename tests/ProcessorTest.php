<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Patchstack\Processor;
use Patchstack\Extensions\Test\Extension;

final class ProcessorTest extends TestCase
{
    /**
     * @var Processor
     */
    protected $processor;

    /**
     * @var array
     */
    protected $rules;

    /**
     * Setup the test for testing the header location redirect.
     *
     * @return void
     */
    protected function setUp(): void
    {
        $this->rules = json_decode(file_get_contents(dirname(__FILE__) . '/data/Rules.json'), true);
        $this->processor = new Processor(
            new Extension(),
            $this->rules,
            []
        );
    }

    public function testMatchParameterValue()
    {
        // Test case for 'equals' type
        $match = ['type' => 'equals', 'value' => 10];
        $value = 10;
        $this->assertTrue($this->processor->matchParameterValue($match, $value));

        // Test case for 'equals_strict' type
        $match = ['type' => 'equals_strict', 'value' => 10];
        $value = '10';
        $this->assertFalse($this->processor->matchParameterValue($match, $value));

        // Test case for 'more_than' type
        $match = ['type' => 'more_than', 'value' => 10];
        $value = 15;
        $this->assertTrue($this->processor->matchParameterValue($match, $value));

        // Test case for 'less_than' type
        $match = ['type' => 'less_than', 'value' => 10];
        $value = 5;
        $this->assertTrue($this->processor->matchParameterValue($match, $value));

        // Test case for 'isset' type
        $match = ['type' => 'isset'];
        $value = 'Hello';
        $this->assertTrue($this->processor->matchParameterValue($match, $value));

        // Test case for 'ctype_special' type
        $match = ['type' => 'ctype_special', 'value' => true];
        $value = 'Hello-World123';
        $this->assertTrue($this->processor->matchParameterValue($match, $value));

        // Test case for 'ctype_digit' type
        $match = ['type' => 'ctype_digit', 'value' => false];
        $value = '123';
        $this->assertFalse($this->processor->matchParameterValue($match, $value));

        // Test case for 'ctype_alnum' type
        $match = ['type' => 'ctype_alnum', 'value' => true];
        $value = 'Hello123';
        $this->assertTrue($this->processor->matchParameterValue($match, $value));

        // Test case for 'is_numeric' type
        $match = ['type' => 'is_numeric', 'value' => true];
        $value = '123';
        $this->assertTrue($this->processor->matchParameterValue($match, $value));

        // Test case for 'contains' type
        $match = ['type' => 'contains', 'value' => 'World'];
        $value = 'Hello World';
        $this->assertTrue($this->processor->matchParameterValue($match, $value));

        // Test case for 'not_contains' type
        $match = ['type' => 'not_contains', 'value' => 'World'];
        $value = 'Hello';
        $this->assertTrue($this->processor->matchParameterValue($match, $value));

        // Test case for 'quotes' type
        $match = ['type' => 'quotes', 'value' => true];
        $value = 'Hello "World"';
        $this->assertTrue($this->processor->matchParameterValue($match, $value));

        // Test case for 'regex' type
        $match = ['type' => 'regex', 'value' => '/^\d{2}$/'];
        $value = '12';
        $this->assertTrue($this->processor->matchParameterValue($match, $value));

        // Test case for 'in_array' type
        $match = ['type' => 'in_array', 'value' => [1, 2, 3]];
        $value = 2;
        $this->assertTrue($this->processor->matchParameterValue($match, $value));

        // Test case for 'not_in_array' type
        $match = ['type' => 'not_in_array', 'value' => [1, 2, 3]];
        $value = 4;
        $this->assertTrue($this->processor->matchParameterValue($match, $value));

        // Test case for 'array_in_array' type
        $match = ['type' => 'array_in_array', 'value' => [1, 2, 3]];
        $value = [3, 4, 5];
        $this->assertTrue($this->processor->matchParameterValue($match, $value));

        // Test case for 'inline_xss' type
        $match = ['type' => 'inline_xss'];
        $value = '"> <script src="https://evil.com/evil.js"></script>';
        $this->assertTrue($this->processor->matchParameterValue($match, $value));

        $value = 'This is a valid "string".';
        $this->assertFalse($this->processor->matchParameterValue($match, $value));
    }
}
