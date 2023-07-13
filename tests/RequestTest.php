<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Patchstack\Request;
use Patchstack\Extensions\Test\Extension;

final class RequestTest extends TestCase
{
    /**
     * @var Request
     */
    private $request;

    /**
     * Setup the test for testing the requesting variables.
     *
     * @return void
     */
    public function setUp(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'This is a user agent';
        $_SERVER['REQUEST_URI'] = '/somepage.php';
        $_SERVER['REQUEST_METHOD'] = 'GET';

        $_GET['something'] = 'testing123';
        $_POST['else'] = 'foobar';
        $this->request = new Request([], new Extension());
    }

    /**
     * Test different request variables.
     */
    public function testRequestCaptureHeaders()
    {
        $value = $this->request->getParameterValues('server.HTTP_USER_AGENT')[0];
        $this->assertTrue($value == 'This is a user agent');

        // Test for the requesting URL.
        $value = $this->request->getParameterValues('server.REQUEST_URI')[0];
        $this->assertTrue($value == '/somepage.php');

        // Test for the requesting method.
        $value = $this->request->getParameterValues('server.REQUEST_METHOD')[0];
        $this->assertTrue($value == 'GET');

        // Test for URL query parameter.
        $value = $this->request->getParameterValues('get.something')[0];
        $this->assertTrue($value == 'testing123');

        // Test for POST payload parameter.
        $value = $this->request->getParameterValues('post.else')[0];
        $this->assertTrue($value == 'foobar');
    }

    public function getValuesByWildcard()
    {
        // Test with valid input
        $data = [
            'foo' => [
                'bar' => [
                    'value1' => 'abc',
                    'value2' => 'def',
                ],
                'baz' => [
                    'value3' => 'ghi',
                    'value4' => 'jkl',
                ],
            ],
        ];
        $parameter = 'foo.bar.*';
        $expected = ['abc', 'def'];
        $result = $this->request->getValuesByWildcard($data, $parameter);
        $this->assertEquals($expected, $result);

        // Test with non-array data
        $data = 'not an array';
        $parameter = 'foo.bar.*';
        $expected = [];
        $result = $this->request->getValuesByWildcard($data, $parameter);
        $this->assertEquals($expected, $result);

        // Test with non-existing key
        $data = [
            'foo' => [
                'bar' => [
                    'value1' => 'abc',
                    'value2' => 'def',
                ],
                'baz' => [
                    'value3' => 'ghi',
                    'value4' => 'jkl',
                ],
            ],
        ];
        $parameter = 'foo.qux.*';
        $expected = [];
        $result = $this->request->getValuesByWildcard($data, $parameter);
        $this->assertEquals($expected, $result);

        // Test with empty parameter
        $data = [
            'foo' => [
                'bar' => [
                    'value1' => 'abc',
                    'value2' => 'def',
                ],
                'baz' => [
                    'value3' => 'ghi',
                    'value4' => 'jkl',
                ],
            ],
        ];
        $parameter = '';
        $expected = [];
        $result = $this->request->getValuesByWildcard($data, $parameter);
        $this->assertEquals($expected, $result);

        // Test with no wildcard matches
        $data = [
            'foo' => [
                'bar' => [
                    'value1' => 'abc',
                    'value2' => 'def',
                ],
                'baz' => [
                    'value3' => 'ghi',
                    'value4' => 'jkl',
                ],
            ],
        ];
        $parameter = 'foo.bar.xyz';
        $expected = [];
        $result = $this->request->getValuesByWildcard($data, $parameter);
        $this->assertEquals($expected, $result);

        // Test with case-insensitive wildcard matching
        $data = [
            'foo' => [
                'bar' => [
                    'Value1' => 'abc',
                    'value2' => 'def',
                ],
                'baz' => [
                    'value3' => 'ghi',
                    'Value4' => 'jkl',
                ],
            ],
        ];
        $parameter = 'foo.*.value*';
        $expected = ['abc', 'def', 'ghi'];
        $result = $this->request->getValuesByWildcard($data, $parameter);
        $this->assertEquals($expected, $result);
    }

    public function getArrayValues()
    {
        $data = [
            'name' => 'John',
            'age' => 30,
            'hobbies' => ['reading', 'coding'],
            'address' => [
                'street' => '123 Main St',
                'city' => 'New York',
            ],
            'emptyValue' => '',
        ];
        $glue = '&';

        // Test with string type
        $type = 'string';
        $expectedString = 'name=John&age=30&hobbies=reading&hobbies=coding&address=123 Main St&address=New York';
        $resultString = $this->request->getArrayValues($data, $glue, $type);
        $this->assertEquals($expectedString, $resultString);

        // Test with array type
        $type = 'array';
        $expectedArray = [
            'name' => 'John',
            'age' => 30,
            'hobbies' => ['reading', 'coding'],
            'address' => [
                'street' => '123 Main St',
                'city' => 'New York',
            ],
        ];
        $resultArray = $this->request->getArrayValues($data, $glue, $type);
        $this->assertEquals($expectedArray, $resultArray);

        // Test with custom glue
        $glue = '|';
        $type = 'string';
        $expectedCustomGlue = 'name=John|age=30|hobbies=reading|hobbies=coding|address=123 Main St|address=New York';
        $resultCustomGlue = $this->request->getArrayValues($data, $glue, $type);
        $this->assertEquals($expectedCustomGlue, $resultCustomGlue);

        // Test with empty data
        $data = [];
        $glue = '&';
        $type = 'string';
        $expectedEmptyData = '';
        $resultEmptyData = $this->request->getArrayValues($data, $glue, $type);
        $this->assertEquals($expectedEmptyData, $resultEmptyData);

        // Test with empty values
        $data = [
            'name' => '',
            'age' => null,
            'hobbies' => [],
        ];
        $glue = '&';
        $type = 'string';
        $expectedEmptyValues = '';
        $resultEmptyValues = $this->request->getArrayValues($data, $glue, $type);
        $this->assertEquals($expectedEmptyValues, $resultEmptyValues);
    }

    public function testApplyMutation()
    {
        // Test with no mutations
        $mutations = [];
        $value = 'Hello, World!';
        $expected = 'Hello, World!';
        $result = $this->request->applyMutation($mutations, $value);
        $this->assertEquals($expected, $result);

        // Test with valid mutations
        $mutations = ['json_encode', 'base64_decode', 'intval'];
        $value = '42';
        $expected = 0;
        $result = $this->request->applyMutation($mutations, $value);
        $this->assertEquals($expected, $result);

        // Test with invalid mutations
        $mutations = ['invalid_mutation'];
        $value = 'Hello, World!';
        $expected = 'Hello, World!';
        $result = $this->request->applyMutation($mutations, $value);
        $this->assertEquals($expected, $result);

        // Test with mutation and type check
        $mutations = ['json_decode'];
        $value = '{"name":"John","age":30}';
        $expected = ['name' => 'John', 'age' => 30];
        $result = $this->request->applyMutation($mutations, $value);
        $this->assertEquals($expected, $result);

        // Test with return value null
        $mutations = ['json_decode'];
        $value = 'Invalid JSON';
        $expected = null;
        $result = $this->request->applyMutation($mutations, $value);
        $this->assertEquals($expected, $result);

        // Test with return value false
        $mutations = ['intval'];
        $value = 'Not a number';
        $expected = false;
        $result = $this->request->applyMutation($mutations, $value);
        $this->assertEquals($expected, $result);

        // Test with return value zero
        $mutations = ['intval'];
        $value = '0';
        $expected = 0;
        $result = $this->request->applyMutation($mutations, $value);
        $this->assertEquals($expected, $result);

        // Test with exception handling
        $mutations = ['json_encode'];
        $value = ['name' => 'John', 'age' => 30];
        $expected = '{"name":"John","age":30}';
        $result = $this->request->applyMutation($mutations, $value);
        $this->assertEquals($expected, $result);
    }

    public function testGetParameterValues()
    {
        // Test case for 'all' type
        $parameter = 'all';
        $expected = [[
            'post' => $_POST,
            'get' => $_GET,
            'url' => isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '',
            'raw' => ['raw' => null]
        ]];
        $result = $this->request->getParameterValues($parameter);
        $this->assertEquals($expected, $result);

        // Test case for 'log' type
        $parameter = 'log';
        $expected = [
            'post' => $_POST,
            'raw' => null
        ];
        $result = $this->request->getParameterValues($parameter);
        $this->assertEquals($expected, $result);

        // Test case for 'post' type
        $parameter = 'post';
        $_POST = ['name' => 'John', 'age' => 30];
        $expected = [['name' => 'John', 'age' => 30]];
        $result = $this->request->getParameterValues($parameter);
        $this->assertEquals($expected, $result);

        // Test case for 'post' type
        $parameter = 'post.name';
        $_POST = ['name' => 'John', 'age' => 30];
        $expected = ['John'];
        $result = $this->request->getParameterValues($parameter);
        $this->assertEquals($expected, $result);

        // Test case for 'get' type
        $parameter = 'get';
        $_GET = ['page' => 1, 'limit' => 10];
        $expected = [['page' => 1, 'limit' => 10]];
        $result = $this->request->getParameterValues($parameter);
        $this->assertEquals($expected, $result);

        // Test case for 'get.page' type
        $parameter = 'get.page';
        $_GET = ['page' => 1, 'limit' => 10];
        $expected = [1];
        $result = $this->request->getParameterValues($parameter);
        $this->assertEquals($expected, $result);

        // Test case for 'request' type
        $parameter = 'request';
        $_REQUEST = ['name' => 'John', 'age' => 30];
        $expected = [['name' => 'John', 'age' => 30]];
        $result = $this->request->getParameterValues($parameter);
        $this->assertEquals($expected, $result);

        // Test case for 'cookie' type
        $parameter = 'cookie';
        $_COOKIE = ['name' => 'John', 'age' => 30];
        $expected = [['name' => 'John', 'age' => 30]];
        $result = $this->request->getParameterValues($parameter);
        $this->assertEquals($expected, $result);

        // Test case for 'files' type
        $parameter = 'files';
        $_FILES = ['file' => ['name' => 'example.txt', 'type' => 'text/plain']];
        $expected = [['file' => ['name' => 'example.txt', 'type' => 'text/plain']]];
        $result = $this->request->getParameterValues($parameter);
        $this->assertEquals($expected, $result);

        // Test case for 'server' type
        $parameter = 'server';
        $_SERVER = ['REQUEST_METHOD' => 'GET', 'SERVER_NAME' => 'example.com'];
        $expected = [['REQUEST_METHOD' => 'GET', 'SERVER_NAME' => 'example.com']];
        $result = $this->request->getParameterValues($parameter);
        $this->assertEquals($expected, $result);


     }
}
