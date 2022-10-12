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

        $request = new Request([], new Extension());
        $this->request = $request->capture();
    }

    /**
     * Test different request variables.
     */
    public function testRequestCaptureHeaders()
    {
        // Test for HTTP user agent.
        foreach ($this->request['rulesHeadersCombinations'] as $header) {
            if (stripos($header, 'User-Agent:') !== false) {
                $this->assertTrue($header == 'User-Agent: This is a user agent');
            }
        }

        // Test for the requesting URL.
        $this->assertTrue($this->request['rulesUri'] == '/somepage.php');

        // Test for the requesting method.
        $this->assertTrue($this->request['method'] == 'GET');

        // Test for URL query parameter.
        foreach ($this->request['rulesParamsCombinations'] as $parameter) {
            if (stripos($parameter, 'something=') !== false) {
                $this->assertTrue($parameter == 'something=testing123');
            }
        }

        // Test for POST payload parameter.
        foreach ($this->request['rulesBodyCombinations'] as $parameter) {
            if (stripos($parameter, 'something=') !== false) {
                $this->assertTrue($parameter == 'else=foobar');
            }
        }
    }
}
