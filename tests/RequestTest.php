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
}
