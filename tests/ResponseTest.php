<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Patchstack\Response;

final class ResponseTest extends TestCase
{
    protected $app;

    /**
     * Setup the test for testing the header location redirect.
     *
     * @return void
     */
    protected function setUp(): void
    {
        $this->app = $this->getMockBuilder(Response::class)->setConstructorArgs([])->onlyMethods(['redirect'])->getMock();

        $this->app->expects($this->any())->method('redirect')->will(
            $this->returnCallback(
                function ($url) {
                    throw new \Exception($url);
                }
            )
        );
    }

    /**
     * Test a redirect with a valid URL.
     *
     * @return void
     */
    public function testRedirectSuccess()
    {
        try {
            $this->app->redirect('https://www.amazon.com', true);
        } catch (\Exception $e) {
            $this->assertEquals($e->getMessage(), 'https://www.amazon.com');
        }

        try {
            $this->app->redirect('https://www.google.com', true);
        } catch (\Exception $e) {
            $this->assertEquals($e->getMessage(), 'https://www.google.com');
        }

        try {
            $this->app->redirect('https://1.1.1.1', true);
        } catch (\Exception $e) {
            $this->assertEquals($e->getMessage(), 'https://1.1.1.1');
        }
    }

    /**
     * Test a redirect which has an invalid URL.
     * Since users can supply this redirect URL, we'd want to check it on the client side too.
     *
     * @return void
     */
    public function testRedirectFailure()
    {
        $response = new Response();

        $this->assertEquals($response->redirect('https//patchstack.com', true), false);
        $this->assertEquals($response->redirect('https:/patchstackcom', true), false);
        $this->assertEquals($response->redirect('$TOJ34r8tq94ht', true), false);
        $this->assertEquals($response->redirect('123.123.123', true), false);
        $this->assertEquals($response->redirect(' ', true), false);
    }
}
