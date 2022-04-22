<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Patchstack\Processor;
use Patchstack\Extensions\Test\Extension;

final class WhitelistTest extends TestCase
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
        $this->rules = json_decode(file_get_contents(dirname(__FILE__) . '/data/Rules.json'));
        $this->whitelist = json_decode(file_get_contents(dirname(__FILE__) . '/data/Whitelist.json'));
        $this->processor = new Processor(
            new Extension(),
            $this->rules,
            $this->whitelist,
            [
                'secret' => 'be298ce20996fbe66657d6b1ba4412fae11b3594'
            ]
        );
    }

    /**
     * Alters the payload between tests.
     * For most firewall rules there's no difference if testing against GET or POST.
     * Therefore, both can be used for testing payloads.
     *
     * @return void
     */
    private function alterPayload(array $payload = [])
    {
        $_POST = [];
        $_GET = [];

        $_POST = isset($payload['POST']) ? $payload['POST'] : [];
        $_GET = isset($payload['GET']) ? $payload['GET'] : [];
    }

    /**
     * Test specific firewall rules.
     *
     * @return void
     */
    public function testRules()
    {
        // Whitelist IP 1.2.3.4 or 5.5.5.5
        $_SERVER['REMOTE_ADDR'] = '1.2.3.4';
        $this->alterPayload();
        $this->assertFalse($this->processor->launch(false));
        $_SERVER['REMOTE_ADDR'] = '';

        // This should be a true response, no firewall or whitelist rules should be hit.
        $this->assertTrue($this->processor->launch(false));

        // Whitelist if POST request action parameter is set to wp_heartbeat
        $this->alterPayload(
            ['POST' => [
            'action' => 'wp_heartbeat'
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();
    }
}
