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
        $this->rules = json_decode(file_get_contents(dirname(__FILE__) . '/data/Rules.json'), true);
        $this->whitelist = json_decode(file_get_contents(dirname(__FILE__) . '/data/Whitelist.json'), true);
    }

    /**
     * Setup the firewall processor.
     *
     * @param  array $rules
     * @return void
     */
    private function setUpFirewallProcessor(array $whitelistRules)
    {
        $this->processor = new Processor(
            new Extension(),
            $this->rules,
            $whitelistRules
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
        // Whitelist IP 127.0.0.1
        $this->alterPayload();
        $this->setUpFirewallProcessor([$this->whitelist[0]]);
        $this->assertFalse($this->processor->launch(false));

        // Whitelist if POST request action parameter is set to wp_heartbeat
        $this->alterPayload(
            ['POST' => [
            'action' => 'wp_heartbeat'
            ]]
        );
        $this->setUpFirewallProcessor([$this->whitelist[1]]);
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();
    }
}
