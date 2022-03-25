<?php declare(strict_types=1);
use PHPUnit\Framework\TestCase;

use Patchstack\Processor;
use Patchstack\Extensions\Test\Extension;

final class FirewallLegacyTest extends TestCase
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
     */
    protected function setUp(): void
    {
        $this->rules = json_decode(file_get_contents(dirname(__FILE__) . '/data/RulesLegacy.json'), true);
    }

    /**
     * Setup the firewall processor.
     * 
     * @param array $rules
     */
    private function setUpFirewallProcessor(array $rules)
    {
        $this->processor = new Processor(
            $rules,
            [],
            [],
            new Extension
        );
    }

    /**
     * Alters the payload between tests.
     */
    private function alterPayload(array $payload)
    {
        $_POST = [];
        $_GET = [];

        $_POST = isset($payload['POST']) ? $payload['POST'] : [];
        $_GET = isset($payload['GET']) ? $payload['GET'] : [];
    }

    /**
     * Testing all firewall rules with no payload should result nothing.
     */
    public function testAllRules()
    {
        $this->setUpFirewallProcessor($this->rules);
        $this->assertTrue($this->processor->legacyProcessor());
    }

    /**
     * Test different cross-site scripting attacks.
     */
    public function testXSS()
    {
        $this->setUpFirewallProcessor($this->rules);

        // Basic JavaScript alert through a GET parameter.
        $this->alterPayload(['GET' => [
            'q' => '<script>alert(1)</script>'
        ]]);
        $this->processor->legacyProcessor();

    }
}