<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Patchstack\Processor;
use Patchstack\Extensions\Test\Extension;

final class FirewallRuleCreationTest extends TestCase
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
            new Extension(),
            $rules,
            [],
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
     * Test the creation of firewall rules.
     *
     * @return void
     */
    public function testFirewallRuleCreation()
    {
        // Since the Opis/Closure package does not support PHP 8.1+, we have to use Laravel's ported version for 8.1+.
        require dirname(__FILE__) . '/../vendor/autoload.php';
        if (PHP_VERSION_ID < 80100) {
            \Opis\Closure\SerializableClosure::setSecretKey('be298ce20996fbe66657d6b1ba4412fae11b3594');
        } else {
            \Laravel\SerializableClosure\SerializableClosure::setSecretKey('be298ce20996fbe66657d6b1ba4412fae11b3594');
        }

        // Create the firewall rule.
        $function = function () {
            return isset($_GET['test']);
        };
        $wrapper = new SerializeClosure($function);
        $rule = (object) [
            'id' => 1,
            'title' => 'Block request with test query parameter in the URL.',
            'rule_closure' => (object) [
                'opis' => base64_encode(serialize($wrapper)),
                'laravel' => base64_encode(serialize($wrapper))
            ],
            'cat' => 'TEST',
            'type' => 'BLOCK'
        ];

        // Test the rule.
        $this->setUpFirewallProcessor([$rule]);
        $this->alterPayload(
            ['GET' => [
            'test' => 'yes'
            ]]
        );
        $this->assertFalse($this->processor->launch(false));

        // Create the more complex firewall rule.
        $function = function () {
            if (!isset($_POST['exec'])) {
                return false;
            }

            $payload = json_decode(base64_decode($_POST['exec']), true);
            return $payload && isset($payload['user_role']) && $payload['user_role'] == 'administrator';
        };
        $wrapper = new SerializeClosure($function);
        $rule = (object) [
            'id' => 1,
            'title' => 'Block request with encoded payload',
            'rule_closure' => (object) [
                'opis' => base64_encode(serialize($wrapper)),
                'laravel' => base64_encode(serialize($wrapper))
            ],
            'cat' => 'TEST',
            'type' => 'BLOCK'
        ];

        // Test the rule.
        $this->setUpFirewallProcessor([$rule]);
        $this->alterPayload(
            ['POST' => [
            'exec' => base64_encode(json_encode(['user_role' => 'administrator']))
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();
    }
}
