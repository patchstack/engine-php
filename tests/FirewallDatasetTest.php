<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Patchstack\Processor;
use Patchstack\Extensions\Test\Extension;

final class FirewallDatasetTest extends TestCase
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
     * @var array
     */
    protected $datasets;

    /**
     * Setup the test for testing the header location redirect.
     *
     * @return void
     */
    protected function setUp(): void
    {
        $this->datasets = json_decode(file_get_contents(dirname(__FILE__) . '/data/Datasets.json'), true);
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
            [],
            [],
            $this->datasets
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
        // Since the Opis/Closure package does not support PHP 8.1+, we have to use Laravel's ported version for 8.1+.
        require dirname(__FILE__) . '/../vendor/autoload.php';
        if (PHP_VERSION_ID < 80100) {
            \Opis\Closure\SerializableClosure::setSecretKey('secret');
            class_alias('\Opis\Closure\SerializableClosure', 'SerializeClosure');
        } else {
            \Laravel\SerializableClosure\SerializableClosure::setSecretKey('secret');
            class_alias('\Laravel\SerializableClosure\SerializableClosure', 'SerializeClosure');
        }

        // For easier access we store the datasets inside of $datasets as it will function
        // like this in the firewall rule processor as well.
        $datasets = $this->datasets;

        // Create the firewall rule.
        $function = function () use ($datasets) {
            return in_array($_SERVER['REMOTE_ADDR'], $datasets['ps_ips']);
        };
        $wrapper = new SerializeClosure($function);
        $rule = (object) [
            'id' => 1,
            'title' => 'Determine if IP is in blacklist',
            'rule' => base64_encode(serialize($wrapper)),
            'cat' => 'TEST',
            'type' => 'BLOCK'
        ];

        // Test the rule.
        $_SERVER['REMOTE_ADDR'] = '1.1.1.1';
        $this->setUpFirewallProcessor([$rule]);
        $this->assertFalse($this->processor->launch(false));
        $_SERVER['REMOTE_ADDR'] = '';

        // Create the firewall rule.
        $function = function () use ($datasets) {
            return preg_match($datasets['ps_sqli'], $_GET['id']) === 1;
        };
        $wrapper = new SerializeClosure($function);
        $rule = (object) [
            'id' => 1,
            'title' => 'Determine if union all select regex is a hit in the id GET parameter',
            'rule' => base64_encode(serialize($wrapper)),
            'cat' => 'TEST',
            'type' => 'BLOCK'
        ];

        // Test the rule.
        $this->setUpFirewallProcessor([$rule]);
        $this->alterPayload(
            ['GET' => [
            'id' => '1 UNION ALL SELECT 1,2,3,4,5,@@version-- '
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();
    }
}
