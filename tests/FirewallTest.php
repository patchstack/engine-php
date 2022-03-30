<?php declare(strict_types=1);
use PHPUnit\Framework\TestCase;
use Patchstack\Processor;
use Patchstack\Extensions\Test\Extension;

final class FirewallTest extends TestCase
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
     * @param array $rules
     * @return void
     */
    private function setUpFirewallProcessor(array $rules)
    {
        $this->processor = new Processor(
            $rules,
            [],
            [],
            [],
            new Extension
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
        // Block request with test parameter present in the URL.
        $this->setUpFirewallProcessor([$this->rules[0]]);
        $this->alterPayload(['GET' => [
            'test' => 'yes'
        ]]);
        $this->assertFalse($this->processor->launch(false));

        // Block request with backdoor parameter in payload set to "mybackdoor" and user agent containing "some_backdoor_agent".
        $this->setUpFirewallProcessor([$this->rules[1]]);
        $this->alterPayload(['POST' => [
            'backdoor' => 'mybackdoor'
        ]]);
        $_SERVER['HTTP_USER_AGENT'] = 'Chrome some_backdoor_agent Edge';
        $this->assertFalse($this->processor->launch(false));
        $_SERVER['HTTP_USER_AGENT'] = '';

        // Block a base64 json encoded request in the payload parameter with the user_role parameter set to "administrator".
        $this->setUpFirewallProcessor([$this->rules[2]]);
        $payload = base64_encode(json_encode(['user_role' => 'administrator']));
        $this->alterPayload(['POST' => [
            'payload' => $payload
        ]]);
        $this->assertFalse($this->processor->launch(false));
    }
}