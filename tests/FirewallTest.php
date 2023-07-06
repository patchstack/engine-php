<?php

declare(strict_types=1);

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
        $this->rules = json_decode(file_get_contents(dirname(__FILE__) . '/data/Rules.json'), true);
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
            []
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
        $_SERVER['REQUEST_URI'] = isset($payload['SERVER'], $payload['SERVER']['REQUEST_URI']) ? $payload['SERVER']['REQUEST_URI'] : '';
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
        $this->alterPayload(
            ['GET' => [
            'test' => 'yes'
            ]]
        );
        $this->assertFalse($this->processor->launch(false));

        // Block request with backdoor parameter in payload set to "mybackdoor" and user agent containing "some_backdoor_agent".
        $this->setUpFirewallProcessor([$this->rules[1]]);
        $this->alterPayload(
            ['POST' => [
            'backdoor' => 'mybackdoor'
            ]]
        );
        $_SERVER['HTTP_USER_AGENT'] = 'Chrome some_backdoor_agent Edge';
        $this->assertFalse($this->processor->launch(false));
        $_SERVER['HTTP_USER_AGENT'] = '';

        // Block a base64 json encoded request in the payload parameter with the user_role parameter set to "administrator".
        $this->setUpFirewallProcessor([$this->rules[2]]);
        $payload = base64_encode(json_encode(['user_role' => 'administrator']));
        $this->alterPayload(
            ['POST' => [
            'payload' => $payload
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();

        // Block WordPress WP-AJAX action restaurant_system_customize_button or restaurant_system_insert_dialog, when not executed by an administrator.
        // Should return false because current_user_can does not exist.
        $this->setUpFirewallProcessor([$this->rules[3]]);
        $this->alterPayload(
            ['POST' => [
            'action' => 'restaurant_system_customize_button'
            ]]
        );
        $this->assertTrue($this->processor->launch(false));
        $this->alterPayload();

        // Block WordPress WP-AJAX action restaurant_system_customize_button or restaurant_system_insert_dialog.
        $this->setUpFirewallProcessor([$this->rules[4]]);
        $this->alterPayload(
            ['POST' => [
            'action' => 'restaurant_system_customize_button'
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();

        // Block access to specific WP-JSON endpoint.
        $this->setUpFirewallProcessor([$this->rules[5]]);
        $this->alterPayload(
            ['SERVER' => [
            'REQUEST_URI' => '/wp-json/yikes/cpt/v1/settings'
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();

        // Block access to specific WP-JSON endpoint.
        $this->setUpFirewallProcessor([$this->rules[5]]);
        $this->alterPayload(
            ['GET' => [
            'rest_route' => '/wp-json/yikes/cpt/v1/settings'
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();

        // Block access to endpoint that should only accept an integer of less than 101.
        $this->setUpFirewallProcessor([$this->rules[6]]);
        $this->alterPayload(
            ['GET' => [
            'pid' => 10000
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();

        // Block access to endpoint that should only accept an integer of more than 99.
        $this->setUpFirewallProcessor([$this->rules[7]]);
        $this->alterPayload(
            ['GET' => [
            'pid' => 99
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();

        // Determine if a POST parameter is not a ctype_alnum.
        $this->setUpFirewallProcessor([$this->rules[8]]);
        $this->alterPayload(
            ['POST' => [
            'value' => 'something)'
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();

        // Determine if a POST parameter is not numeric.
        $this->setUpFirewallProcessor([$this->rules[9]]);
        $this->alterPayload(
            ['POST' => [
            'number' => '8*8'
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();

        // Determine if the URL matches a regex.
        $this->setUpFirewallProcessor([$this->rules[10]]);
        $this->alterPayload(
            ['SERVER' => [
            'REQUEST_URI' => '/something/backdoor/something-else/'
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();

        // Determine if value is not part of an array of values.
        $this->setUpFirewallProcessor([$this->rules[11]]);
        $this->alterPayload(
            ['GET' => [
            'user' => 'simon'
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();

        $this->setUpFirewallProcessor([$this->rules[11]]);
        $this->alterPayload(
            ['GET' => [
            'user' => 'admin'
            ]]
        );
        $this->assertTrue($this->processor->launch(false));
        $this->alterPayload();

        // Determine if an array of values is part of a given array.
        $this->setUpFirewallProcessor([$this->rules[12]]);
        $this->alterPayload(
            ['POST' => [
            'usernames' => ['simon', 'peter']
            ]]
        );
        $this->assertTrue($this->processor->launch(false));
        $this->alterPayload();

        $this->setUpFirewallProcessor([$this->rules[12]]);
        $this->alterPayload(
            ['POST' => [
            'usernames' => ['admin']
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();

        // Detect an open redirect vulnerability
        $this->setUpFirewallProcessor([$this->rules[15]]);
        $this->alterPayload(
            ['GET' => [
            'tourl' => 'https://wordpress.test/my-location/'
            ]]
        );
        $this->assertTrue($this->processor->launch(false));
        $this->alterPayload();

        $this->setUpFirewallProcessor([$this->rules[15]]);
        $this->alterPayload(
            ['GET' => [
            'tourl' => 'https://badsite.com'
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();

        // Determine if a POST parameter is not a ctype_alnum.
        $this->setUpFirewallProcessor([$this->rules[17]]);
        $this->alterPayload(
            ['POST' => [
            'value' => 'something_-0-9 '
            ]]
        );
        $this->assertTrue($this->processor->launch(false));
        $this->alterPayload();

        $this->setUpFirewallProcessor([$this->rules[17]]);
        $this->alterPayload(
            ['POST' => [
            'value' => 'sleep(5), id'
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();

        // Determine if a POST parameter (using wildcard) contains a certain character.
        $this->setUpFirewallProcessor([$this->rules[18]]);
        $this->alterPayload(
            ['POST' => [
            'user' => [
                'test' => 'test',
                'role' => [
                    'test' => 'test',
                    'type1' => 'subscriber',
                    'type2' => 'editor'
                ]
            ]
            ]]
        );
        $this->assertTrue($this->processor->launch(false));
        $this->alterPayload();

        $this->setUpFirewallProcessor([$this->rules[18]]);
        $this->alterPayload(
            ['POST' => [
            'user' => [
                'test' => 'test',
                'role' => [
                    'test' => 'test',
                    'type1' => 'editor',
                    'type5' => 'administrator'
                ]
            ]
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();

        // Determine if a POST parameter does not contain a substring.
        $this->setUpFirewallProcessor([$this->rules[19]]);
        $this->alterPayload(
            ['POST' => [
            'what' => 'myteststring'
            ]]
        );
        $this->assertTrue($this->processor->launch(false));
        $this->alterPayload();

        $this->setUpFirewallProcessor([$this->rules[19]]);
        $this->alterPayload(
            ['POST' => [
            'what' => 'myvalidstring'
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();

        // Determine if a POST parameter contains a shortcode with a bad attribute.
        // Import the WordPress functions.
        function get_shortcode_atts_regex() {
            return '/([\w-]+)\s*=\s*"([^"]*)"(?:\s|$)|([\w-]+)\s*=\s*\'([^\']*)\'(?:\s|$)|([\w-]+)\s*=\s*([^\s\'"]+)(?:\s|$)|"([^"]*)"(?:\s|$)|\'([^\']*)\'(?:\s|$)|(\S+)(?:\s|$)/';
        }

        function shortcode_parse_atts( $text ) {
            $atts    = array();
            $pattern = get_shortcode_atts_regex();
            $text    = preg_replace( "/[\x{00a0}\x{200b}]+/u", ' ', $text );
            if ( preg_match_all( $pattern, $text, $match, PREG_SET_ORDER ) ) {
                foreach ( $match as $m ) {
                    if ( ! empty( $m[1] ) ) {
                        $atts[ strtolower( $m[1] ) ] = stripcslashes( $m[2] );
                    } elseif ( ! empty( $m[3] ) ) {
                        $atts[ strtolower( $m[3] ) ] = stripcslashes( $m[4] );
                    } elseif ( ! empty( $m[5] ) ) {
                        $atts[ strtolower( $m[5] ) ] = stripcslashes( $m[6] );
                    } elseif ( isset( $m[7] ) && strlen( $m[7] ) ) {
                        $atts[] = stripcslashes( $m[7] );
                    } elseif ( isset( $m[8] ) && strlen( $m[8] ) ) {
                        $atts[] = stripcslashes( $m[8] );
                    } elseif ( isset( $m[9] ) ) {
                        $atts[] = stripcslashes( $m[9] );
                    }
                }
        
                // Reject any unclosed HTML elements.
                foreach ( $atts as &$value ) {
                    if ( false !== strpos( $value, '<' ) ) {
                        if ( 1 !== preg_match( '/^[^<]*+(?:<[^>]*+>[^<]*+)*+$/', $value ) ) {
                            $value = '';
                        }
                    }
                }
            } else {
                $atts = ltrim( $text );
            }
        
            return $atts;
        }

        $this->setUpFirewallProcessor([$this->rules[20]]);
        $this->alterPayload(
            ['POST' => [
            'content' => 'This is my post content and a shortcode with bad attribute value. [learn_press_featured_courses order_by="post_date" order="desc"]'
            ]]
        );
        $this->assertTrue($this->processor->launch(false));
        $this->alterPayload();

        $this->setUpFirewallProcessor([$this->rules[20]]);
        $this->alterPayload(
            ['POST' => [
            'content' => 'This is my post content with a legitimate shortcode. [learn_press_featured_courses order_by="post_date" order="\',(select sleep(10))"]'
            ]]
        );
        $this->assertFalse($this->processor->launch(false));
        $this->alterPayload();
    }
}
