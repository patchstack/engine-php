<?php

namespace Patchstack;

use Patchstack\Response;
use Patchstack\Request;
use Patchstack\Extensions\ExtensionInterface;

use Opis\Closure\SerializableClosure;

class Processor
{
	/**
	 * The firewall rules to process.
	 * 
	 * @var array
	 */
	private $firewallRules = array();

	/**
	 * The whitelist rules to process.
	 * 
	 * @var array
	 */
	private $whitelistRules = array();

	/**
	 * The options of the engine.
	 * 
	 * @var array
	 */
	private $options = array(
		'autoblockAttempts' => 10,
		'autoblockMinutes' => 30,
		'autoblockTime' => 60,
		'whitelistKeysRules' => array()
	);

	/**
	 * The extension that will process specific logic for the CMS.
	 * 
	 * @var ExtensionInterface
	 */
	private $extension;

	/**
	 * The captured request that needs to be inspected.
	 * 
	 * @var Request
	 */
	private $request;

	/**
	 * The response that will be sent, depending on the action executed by the processor.
	 * 
	 * @var Response
	 */
	private $response;

	/**
	 * Creates a new processor instance.
	 * 
	 * @param array $firewallRules
	 * @param array $whitelistRules
	 * @param array $options
	 * @param ExtensionInterface $extension
	 */
	public function __construct(
		$firewallRules,
		$whitelistRules,
		$options,
		ExtensionInterface $extension
	) {
		$this->firewallRules = $firewallRules;
		$this->whitelistRules = $whitelistRules;
		$this->options = array_merge($this->options, $options);
		$this->extension = $extension;
		$this->request = new Request($this->options);
		$this->response = new Response($this->options);
	}

	/**
	 * Magic getter for the options.
	 * 
	 * @return mixed
	 */
	public function __get($name)
	{
		return isset($this->options[$name]) ? $this->options[$name] : null;
	}

	/**
	 * Launch the firewall. First we determine if the user is blocked and whitelisted, then go through
	 * all of the firewall rules
	 * 
	 * @return void
	 */
	public function launch()
	{
		// Determine if we have any firewall rules loaded.
		if (count($this->firewallRules) == 0) {
			return;
		}

		// Determine if the user is temporarily blocked from the site before we do anything else.
		if ($this->extension->isBlocked($this->autoblockMinutes, $this->autoblockTime, $this->autoblockAttempts) && !$this->extension->canBypass()) {
			//$this->extension->forceExit(22);
		}

		// Since the Opis/Closure package does not support PHP 8.1+,
		// we have to use Laravel's ported version for 8.1+.
		if (PHP_VERSION_ID < 80100) {
			require dirname(__FILE__) . '/../vendor/closure/vendor/autoload.php';
		} else {
			require dirname(__FILE__) . '/../vendor/serializable-closure/vendor/autoload.php';
		}

		// Check for whitelist.
		$request  = $this->request->capture();
		if ($this->extension->isWhitelisted($this->whitelistRules, $request)) {
			return;
		}

		// Run the legacy firewall rules processor.
		// Only used for general firewall rules.
		$this->legacyProcessor();





		$ip = $this->extension->getIpAddress();

		SerializableClosure::setSecretKey('secret');

		$test = function () {
			if (!isset($_GET['test'])) {
				return false;
			}

			$decode = json_decode(base64_decode($_GET['test']), true);
			return $decode && isset($decode['test']);
		};

		// Wrap the closure
		$wrapper = new SerializableClosure($test);

		// Now it can be serialized
		$serialized = serialize($wrapper);
		SerializableClosure::setSecretKey('secret');
		foreach ($this->firewallRules as $rule) {

			// Get the firewall rule and extract it.
			$firewall_rule = json_decode($rule['rule']);
			$vpatch = unserialize($serialized);
			if (!$vpatch) {
				continue;
			}

			// Execute the firewall rule.
			$rule_hit = false;
			try {
				$closure = $vpatch->getClosure();
				$rule_hit = $closure();
			} catch (\Exception $e) {
				continue;
			}

			// If the payload did not match the rule, continue.
			var_dump($rule_hit);
			if (!$rule_hit) {
				continue;
			}

			// Determine what action to perform.
			if ($firewall_rule->type == 'BLOCK') {
				$this->extension->logRequest($rule['id'], $request, 'BLOCK');
				$this->extension->forceExit($rule['id']);
			} elseif ($firewall_rule->type == 'LOG') {
				$this->extension->logRequest($rule['id'], $request, 'LOG');
			} elseif ($firewall_rule->type == 'REDIRECT') {
				$this->extension->logRequest($rule['id'], $request, 'REDIRECT');
				$this->response->redirect($firewall_rule->type_params);
				exit;
			}
		}
	}

	/**
	 * The legacy firewall processor will only iterate over the general firewall rules.
	 * Returns true if all rules were passed. False if any rule was hit.
	 * 
	 * @return boolean
	 */
	public function legacyProcessor($mustExit = true)
	{
		// Obtain the IP address and request data.
		$client_ip = $this->extension->getIpAddress();
		$requests  = $this->request->capture();

		// Iterate through all root objects.
		foreach ($this->firewallRules as $firewall_rule) {
			$blocked_count = 0;
			$rule_terms = json_decode($firewall_rule['rule']);

			// Determine if we should match the IP address.
			$ip = isset($rule_terms->rules->ip_address) ? $rule_terms->rules->ip_address : null;
			if (!is_null($ip)) {
				$matched_ip = false;
				if (strpos($ip, '*') !== false) {
					$matched_ip = $this->plugin->ban->check_wildcard_rule($client_ip, $ip);
				} elseif (strpos($ip, '-') !== false) {
					$matched_ip = $this->plugin->ban->check_range_rule($client_ip, $ip);
				} elseif (strpos($ip, '/') !== false) {
					$matched_ip = $this->plugin->ban->check_subnet_mask_rule($client_ip, $ip);
				} elseif ($client_ip == $ip) {
					$matched_ip = true;
				}

				if (!$matched_ip) {
					continue;
				}
			}

			// If matches on all request methods, only 1 rule match is required to block
			if ($rule_terms->method === 'ALL') {
				$count_rules = 1;
			} else {
				$count_rules = json_decode(json_encode($rule_terms->rules), true);
				$count_rules = $this->countRules($count_rules);
			}

			// Loop through all request data that we captured.
			foreach ($requests as $key => $request) {

				// Treat the raw POST data string as the body contents of all values combined.
				if ($key == 'rulesRawPost') {
					$key = 'rulesBodyAll';
				}

				// Determine if the requesting method matches.
				if ($rule_terms->method == $requests['method'] || $rule_terms->method == 'ALL' || $rule_terms->method == 'GET' || ($rule_terms->method == 'FILES' && $this->extension->isFileUploadRequest())) {
					$test = strtolower(preg_replace('/(?!^)[A-Z]{2,}(?=[A-Z][a-z])|[A-Z][a-z]/', '->$0', $key));
					$exp  = explode('->', $test);

					// Determine if a rule exists for this request.
					$rule = array_reduce(
						$exp,
						function ($o, $p) {
							if (!isset($o->$p)) {
								return null;
							}

							return $o->$p;
						},
						$rule_terms
					);

					// Determine if the rule matches the request.
					if (!is_null($rule) && substr($key, 0, 4) == 'rule' && $this->isRuleMatch($rule, $request)) {
						$blocked_count++;
					}
				}
			}

			// Determine if the user should be blocked.
			if ($blocked_count >= $count_rules) {
				if ($rule_terms->type == 'BLOCK') {
					$this->extension->logRequest($firewall_rule['id'], $request, 'BLOCK');
					
					// Do we have to exit the page or simply return false?
					if($mustExit){
						$this->extension->forceExit($firewall_rule['id']);
					}else{
						return false;
					}
				} elseif ($rule_terms->type == 'LOG') {
					$this->extension->logRequest($firewall_rule['id'], $request, 'LOG');
				} elseif ($rule_terms->type == 'REDIRECT') {
					$this->extension->logRequest($firewall_rule['id'], $request, 'REDIRECT');
					$this->response->redirect($rule_terms->type_params, $mustExit);
				}
			}
		}

		return true;
	}

	/**
	 * Determine if the request matches the given firewall or whitelist rule.
	 *
	 * @param string       $rule
	 * @param string|array $request
	 * @return bool
	 */
	private function isRuleMatch( $rule, $request ) {
		$is_matched = false;
		if ( is_array( $request ) ) {
			foreach ( $request as $value ) {
				$is_matched = $this->isRuleMatch( $rule, $value );
				if ( $is_matched ) {
					return $is_matched;
				}
			}
		} else {
			return preg_match( $rule, urldecode( $request ) );
		}

		return $is_matched;
	}

	/**
	 * Count the number of rules.
	 *
	 * @param array $array
	 * @return integer
	 */
	private function countRules($array)
	{
		$counter = 0;
		if (is_object($array)) {
			$array = (array) $array;
		}

		if ($array['uri']) {
			$counter++;
		}

		foreach (array('body', 'params', 'headers') as $type) {
			foreach ($array[$type] as $key => $value) {
				if (!is_null($value)) {
					$counter++;
				}
			}
		}

		return $counter;
	}
}
