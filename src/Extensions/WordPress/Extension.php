<?php

namespace Patchstack\Extensions\WordPress;

use Patchstack\Extensions\ExtensionInterface;

class Extension implements ExtensionInterface
{
	/**
	 * WordPress specific options that we need to remember.
	 * 
	 * @var array
	 */
	public $options = array(
		'patchstack_basic_firewall_roles' => array('administrator', 'editor', 'author'),
		'patchstack_custom_whitelist_rules' => ''
	);

	/**
	 * The core of the Patchstack plugin.
	 * 
	 * @var P_Core
	 */
	private $core;

	/**
	 * Creates a new extension instance.
	 * 
	 * @var array $options
	 */
	public function __construct($options, $core)
	{
		$this->options = array_merge($this->options, $options);
		$this->core = $core;
	}

	/**
	 * Log the HTTP request.
	 * 
	 * @param int $ruleId
	 * @param array $request
	 * @param string $logType
	 * @return void
	 */
	public function logRequest($ruleId, $request, $logType = 'BLOCK')
	{
		global $wpdb;
		if (!$wpdb) {
			return;
		}

		// Determine where to get the POST payload from.
		if (!isset($request['rulesRawPost']) || empty($request['rulesRawPost'])) {
			$postData = count($_POST) == 0 ? null : json_encode($_POST);
		} else {
			$postData = $request['rulesRawPost'];
		}

		// Insert into the logs.
		$wpdb->insert(
			$wpdb->prefix . 'patchstack_firewall_log',
			array(
				'ip'          => $this->getIpAddress(),
				'request_uri' => isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '',
				'user_agent'  => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
				'method'      => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '',
				'fid'         => '55' . $ruleId,
				'flag'        => '',
				'post_data'   => $postData,
				'block_type'  => $logType
			)
		);
	}

	/**
	 * Determine if the current logged in user is logged in and whitelisted.
	 * 
	 * @return bool
	 */
	public function canBypass()
	{
		if (!is_user_logged_in()) {
			return false;
		}

		// Get the whitelisted roles.
		$roles = $this->options['patchstack_basic_firewall_roles'];
		if (!is_array($roles)) {
			return false;
		}

		// Special scenario for super admins on a multisite environment.
		if (in_array('administrator', $roles) && is_multisite() && is_super_admin()) {
			return true;
		}

		// Get the roles of the user.
		$user = wp_get_current_user();
		if (!isset($user->roles) || count((array) $user->roles) == 0) {
			return false;
		}

		// Is the user in the whitelist roles list?
		$role_count = array_intersect($user->roles, $roles);
		return count($role_count) != 0;
	}

	/**
	 * Determine if the visitor is blocked from the website.
	 * 
	 * @param int $minutes
	 * @param int $blockTime
	 * @param int $attempts
	 * @return bool
	 */
	public function isBlocked($minutes, $blockTime, $attempts)
	{
		// Calculate block time.
		if (empty($minutes) || empty($blockTime)) {
			$time = 30 + 60;
		} else {
			$time = $minutes + $blockTime;
		}

		// Determine if the user should be blocked.
		global $wpdb;
		$results = $wpdb->get_results(
			$wpdb->prepare('SELECT COUNT(*) as blockedCount FROM ' . $wpdb->prefix . "patchstack_firewall_log WHERE block_type = 'BLOCK' AND apply_ban = 1 AND ip = '%s' AND log_date >= ('" . current_time('mysql') . "' - INTERVAL %d MINUTE)", array($this->getIpAddress(), $time)),
			OBJECT
		);

		if (!isset($results, $results[0], $results[0]->blockedCount)) {
			return false;
		}

		return $results[0]->blockedCount > $attempts;
	}

	/**
	 * The response to return when a request has been blocked.
	 * 
	 * @param int $fid
	 * @return void
	 */
	public function forceExit($fid)
	{
		status_header(403);
		send_nosniff_header();
		nocache_headers();

		require_once dirname(__FILE__) . '/../../../../../includes/views/access-denied.php';

		exit;
	}

	/**
	 * Get the IP address of the request.
	 * 
	 * @return string
	 */
	public function getIpAddress()
	{
		return $this->core->get_ip();
	}

	/**
	 * Check the custom whitelist rules defined in the backend of WordPress
	 * and attempt to match it with the request.
	 *
	 * @return boolean
	 */
	private function isWhitelistedCustom()
	{
		$whitelist = $this->options['patchstack_custom_whitelist_rules'];
		if (empty($whitelist)) {
			return false;
		}

		// Loop through all lines.
		$lines = explode("\n", $whitelist);
		$ip    = $this->getIpAddress();

		foreach ($lines as $line) {
			$t = explode(':', $line);

			if (count($t) == 2) {
				$val = strtolower(trim($t[1]));
				switch (strtolower($t[0])) {
						// IP address match.
					case 'ip':
						if ($ip == $val) {
							return true;
						}
						break;
						// Payload match.
					case 'payload':
						if (count($_POST) > 0 && strpos(strtolower(print_r($_POST, true)), $val) !== false) {
							return true;
						}

						if (count($_GET) > 0 && strpos(strtolower(print_r($_GET, true)), $val) !== false) {
							return true;
						}
						break;
						// URL match.
					case 'url':
						if (strpos(strtolower($_SERVER['REQUEST_URI']), $val) !== false) {
							return true;
						}
						break;
				}
			}
		}

		return false;
	}

	/**
	 * Determine if the request is whitelisted.
	 */
	public function isWhitelisted($whitelistRules, $request)
	{
		// First check if the user has custom whitelist rules configured.
		if ($this->isWhitelistedCustom()) {
			return true;
		}

		// Determine if there are any whitelist rules to process.
		if (count($whitelistRules) == 0) {
			return false;
		}

		// Grab visitor's IP address and request data.
		$client_ip = $this->getIpAddress();
		$requests  = $request;

		foreach ($whitelistRules as $whitelist) {
			$whitelist_rule = json_decode($whitelist['rule']);

			// If an IP address match is given, determine if it matches.
			$ip = isset($whitelist_rule->rules, $whitelist_rule->rules->ip_address) ? $whitelist_rule->rules->ip_address : null;
			if (!is_null($ip)) {
				if (strpos($ip, '*') !== false) {
					$whitelisted_ip = $this->plugin->ban->check_wildcard_rule($client_ip, $ip);
				} elseif (strpos($ip, '-') !== false) {
					$whitelisted_ip = $this->plugin->ban->check_range_rule($client_ip, $ip);
				} elseif (strpos($ip, '/') !== false) {
					$whitelisted_ip = $this->plugin->ban->check_subnet_mask_rule($client_ip, $ip);
				} elseif ($client_ip == $ip) {
					$whitelisted_ip = true;
				} else {
					$whitelisted_ip = false;
				}
			} else {
				$whitelisted_ip = true;
			}

			foreach ($requests as $key => $request) {

				// Treat the raw POST data string as the body contents of all values combined.
				if ($key == 'rulesRawPost') {
					$key = 'rulesBodyAll';
				}

				if ($whitelist_rule->method == $requests['method'] || $whitelist_rule->method == 'ALL') {
					$test = strtolower(preg_replace('/(?!^)[A-Z]{2,}(?=[A-Z][a-z])|[A-Z][a-z]/', '->$0', $key));
					$exp = explode('->', $test);

					// Determine if a rule exists for this request.
					$rule = $whitelist_rule;
					foreach ($exp as $var){
						if(!isset($rule->$var)){
							$rule = null;
							continue;
						}
						$rule = $rule->$var;
					}

					if (!is_null($rule) && substr($key, 0, 4) == 'rule' && $this->isRuleMatch($rule, $request) && $whitelisted_ip) {
						return true;
					}
				}
			}
		}

		return false;
	}

	/**
	 * Determine if the request matches the given firewall or whitelist rule.
	 *
	 * @param string       $rule
	 * @param string|array $request
	 * @return bool
	 */
	private function isRuleMatch($rule, $request)
	{
		$is_matched = false;
		if (is_array($request)) {
			foreach ($request as $value) {
				$is_matched = $this->isRuleMatch($rule, $value);
				if ($is_matched) {
					return $is_matched;
				}
			}
		} else {
			return preg_match($rule, urldecode($request));
		}

		return $is_matched;
	}

    /**
     * Determine if the current request is a file upload request.
     * 
     * @return boolean
     */
	public function isFileUploadRequest()
	{
		return isset($_FILES) && count($_FILES) > 0;
	}
}
