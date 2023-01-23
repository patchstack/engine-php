<?php

namespace Patchstack;

use Patchstack\Response;
use Patchstack\Request;
use Patchstack\Extensions\ExtensionInterface;

class Processor
{
    /**
     * The firewall rules to process.
     *
     * @var array
     */
    private $firewallRules = [];

    /**
     * The legacy firewall rules to process.
     *
     * @var array
     */
    private $firewallRulesLegacy = [];

    /**
     * The whitelist rules to process.
     *
     * @var array
     */
    private $whitelistRules = [];

    /**
     * The legacy whitelist rules to process.
     *
     * @var array
     */
    private $whitelistRulesLegacy = [];

    /**
     * The options of the engine.
     *
     * @var array
     */
    private $options = [
        'autoblockAttempts' => 10,
        'autoblockMinutes' => 30,
        'autoblockTime' => 60,
        'whitelistKeysRules' => []
    ];

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
     * @param ExtensionInterface $extension
     * @param array $firewallRules
     * @param array $whitelistRules
     * @param array $options
     * @param array $firewallRulesLegacy
     * @param array $whitelistRulesLegacy
     * @return void
     */
    public function __construct(
        ExtensionInterface $extension,
        $firewallRules = [],
        $whitelistRules = [],
        $options = [],
        $firewallRulesLegacy = [],
        $whitelistRulesLegacy = []
    ) {
        $this->extension = $extension;
        $this->firewallRules = $firewallRules;
        $this->whitelistRules = $whitelistRules;
        $this->options = array_merge($this->options, $options);
        $this->firewallRulesLegacy = $firewallRulesLegacy;
        $this->whitelistRulesLegacy = $whitelistRulesLegacy;

        $this->request = new Request($this->options, $this->extension);
        $this->response = new Response($this->options);
    }

    /**
     * Magic getter for the options.
     *
     * @param string $name
     * @return mixed
     */
    public function __get($name)
    {
        return isset($this->options[$name]) ? $this->options[$name] : null;
    }

    /**
     * Launch the firewall. First we determine if the user is blocked and whitelisted, then go through
     * all of the firewall rules.
     *
     * Will return true if $mustExit is false and all of the rules were processed without a positive detection.
     *
     * @param boolean $mustExit
     * @return boolean
     */
    public function launch($mustExit = true)
    {
        // Determine if the user is temporarily blocked from the site before we do anything else.
        if ($this->extension->isBlocked($this->autoblockMinutes, $this->autoblockTime, $this->autoblockAttempts) && !$this->extension->canBypass()) {
            $this->extension->forceExit(22);
        }

        // Check for whitelist based on the legacy whitelist rules.
        $request  = $this->request->capture();
        if ($this->extension->isWhitelisted($this->whitelistRulesLegacy, $request)) {
            return true;
        }

        // Determine if we have a valid configuration passed.
        if (!is_array($this->firewallRules) || !is_array($this->whitelistRules)) {
            return true;
        }

        // Determine if we have any firewall and/or whitelist rules loaded.
        if (count($this->firewallRules) == 0 && count($this->whitelistRules) == 0) {
            return true;
        }

        // Determine if the current request is whitelisted or not (role based).
        $isWhitelisted = $this->extension->canBypass();

        // Merge the rules together. First iterate through the whitelist rules.
        $rules = array_merge($this->whitelistRules, $this->firewallRules);
        foreach ($rules as $rule) {
            // Should never happen.
            if (!isset($rule['rules']) || empty($rule['rules'])) {
                continue;
            }

            // If this rule should respect the whitelist, we check this before we continue.
            if (isset($rule['bypass_whitelist']) && ($rule['bypass_whitelist'] === 0 || $rule['bypass_whitelist'] === false) && $isWhitelisted) {
                continue;
            }

            // Execute the firewall rule.
            $rule_hit = $this->executeFirewall($rule['rules']);

            // If the payload did not match the rule, continue on to the next rule.
            if (!$rule_hit) {
                continue;
            }

            // Determine what action to perform.
            if ($rule['type'] == 'BLOCK') {
                $this->extension->logRequest($rule['id'], $request, 'BLOCK');

                // Do we have to exit the page or simply return false?
                if ($mustExit) {
                    $this->extension->forceExit($rule['id']);
                } else {
                    return false;
                }
            } elseif ($rule['type'] == 'LOG') {
                $this->extension->logRequest($rule['id'], $request, 'LOG');
            } elseif ($rule['type'] == 'REDIRECT') {
                $this->extension->logRequest($rule['id'], $request, 'REDIRECT');
                $this->response->redirect($rule['type_params'], $mustExit);
            } elseif ($rule['type'] == 'WHITELIST') {
                return $mustExit;
            }
        }

        // Run the legacy firewall rules processor for backwards compatibility.
        if (count($this->firewallRulesLegacy) > 0) {
            $this->launchLegacy(true, $request, $this->extension->getIpAddress());
        }

        return true;
    }

    /**
     * Execute the firewall rules.
     * 
     * @param array $rules
     * @return bool
     */
    public function executeFirewall($rules)
    {
        // Count number of inclusive rules, if any.
        $inclusiveCount = 0;
        if (count($rules) > 1) {
            $inclusiveCount = $this->getInclusiveCount($rules);
        }

        // Keep track of how many inclusive rule hits.
        $inclusiveHits = 0;

        // Loop through all of the conditions for this rule.
        foreach ($rules as $rule) {
            // Parameter must always be present.
            if (!isset($rule['parameter'])) {
                continue;
            }

            // Extract the value of the paramater that we want.
            $value = $this->request->getParameterValue($rule['parameter']);
            if (is_null($value)) {
                continue;
            }

            // Apply mutations, if any.
            if (isset($rule['mutations']) && is_array($rule['mutations'])) {
                $value = $this->request->applyMutation($rule['mutations'], $value);
                if (is_null($value)) {
                    continue;
                }
            }

            // Perform the matching.
            if (isset($rule['match']) && is_array($rule['match']) || isset($rule['rules'])) {

                // Do we have to process child-rules?
                if (isset($rule['rules'])) {
                    $match = $this->executeFirewall($rule['rules']);
                } else {
                    $match = $this->matchParameterValue($rule['match'], $value);
                }

                // Is the rule a match?
                if ($match) {
                    // In case there are multiple rules, they may require chained AND conditions.
                    if ($inclusiveCount <= 1) {
                        return true;
                    } else {
                        $inclusiveHits++;
                    }
                }
            }
        }

        // In case we hit all of the AND conditions.
        if ($inclusiveCount > 1 && $inclusiveHits === $inclusiveCount) {
            return true;
        }

        return false;
    }

    /**
     * Get the number of inclusive rules as part of the rule group.
     * 
     * @param array $rules
     * @return int
     */
    public function getInclusiveCount($rules)
    {
        if (count($rules) == 1) {
            return 1;
        }

        $count = 0;
        foreach ($rules as $rule) {
            if (isset($rule['inclusive']) && $rule['inclusive'] === true) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * With the given parameter value, attempt to match it.
     * 
     * @param mixed $match
     * @param mixed $value
     * @return bool
     */
    public function matchParameterValue($match, $value)
    {
        // Take some of the parameters for easy access.
        $matchType = isset($match['type']) ? $match['type'] : null;
        $matchValue = isset($match['value']) ? $match['value'] : null;

        // Perform a match depending on the given match type.
        // If a scalar matches another scalar (loose).
        if ($matchType == 'equals' && is_scalar($value) && is_scalar($matchValue)) {
            return $matchValue == $value;
        }

        // If a scalar matches another scaler (strict).
        if ($matchType == 'equals_strict' && is_scalar($value) && is_scalar($matchValue)) {
            return $matchValue === $value;
        }

        // If a scalar is bigger than another scalar.
        if ($matchType == 'more_than' && is_scalar($value) && is_scalar($matchValue)) {
            return $value > $matchValue;
        }

        // If a scalar is less than another scalar.
        if ($matchType == 'less_than' && is_scalar($value) && is_scalar($matchValue)) {
            return $value < $matchValue;
        }

        // If the parameter is present at all.
        if ($matchType == 'isset') {
            return true;
        }

        // If a scaler is a ctype digit.
        if ($matchType == 'ctype_digit' && is_scalar($value)) {
            return @ctype_digit($value) === $matchValue;
        }

        // If a scaler is a ctype alnum.
        if ($matchType == 'ctype_alnum' && is_scalar($value)) {
            return @ctype_alnum($value) === $matchValue;
        }

        // If a scalar is numeric.
        if ($matchType == 'is_numeric' && is_scalar($value)) {
            return @is_numeric($value) === $matchValue;
        }

        // If a scalar contains a value.
        if (($matchType == 'contains' || $matchType == 'stripos') && is_scalar($value)) {
            return @stripos($value, $matchValue) !== false;
        }

        // If a string matches a regular expression.
        if ($matchType == 'regex' && is_string($matchValue) && is_scalar($value)) {
            return @preg_match($matchValue, @urldecode($value)) === 1;
        }

        // If the user does not have a WP privilege.
        if ($matchType == 'current_user_cannot' && is_scalar($matchValue) && function_exists('current_user_can')) {
            return @!current_user_can($matchValue);
        }

        // If a value is in an array.
        if ($matchType == 'in_array' && !is_array($value) && is_array($matchValue)) {
            return @in_array($value, $matchValue);
        }

        // If a value is not in an array.
        if ($matchType == 'not_in_array' && !is_array($value) && is_array($matchValue)) {
            return @!in_array($value, $matchValue);
        }

        // If an array of values is in another array of values.
        if ($matchType == 'array_in_array' && is_array($value) && is_array($matchValue)) {
            return @array_intersect($value, $matchValue);
        }

        // If a specific parameter key matches a sub-match condition.
        if ($matchType == 'array_key_value' && isset($match['key'], $match['match'])) {
            $value = $this->request->getParameterValue($match['key'], $value);
            return $this->matchParameterValue($match['match'], $value);
        }

        // If the user provided value does not match the current hostname.
        if ($matchType == 'hostname' && is_string($value)) {
            if (empty($value)) {
                return false;
            }

            // We only care about the hostname.
            $host = parse_url($value, PHP_URL_HOST);
            if (!$host) {
                return true;
            }

            return $host !== $this->extension->getHostName();
        }

        // If any of the uploaded files in the parameter matches a sub-match condition.
        if ($matchType == 'file_contains' && isset($match['match'])) {
            // Extract all tmp_names.
            if (isset($value['tmp_name'])) {
                $files = $value['tmp_name'];
                if (!is_array($files)) {
                    $files = [$files];
                }
            } else {
                $files = array_column($value, 'tmp_name');
            }
            
            // No need to continue if there are no files.
            if (is_array($files) && count($files) === 0) {
                return false;
            }

            // Cast all tmp_names to a single-dimension array.
            $files = $this->request->getArrayValues($files, '', 'array');
            if (is_array($files) && count($files) === 0) {
                return false;
            }

            // Get the contents of the files.
            $contents = '';
            foreach ($files as $file) {
                $contents .= (string) @file_get_contents($file);
            }

            // Now attempt to match it.
            return $this->matchParameterValue($match['match'], $contents);
        }

        return false;
    }

    /**
     * The legacy firewall processor will only iterate over the general legacy firewall rules.
     * Will return true if $mustExit is false and all of the rules were processed without a positive detection.
     *
     * @param boolean $mustExit
     * @param array $request
     * @param string $ip
     * @return boolean
     */
    public function launchLegacy($mustExit = true, $request = [], $ip = '')
    {
        // Obtain the IP address and request data if it has not been supplied yet.
        $client_ip = $ip == '' ? $this->extension->getIpAddress() : $ip;
        $requests  = count($request) == 0 ? $this->request->capture() : $request;

        // The request parameter values exploded into pairs.
        $requestParams = [
            'method' => 'method',
            'rulesFile' => 'rules->file',
            'rulesRawPost' => 'rules->raw->post',
            'rulesUri' => 'rules->uri',
            'rulesHeadersAll' => 'rules->headers->all',
            'rulesHeadersKeys' => 'rules->headers->keys',
            'rulesHeadersValues' => 'rules->headers->values',
            'rulesHeadersCombinations' => 'rules->headers->combinations',
            'rulesBodyAll' => 'rules->body->all',
            'rulesBodyKeys' => 'rules->body->keys',
            'rulesBodyValues' => 'rules->body->values',
            'rulesBodyCombinations' => 'rules->body->combinations',
            'rulesParamsAll' => 'rules->params->all',
            'rulesParamsKeys' => 'rules->params->keys',
            'rulesParamsValues' => 'rules->params->values',
            'rulesParamsCombinations' => 'rules->params->combinations'
        ];

        // Iterate through all root objects.
        foreach ($this->firewallRulesLegacy as $firewall_rule) {
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

            // Loop through all request data that we captured.
            foreach ($requests as $key => $request) {
                // Treat the raw POST data string as the body contents of all values combined.
                if ($key == 'rulesRawPost') {
                    $key = 'rulesBodyAll';
                }

                // Determine if the requesting method matches.
                if ($rule_terms->method == $requests['method'] || $rule_terms->method == 'ALL' || $rule_terms->method == 'GET' || ($rule_terms->method == 'FILES' && $this->extension->isFileUploadRequest())) {
                    if (!isset($requestParams[$key])) {
                        continue;
                    }
                    $exp  = explode('->', $requestParams[$key]);

                    // Determine if a rule exists for this request.
                    $rule = $rule_terms;
                    foreach ($exp as $var) {
                        if (!isset($rule->$var)) {
                            $rule = null;
                            continue;
                        }
                        $rule = $rule->$var;
                    }

                    // Determine if the rule matches the request.
                    if (!is_null($rule) && substr($key, 0, 4) == 'rule' && $this->isLegacyRuleMatch($rule, $request)) {
                        if ($rule_terms->type == 'BLOCK') {
                            $this->extension->logRequest($firewall_rule['id'], $request, 'BLOCK');

                            // Do we have to exit the page or simply return false?
                            if ($mustExit) {
                                $this->extension->forceExit($firewall_rule['id']);
                            } else {
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
            }
        }

        return true;
    }

    /**
     * Determine if the request matches the given firewall or whitelist rule.
     *
     * @param string $rule
     * @param string|array $request
     * @return bool
     */
    private function isLegacyRuleMatch($rule, $request)
    {
        $is_matched = false;
        if (is_array($request)) {
            foreach ($request as $value) {
                $is_matched = $this->isLegacyRuleMatch($rule, $value);
                if ($is_matched) {
                    return $is_matched;
                }
            }
        } else {
            return preg_match($rule, urldecode($request));
        }

        return $is_matched;
    }
}
