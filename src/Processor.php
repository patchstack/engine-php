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

        $this->request = new Request($this->options);
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

        // Determine if we have any firewall and/or whitelist rules loaded.
        if (count($this->firewallRules) == 0 && count($this->whitelistRules) == 0) {
            return true;
        }

        // Merge the rules together. First iterate through the whitelist rules.
        $rules = array_merge($this->whitelistRules, $this->firewallRules);
        foreach ($rules as $rule) {
            // Should never happen.
            if (!isset($rule->rules) || empty($rule->rules)) {
                continue;
            }

            // Execute the firewall rule.
            $rule_hit = $this->executeFirewall(json_decode(json_encode($rule->rules), true));

            // If the payload did not match the rule, continue.
            if (!$rule_hit) {
                continue;
            }

            // Determine what action to perform.
            if ($rule->type == 'BLOCK') {
                $this->extension->logRequest($rule->id, $request, 'BLOCK');

                // Do we have to exit the page or simply return false?
                if ($mustExit) {
                    $this->extension->forceExit($rule->id);
                } else {
                    return false;
                }
            } elseif ($rule->type == 'LOG') {
                $this->extension->logRequest($rule->id, $request, 'LOG');
            } elseif ($rule->type == 'REDIRECT') {
                $this->extension->logRequest($rule->id, $request, 'REDIRECT');
                $this->response->redirect($rule->type_params, $mustExit);
            } elseif ($rule->type == 'WHITELIST') {
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
            $value = $this->getParameterValue($rule['parameter']);
            if (is_null($value)) {
                continue;
            }

            // Apply mutations, if any.
            if (isset($rule['mutations']) && is_array($rule['mutations'])) {
                $value = $this->applyMutation($rule['mutations'], $value);
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
        if ($matchType == 'equals' && is_scalar($value)) {
            return $matchValue == $value;
        }

        if ($matchType == 'bigger_than' && is_scalar($value)) {
            return $value > $matchValue;
        }

        if ($matchType == 'less_than' && is_scalar($value)) {
            return $value < $matchValue;
        }

        if ($matchType == 'isset') {
            return true;
        }

        if ($matchType == 'ctype_digit' && is_scalar($value)) {
            return @ctype_digit($value) === $matchValue;
        }

        if ($matchType == 'ctype_alnum' && is_scalar($value)) {
            return @ctype_alnum($value) === $matchValue;
        }

        if ($matchType == 'is_numeric' && is_scalar($value)) {
            return @is_numeric($value) === $matchValue;
        }

        if (($matchType == 'contains' || $matchType == 'stripos') && is_scalar($value)) {
            return @stripos($value, $matchValue) !== false;
        }

        if ($matchType == 'regex' && is_scalar($value)) {
            return @preg_match($matchValue, @urldecode($value)) === 1;
        }

        if ($matchType == 'current_user_cannot' && function_exists('current_user_can')) {
            return @!current_user_can($matchValue);
        }

        if ($matchType == 'in_array' && !is_array($value)) {
            return @in_array($value, $matchValue);
        }

        if ($matchType == 'not_in_array' && !is_array($value)) {
            return @!in_array($value, $matchValue);
        }

        if ($matchType == 'array_in_array' && is_array($value)) {
            return @array_intersect($value, $matchValue);
        }

        if ($matchType == 'array_key_value' && isset($match['key'], $match['match'])) {
            $value = $this->getParameterValue($match['key'], $value);
            return $this->matchParameterValue($match['match'], $value);
        }

        return false;
    }

    /**
     * Grab the request parameters we are trying to capture for the given rule.
     * 
     * @param mixed $parameter
     * @param array $data
     * @return mixed|null
     */
    public function getParameterValue($parameter, $data = [])
    {
        // For when a rule contains sub-rules.
        if (ctype_digit($parameter) || empty($parameter)) {
            return null;
        }

        // Explode on the dot to grab the proper key value.
        $t = explode('.', $parameter);
        $type = $t[0];

        if (count($data) == 0) {
            array_shift($t);
        }

        switch ($type) {
            case 'post':
                $data = $_POST;
                break;
            case 'get':
                $data = $_GET;
                break;
            case 'request':
                $data = $_REQUEST;
                break;
            case 'cookie':
                $data = $_COOKIE;
                break;
            case 'files':
                $data = $_FILES;
                break;
            case 'server':
                $data = $_SERVER;
                break;
            case 'raw':
                $data = @file_get_contents( 'php://input' );

                // Ignore if no data in payload.
                if (empty($data)) {
                    $data = [];
                    break;
                }

                // Determine if it's base64 encoded.
                if (preg_match('%^[a-zA-Z0-9/+]*={0,2}$%', $data)) {
                    $decoded = base64_decode($data, true);
                    if ($decoded !== false) {
                        $encoding = mb_detect_encoding($decoded);
                        if (in_array($encoding, ['UTF-8', 'ASCII'], true) && $decoded !== false && base64_encode($decoded) === $data) {
                            $data = $decoded;
                        }
                    }
                }

                // Determine if it's JSON encoded.
                $result = json_decode($data, true);
                if (is_array($result)) {
                    $data = $result;
                }

                // If it's not an array, no need to continue.
                if (!is_array($data)) {
                    return $data;
                }
            default:
                break;
        }

        // No need to continue if we don't have any data to match against.
        if (count($data) == 0) {
            return null;
        }

        // Special condition for the IP address.
        if ($type === 'server' && $t[0] === 'ip') {
            return [$this->extension->getIpAddress()];
        }

        // Just one parameter we have to match against.
        if (count($t) === 1) {
            return isset($data[$t[0]]) ? $data[$t[0]] : null;
        }

        // For multidimensional arrays.
        $end  = $data;
        $skip = false;
        foreach ( $t as $var ) {
            if ( ! isset( $end[ $var ] ) ) {
                $skip = true;
                break;
            }
            $end = $end[ $var ];
        }

        return $skip ? null : $end;
    }

    /**
     * Apply mutations to the captured value.
     * 
     * @param array $mutations
     * @param mixed $value
     * @return mixed
     */
    public function applyMutation($mutations, $value)
    {
        if (count($mutations) === 0) {
            return $value;
        }

        // Define the allowed mutations.
        // Array value contains the arguments to pass to the function as well as expected type.
        $allowed = [
            'json_encode' => [
                'args' => []
            ],
            'json_decode' => [
                'args' => [true],
                'type' => 'is_string'
            ],
            'base64_decode' => [
                'args' => [],
                'type' => 'is_string'
            ],
            'intval' => [
                'args' => [],
                'type' => 'is_scalar'
            ]
        ];

        // If it's not a whitelisted mutation, reject and return original value.
        foreach ($mutations as $mutation) {
            if (!isset($allowed[$mutation])) {
                return $value;
            }
        }

        // Apply the mutations in ascending order.
        try {
            foreach ($mutations as $mutation) {
                // In order to avoid errors if the wrong type of value is passed to the function.
                if (isset($allowed[$mutation]['type']) && !call_user_func($allowed[$mutation]['type'], $value)) {
                    continue;
                }

                // Call the function with given arguments.
                $value = call_user_func_array($mutation, array_merge([$value], $allowed[$mutation]['args']));

                // No need to continue in these scenarios.
                if (is_null($value) || $value === false || $value === 0) {
                    return $value;
                }
            }
        } catch (\Exception $e) {
            return $value;
        }

        return $value;
    }

    /**
     * The legacy firewall processor will only iterate over the general firewall rules.
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
                    if (!is_null($rule) && substr($key, 0, 4) == 'rule' && $this->isRuleMatch($rule, $request)) {
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
}
