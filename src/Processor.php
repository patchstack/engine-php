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
    private $firewallRules = array();

    /**
     * The legacy firewall rules to process.
     *
     * @var array
     */
    private $firewallRulesLegacy = array();

    /**
     * The whitelist rules to process.
     *
     * @var array
     */
    private $whitelistRules = array();

    /**
     * The legacy whitelist rules to process.
     *
     * @var array
     */
    private $whitelistRulesLegacy = array();

    /**
     * Firewall datasets which can be interacted with by the firewall rules.
     *
     * @var array
     */
    private $dataset = array();

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
     * The secret that is used for the firewall rules integrity.
     * Default is set to "secret" for easy PHPUnit testing.
     *
     * @var string
     */
    private $secret = 'secret';

    /**
     * Creates a new processor instance.
     *
     * @param ExtensionInterface $extension
     * @param array $firewallRules
     * @param array $whitelistRules
     * @param array $options
     * @param array $datasets
     * @param array $firewallRulesLegacy
     * @param array $whitelistRulesLegacy
     * @return void
     */
    public function __construct(
        ExtensionInterface $extension,
        $firewallRules = array(),
        $whitelistRules = array(),
        $options = array(),
        $datasets = array(),
        $firewallRulesLegacy = array(),
        $whitelistRulesLegacy = array()
    ) {
        $this->extension = $extension;
        $this->firewallRules = $firewallRules;
        $this->whitelistRules = $whitelistRules;
        $this->options = array_merge($this->options, $options);
        $this->dataset = $datasets;
        $this->firewallRulesLegacy = $firewallRulesLegacy;
        $this->whitelistRulesLegacy = $whitelistRulesLegacy;

        $this->secret = isset($options['secret']) ? $options['secret'] : 'secret';
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

        // Since the Opis/Closure package does not support PHP 8.1+, we have to use Laravel's ported version for 8.1+.
        require dirname(__FILE__) . '/../vendor/autoload.php';
        if (PHP_VERSION_ID < 80100) {
            \Opis\Closure\SerializableClosure::setSecretKey($this->secret);
            $type = 'opis';
        } else {
            \Laravel\SerializableClosure\SerializableClosure::setSecretKey($this->secret);
            $type = 'laravel';
        }

        // Grab the IP address of the request.
        $ip = $this->extension->getIpAddress();

        // Store the datasets in a shorter variable for easy access.
        $dataset = $this->dataset;

        // Merge the rules together. First iterate through the whitelist rules.
        $rules = array_merge($this->whitelistRules, $this->firewallRules);
        foreach ($rules as $rule) {
            // Get the firewall rule and extract it.
            $vpatch = base64_decode($rule->rule_closure->{$type});
            if (!$vpatch) {
                continue;
            }

            // Execute the firewall rule.
            $rule_hit = false;
            try {
                $vpatch = unserialize($vpatch);
                if (!$vpatch) {
                    continue;
                }

                $closure = $vpatch->getClosure();
                $rule_hit = $closure($ip, $dataset, $request);
            } catch (\Exception $e) {
                continue;
            }

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
            $this->launchLegacy(true, $request, $ip);
        }

        return true;
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
    public function launchLegacy($mustExit = true, $request = array(), $ip = '')
    {
        // Obtain the IP address and request data if it has not been supplied yet.
        $client_ip = $ip == '' ? $this->extension->getIpAddress() : $ip;
        $requests  = count($request) == 0 ? $this->request->capture() : $request;

        // The request parameter values exploded into pairs.
        $requestParams = array(
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
        );

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
