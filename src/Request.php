<?php

namespace Patchstack;

use Patchstack\Extensions\ExtensionInterface;

class Request
{
    /**
     * The options of the engine.
     *
     * @var array
     */
    private $options;

    /**
     * The extension that will process specific logic for the CMS.
     *
     * @var ExtensionInterface
     */
    private $extension;

    /**
     * Creates a new request instance.
     *
     * @param  array $options
     * @return void
     */
    public function __construct($options, ExtensionInterface $extension)
    {
        $this->options = $options;
        $this->extension = $extension;
    }

    /**
     * Grab the request parameters we are trying to capture for the given rule.
     * 
     * @param mixed $parameter
     * @param array $data
     * @return mixed
     */
    public function getParameterValues($parameter, $data = [])
    {
        // For when a rule contains sub-rules.
        if (empty($parameter) || ctype_digit($parameter)) {
            return null;
        }

        // Explode on the dot to grab the proper key value.
        $t = explode('.', $parameter);
        $type = $t[0];

        if (count($data) == 0) {
            array_shift($t);
        }

        switch ($type) {
            case 'all':
                $data = [
                    'post' => $_POST,
                    'get' => $_GET,
                    'url' => isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '',
                    'raw' => ['raw' => $this->getParameterValues('raw')]
                ];
                break;
            case 'log':
                return [
                    'post' => $_POST,
                    'raw' => $this->getParameterValues('raw')
                ];
                break;
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
                    return [$data];
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

        // For wildcard matching we handle it a bit differently.
        // We want to extract all wildcard matches and pass them as an array so we
        // can execute a firewall rule against all the fields that match.
        if (strpos($parameter, '*') !== false) {
            $values = $this->getValuesByWildcard($data, $parameter);
            return count($values) == 0 ? null : $values;
        }

        // Just one parameter we have to match against.
        if (count($t) === 1) {
            return isset($data[$t[0]]) ? [$data[$t[0]]] : null;
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

        return $skip ? null : [$end];
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
            ],
            'urldecode' => [
                'args' => [],
                'type' => 'is_string'
            ],
            'getArrayValues' => [
                'args' => [],
                'type' => 'is_array'
            ],
            'getShortcodeAtts' => [
                'args' => [],
                'type' => 'is_string'
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
                if ($mutation == 'getArrayValues') {
                    $value = $this->getArrayValues($value);
                } elseif ($mutation == 'getShortcodeAtts') {
                    $value = $this->getShortcodeAtts($value);
                } else {
                    $value = call_user_func_array($mutation, array_merge([$value], $allowed[$mutation]['args']));
                }
                
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
     * Given an array, get all parameters which match a certain wildcard.
     * 
     * @param array $data
     * @param string $parameter
     * @return array
     */
    public function getValuesByWildcard($data, $parameter)
    {
        // First we want to get the furthest possible down.
        $t = explode('.', $parameter);
        array_shift($t);
        $end  = $data;
        $wildcard = '';
        foreach ( $t as $var ) {
            
            // We hit the wildcard.
            if (strpos($var, '*') !== false) {
                $wildcard = str_replace('*', '', $var);
                break;
            }
            
            // We're not at the end and there's no wildcard.
            if (!isset( $end[ $var ] ) && strpos($var, '*') === false) {
                return [];
            }

            $end = $end[ $var ];
        }
        
        // No need to continue if there is nothing to match.
        if (!is_array($end) || count($end) == 0) {
            return [];
        }

        // Based on the data that is left, find the wildcard matches.
        $return = [];
        foreach ($end as $key => $value) {
            if (stripos($key, $wildcard) !== false) {
                $return[] = $value;
            }
        }
        
        return $return;
    }

    /**
     * Given an array, multi-dimensional or not, extract all of its values.
     * 
     * @param array $data
     * @param string $glue
     * @param string $type
     * @return string|array
     */
    public function getArrayValues($data, $glue = '&', $type = 'string')
    {
        // If we want to return a single line string.
        if ($type == 'string') {
            $ret = '';
            foreach ($data as $key => $item) {
                if (empty($item)) {
                    continue;
                }
    
                if (is_array($item)) {
                    $ret .= $this->getArrayValues($item, $glue) . $glue;
                } else {
                    $ret .= $key . '=' . $item . $glue;
                }
            }
    
            return substr($ret, 0, 0 - strlen($glue));
        }
        
        // Or a single dimension array with each value its own entry.
        $ret = [];
        foreach ($data as $key => $item) {
            if (empty($item)) {
                continue;
            }

            if (is_array($item)) {
                $ret = array_merge($ret, $this->getArrayValues($item, $glue, 'array'));
            } else {
                $ret[] = $item;
            }
        }

        return $ret;
    }

    /**
     * Given a string, fetch all shortcodes and its attributes.
     * 
     * @param string $value
     * @return array
     */
    public function getShortcodeAtts($value)
    {
        // For rare cases where this may not be defined.
        if (!function_exists('shortcode_parse_atts')) {
            return [];
        }

        // The regular expression used by WordPress core to fetch shortcodes and its attributes.
        preg_match_all(
            '/\[(\[?)(.*?)(?![\w-])([^\]\/]*(?:\/(?!\])[^\]\/]*)*?)(?:(\/)\]|\](?:([^\[]*+(?:\[(?!\/\2\])[^\[]*+)*+)\[\/\2\])?)(\]?)/',
            $value,
            $shortcodes,
            PREG_SET_ORDER
        );

        // No matches.
        if (count($shortcodes) == 0) {
            return [];
        }

        // Iterate through all shortcodes and fetch their attributes.
        $return = [];
        foreach ($shortcodes as $shortcode) {
            if (!isset($shortcode[2], $shortcode[3], $shortcode[5])) {
                continue;
            }

            // Merge together if the shortcode occurs more than once.
            if (isset($return[$shortcode[2]])) {
                $atts = @\shortcode_parse_atts($shortcode[3]);
                foreach ($atts as $key => $value) {
                    if (isset($return[$shortcode[2]][$key])) {
                        $return[$shortcode[2]][$key] .= $value;
                    } else {
                        $return[$shortcode[2]][$key] = $value;
                    }
                }
            } else {
                $return[$shortcode[2]] = @\shortcode_parse_atts($shortcode[3]);
            }
        }

        return $return; 
    }
}
