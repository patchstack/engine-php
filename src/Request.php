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
     * @return mixed|null
     */
    public function getParameterValue($parameter, $data = [])
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
                    'raw' => ['raw' => $this->getParameterValue('raw')]
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
            return $this->extension->getIpAddress();
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
            ],
            'urldecode' => [
                'args' => [],
                'type' => 'is_string'
            ],
            'getArrayValues' => [
                'args' => [],
                'type' => 'is_array'
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
     * Returns all the information related to the request.
     *
     * @return array
     */
    public function capture()
    {
        $data = self::captureKeys();

        // Get the method and URL.
        $method   = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
        $rulesUri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';

        // Store the header values in different formats.
        $rulesHeadersKeys         = [];
        $rulesHeadersValues       = [];
        $rulesHeadersCombinations = [];

        // Retrieve the headers.
        $headers         = self::getHeaders();
        $rulesHeadersAll = implode(' ', $headers);
        foreach ($headers as $name => $value) {
            $rulesHeadersKeys[]         = $name;
            $rulesHeadersValues[]       = $value;
            $rulesHeadersCombinations[] = $name . ': ' . $value;
        }

        // Store the $_POST values in different formats.
        $rulesBodyKeys         = [];
        $rulesBodyValues       = [];
        $rulesBodyCombinations = [];

        // Retrieve the $_POST values.
        $rulesBodyAll = urldecode(http_build_query($data['POST']));
        foreach ($data['POST'] as $key => $value) {
            if (is_array($value)) {
                $value = @self::multiImplode($value, ' ');
            }
            $rulesBodyKeys[]         = $key;
            $rulesBodyValues[]       = $value;
            $rulesBodyCombinations[] = $key . '=' . $value;
        }

        // Store the $_GET values in different formats.
        $rulesParamsKeys         = [];
        $rulesParamsValues       = [];
        $rulesParamsCombinations = [];

        // Retrieve the $_GET values.
        $rulesParamsAll = urldecode(http_build_query($data['GET']));
        foreach ($data['GET'] as $key => $value) {
            if (is_array($value)) {
                $value = self::multiImplode($value, ' ');
            }
            $rulesParamsKeys[]         = $key;
            $rulesParamsValues[]       = $value;
            $rulesParamsCombinations[] = $key . '=' . $value;
        }

        // Raw POST data.
        $rulesRawPost = @file_get_contents('php://input');

        // Data about file uploads.
        $rulesFile = self::getUploadData();

        // Return each value as its own array.
        return compact(
            'method',
            'rulesFile',
            'rulesRawPost',
            'rulesUri',
            'rulesHeadersAll',
            'rulesHeadersKeys',
            'rulesHeadersValues',
            'rulesHeadersCombinations',
            'rulesBodyAll',
            'rulesBodyKeys',
            'rulesBodyValues',
            'rulesBodyCombinations',
            'rulesParamsAll',
            'rulesParamsKeys',
            'rulesParamsValues',
            'rulesParamsCombinations'
        );
    }

    /**
     * Retrieve all HTTP headers that start with HTTP_.
     *
     * @return array
     */
    public function getHeaders()
    {
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }

        return $headers;
    }

    /**
     * Implode array recursively.
     *
     * @param  $array
     * @param  $glue
     * @return bool|string
     */
    private function multiImplode($array, $glue)
    {
        $ret = '';

        foreach ($array as $item) {
            if (is_array($item)) {
                $ret .= self::multiImplode($item, $glue) . $glue;
            } else {
                $ret .= $item . $glue;
            }
        }

        return substr($ret, 0, 0 - strlen($glue));
    }

    /**
     * Retrieve information about any file uploads.
     *
     * @return array
     */
    private function getUploadData()
    {
        if (!is_array($_FILES) || count($_FILES) == 0) {
            return '';
        }

        // Extract the information we need from $_FILES.
        $return = [];
        foreach ($_FILES as $data) {
            foreach ($data as $key2 => $data2) {
                // We only want the name and type.
                if (!in_array($key2, ['name', 'type'])) {
                    continue;
                }

                if (!is_array($data2)) {
                    $return[] = $key2 . '=' . $data2;
                } else {
                    $return[] = $key2 . '=' . @self::multiImplode($data2, '&' . $key2 . '=');
                }
            }
        }

        return implode('&', $return);
    }

    /**
     * Capture the keys of the request.
     *
     * @return array
     */
    public function captureKeys()
    {
        // Data we want to go through.
        $data = [
            'POST' => $_POST,
            'GET'  => $_GET,
        ];

        // No need to continue if the option does not exist.
        if (!isset($this->options['whitelistKeysRules'])) {
            return $data;
        }

        // Determine if there are any keys we should remove from the data set.
        if (!is_array($this->options['whitelistKeysRules']) || count($this->options['whitelistKeysRules']) == 0) {
            return $data;
        }

        // Remove the keys where necessary, go through all data types (GET, POST).
        foreach ($this->options['whitelistKeysRules'] as $type => $entries) {
            // Go through all whitelisted actions.
            foreach ($entries as $entry) {
                $t = explode('.', $entry);

                // For non-multidimensional array checks.
                if (count($t) == 1) {
                    // If the value itself exists.
                    if (isset($data[$type][$t[0]])) {
                        unset($data[$type][$t[0]]);
                    }

                    // For pattern checking.
                    if (strpos($t[0], '*') !== false) {
                        $star = explode('*', $t[0]);

                        // Loop through all $_POST, $_GET values.
                        foreach ($data as $method => $values) {
                            foreach ($values as $key => $value) {
                                if (!is_array($value) && strpos($key, $star[0]) !== false) {
                                    unset($data[$method][$key]);
                                }
                            }
                        }
                    }
                    continue;
                }

                // For multidimensional array checks.
                $end  = &$data[$type];
                $skip = false;
                foreach ($t as $var) {
                    if (!isset($end[$var])) {
                        $skip = true;
                        break;
                    }
                    $end = &$end[$var];
                }

                // Since we cannot unset it due to it being a reference variable,
                // we just set it to an empty string instead.
                if (!$skip) {
                    $end = '';
                }
            }
        }

        return $data;
    }
}
