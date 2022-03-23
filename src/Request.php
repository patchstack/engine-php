<?php

namespace Patchstack;

class Request
{
	/**
	 * The options of the engine.
	 * 
	 * @var array
	 */
	private $options;

	/**
	 * Creates a new request instance.
	 * 
	 * @param array $options
	 * @return void
	 */
	public function __construct($options)
	{
		$this->options = $options;
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
		$rulesHeadersKeys         = array();
		$rulesHeadersValues       = array();
		$rulesHeadersCombinations = array();

		// Retrieve the headers.
		$headers         = self::getHeaders();
		$rulesHeadersAll = implode(' ', $headers);
		foreach ($headers as $name => $value) {
			$rulesHeadersKeys[]         = $name;
			$rulesHeadersValues[]       = $value;
			$rulesHeadersCombinations[] = $name . ': ' . $value;
		}

		// Store the $_POST values in different formats.
		$rulesBodyKeys         = array();
		$rulesBodyValues       = array();
		$rulesBodyCombinations = array();

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
		$rulesParamsKeys         = array();
		$rulesParamsValues       = array();
		$rulesParamsCombinations = array();

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
		$headers = array();
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
	 * @param $array
	 * @param $glue
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
		$return = array();
		foreach ($_FILES as $key => $data) {
			foreach ($data as $key2 => $data2) {

				// We only want the name and type.
				if (!in_array($key2, array('name', 'type'))) {
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
		$data = array(
			'POST' => $_POST,
			'GET'  => $_GET,
		);

		// Determine if there are any keys we should remove from the data set.
		if (count($this->options['whitelistKeysRules']) == 0 || !is_array($this->options['whitelistKeysRules'])) {
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
