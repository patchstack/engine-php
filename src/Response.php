<?php

namespace Patchstack;

class Response
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
	public function __construct($options = array())
	{
		$this->options = $options;
	}

    /**
     * Perform a redirect if the request must be redirected to somewhere else.
     * The caller should exit the script.
     * 
     * @param string $redirectTo
     * @return void
     */
    public function redirect($redirectTo)
    {
        // Don't redirect an invalid URL.
        if (!$redirectTo || filter_var($redirectTo, FILTER_VALIDATE_URL) === false) {
            return false;
        }

        // Perform the redirect.
        header('Location: ' . $redirectTo, true, 302);
    }
}
