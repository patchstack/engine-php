<?php

namespace Patchstack;

class Response
{
    /**
     * Perform a redirect if the request must be redirected to somewhere else.
     * 
     * @param string $redirectTo
     * @return void
     */
    public static function redirect($redirectTo)
    {
        // Don't redirect an invalid URL.
        if (!$redirectTo || filter_var($redirectTo, FILTER_VALIDATE_URL) === false) {
            return;
        }

        // Perform the redirect.
        header('Location: ' . $redirectTo, true, 302);
        exit;
    }
}
