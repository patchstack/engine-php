<?php

namespace Patchstack\Extensions\Test;

use Patchstack\Extensions\ExtensionInterface;

class Extension implements ExtensionInterface
{
    /**
     * Log the request, this can be of type BLOCK, LOG or REDIRECT.
     * 
     * @param int $ruleId
     * @param string $bodyData
     * @param string $blockType
     * @return void
     */
    public function logRequest($ruleId, $bodyData, $blockType)
    {
        return true;
    }

    /**
     * Determine if the current visitor can bypass the firewall.
     * 
     * @return bool
     */
    public function canBypass()
    {
        return false;
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
        return false;
    }

    /**
     * Force exit the page when a request has been blocked.
     * 
     * @param int $ruleId
     * @return void
     */
    public function forceExit($ruleId)
    {
        exit;
    }

    /**
     * Get the IP address of the request.
     * 
     * @return string
     */
    public function getIpAddress()
    {
        return '127.0.0.1';
    }

    /**
     * Determine if the request should be passed without going through the firewall.
     * 
     * @param array $whitelistRules
     * @param array $request
     */
    public function isWhitelisted($whitelistRules, $request)
    {
        return false;
    }

    /**
     * Determine if the current request is a file upload request.
     * 
     * @return boolean
     */
    public function isFileUploadRequest()
    {
        return false;
    }
}