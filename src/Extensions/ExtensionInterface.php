<?php

namespace Patchstack\Extensions;

/**
 * Any extension must implement the methods of the interface.
 * Some CMS systems might implement some of the logic completely different than others.
 */
interface ExtensionInterface
{
    /**
     * Log the request, this can be of type BLOCK, LOG or REDIRECT.
     *
     * @param  int    $ruleId
     * @param  string $bodyData
     * @param  string $blockType
     * @return void
     */
    public function logRequest($ruleId, $bodyData, $blockType);

    /**
     * Determine if the current visitor can bypass the firewall.
     *
     * @return bool
     */
    public function canBypass();

    /**
     * Determine if the visitor is blocked from the website.
     *
     * @param  int $minutes
     * @param  int $blockTime
     * @param  int $attempts
     * @return bool
     */
    public function isBlocked($minutes, $blockTime, $attempts);

    /**
     * Force exit the page when a request has been blocked.
     *
     * @param  int $ruleId
     * @return void
     */
    public function forceExit($ruleId);

    /**
     * Get the IP address of the request.
     *
     * @return string
     */
    public function getIpAddress();

    /**
     * Determine if the request should be passed without going through the firewall.
     *
     * @param array $whitelistRules
     * @param array $request
     */
    public function isWhitelisted($whitelistRules, $request);

    /**
     * Determine if the current request is a file upload request.
     *
     * @return boolean
     */
    public function isFileUploadRequest();
}
