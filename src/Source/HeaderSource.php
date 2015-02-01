<?php

namespace Riimu\Kit\CSRF\Source;

/**
 * Looks for the token sent in request headers.
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2014, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class HeaderSource implements TokenSource
{
    /** @var string Name of the custom header used to send the csrf token */
    private $headerName;

    /**
     * Creates a new instance of HeaderSource.
     * @param string $headerName Case insensitive name of the header
     */
    public function __construct($headerName = 'X-CSRF-Token')
    {
        $this->headerName = $headerName;
    }

    public function getRequestToken()
    {
        if (function_exists('apache_request_headers')) {
            $token = $this->getHeader($this->headerName, apache_request_headers());

            if ($token !== false) {
                return $token;
            }
        }

        return $this->getHeader('HTTP_' . str_replace('-', '_', $this->headerName), $_SERVER);
    }

    /**
     * Returns the case insensitive header from the list of headers.
     * @param string $name name of the header
     * @param string[] $headers List of headers
     * @return string|false Contents of the header or false if it does not exist
     */
    private function getHeader($name, $headers)
    {
        $headers = array_change_key_case($headers);
        $name = strtolower($name);

        return isset($headers[$name]) ? $headers[$name] : false;
    }
}
