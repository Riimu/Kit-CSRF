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
    private $header;

    /**
     * Creates a new instance of HeaderSource.
     * @param string $headerName Case insensitive name of the header
     */
    public function __construct($headerName = 'X-CSRF-Token')
    {
        $this->header = $headerName;
    }

    public function getRequestToken()
    {
        $token = $this->getHeader($this->header, $this->getRequestHeaders());

        if ($token === false) {
            $header = 'HTTP_' . str_replace('-', '_', $this->header);
            $token = $this->getHeader($header, $this->getServerHeaders());
        }

        return $token;
    }

    /**
     * Returns headers provided in the request as is.
     * @return array Associative array of request headers
     */
    protected function getRequestHeaders()
    {
        $headers = function_exists('apache_request_headers')
            ? apache_request_headers() : [];

        return is_array($headers) ? $headers : [];
    }

    /**
     * Returns the server data array with header information.
     * @return array Server data array
     */
    protected function getServerHeaders()
    {
        return isset($_SERVER) ? $_SERVER : [];
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

        return isset($headers[$name]) ? (string) $headers[$name] : false;
    }
}
