<?php

namespace Riimu\Kit\CSRF\Storage;

/**
 * Stores the actual token in a browser cookie.
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2014, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class CookieStorage implements TokenStorage
{
    /** @var string Name of the cookie used to store the actual token */
    private $name;

    /** @var integer Lifetime for token cookie in seconds */
    private $time;

    /** @var string Path for the token cookie */
    private $path;

    /** @var null|string Domain for the token cookie or null for none */
    private $domain;

    /**
     * Creates a new instance of CookieStorage.
     * @param string $name Name of the cookie used to store the token
     * @param integer $time Lifetime of the token cookie in seconds
     * @param string $path Path for the token cookie
     * @param string|null $domain Domain for the token cookie or null for none
     */
    public function __construct($name = 'csrf_token', $time = 0, $path = '/', $domain = null)
    {
        $this->name = $name;
        $this->time = (int) $time;
        $this->path = $path;
        $this->domain = $domain;
    }

    /**
     * Stores the actual CSRF token in persistent storage.
     * @param string $token The actual CSRF token
     * @codeCoverageIgnore
     */
    public function storeToken($token)
    {
        $time = $this->time == 0 ? 0 : time() + $this->time;

        if ($this->domain === null) {
            setcookie($this->name, base64_encode($token), $time, $this->path);
        } else {
            setcookie($this->name, base64_encode($token), $time, $this->path, $this->domain);
        }
    }

    public function getStoredToken()
    {
        return isset($_COOKIE[$this->name]) ? base64_decode($_COOKIE[$this->name]) : false;
    }
}
