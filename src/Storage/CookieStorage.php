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
    /**
     * Name of the cookie used to store the actual token.
     * @var string
     */
    private $name;

    /**
     * Lifetime for token cookie in seconds.
     * @var integer
     */
    private $time;

    /**
     * Path for the token cookie.
     * @var string
     */
    private $path;

    /**
     * Domain for the token cookie or null for none.
     * @var null|string
     */
    private $domain;

    /**
     * Creates a new instance of CookieStorage.
     * @param string $name Name of the cookie used to store the token
     * @param integer $time Lifetime of the token cookie seconds
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
     * Stores the actual csrf token in persistent storage.
     * @param string $token The actual csrf token
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
