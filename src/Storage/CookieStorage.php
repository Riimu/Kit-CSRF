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
    /** @var array List of cookie parameters */
    private $cookieParams;

    /**
     * Creates a new instance of CookieStorage.
     * @param string $name Name of the cookie used to store the token
     * @param integer $time Lifetime of the token cookie in seconds
     * @param string $path Path for the token cookie
     * @param string|null $domain Domain for the token cookie or null for none
     * @param boolean $secure Whether to pass cookie only via SSL connection
     * @param boolean $httpOnly Whether to pass to cookie only via HTTP requests
     */
    public function __construct(
        $name = 'csrf_token',
        $time = 0,
        $path = '/',
        $domain = '',
        $secure = false,
        $httpOnly = true
    ) {
        $this->cookieParams = [
            'name' => (string) $name,
            'value' => null,
            'time' => (int) $time,
            'path' => (string) $path,
            'domain' => (string) $domain,
            'secure' => (bool) $secure,
            'httpOnly' => (bool) $httpOnly,
        ];
    }

    /**
     * Stores the actual CSRF token in persistent storage.
     * @param string $token The actual CSRF token
     * @codeCoverageIgnore
     */
    public function storeToken($token)
    {
        $params = $this->cookieParams;
        $params['time'] = $params['time'] === 0 ? 0 : time() + $params['time'];
        $params['value'] = base64_encode($token);

        call_user_func_array('setcookie', array_values($params));
    }

    public function getStoredToken()
    {
        return isset($_COOKIE[$this->cookieParams['name']])
            ? base64_decode($_COOKIE[$this->cookieParams['name']]) : false;
    }
}
