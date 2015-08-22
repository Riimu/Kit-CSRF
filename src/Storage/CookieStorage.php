<?php

namespace Riimu\Kit\CSRF\Storage;

/**
 * Token storage that uses browser cookies to store the CSRF token.
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
     * @param int $expire Lifetime of the token cookie in seconds
     * @param string $path Path for the token cookie
     * @param string $domain Domain for the token cookie or empty string for none
     * @param bool $secure Whether to pass cookie only via SSL connection
     * @param bool $httpOnly Whether to make the cookie available only to requests
     */
    public function __construct(
        $name = 'csrf_token',
        $expire = 0,
        $path = '/',
        $domain = '',
        $secure = false,
        $httpOnly = true
    ) {
        $this->cookieParams = [
            'name'      => (string) $name,
            'expire'    => (int) $expire,
            'path'      => (string) $path,
            'domain'    => (string) $domain,
            'secure'    => (bool) $secure,
            'httpOnly'  => (bool) $httpOnly,
        ];
    }

    public function storeToken($token)
    {
        $params = $this->cookieParams;

        if ($params['expire'] !== 0) {
            $params['expire'] = time() + $params['expire'];
        }

        if (!$this->setCookie(base64_encode($token), $params)) {
            throw new TokenStorageException('Error setting CSRF token cookie');
        }
    }

    /**
     * Sets the cookie that stores the secret CSRF token.
     * @param string $value The value for the cookie
     * @param array $params Parameters for the cookie
     * @return bool True if the cookie was set successfully, false if not
     * @throws TokenStorageException If the headers have already been sent
     * @codeCoverageIgnore
     */
    protected function setCookie($value, array $params)
    {
        if (headers_sent()) {
            throw new TokenStorageException('Cannot store CSRF token, headers already sent');
        }

        return setcookie(
            $params['name'],
            $value,
            $params['expire'],
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httpOnly']
        );
    }

    public function getStoredToken()
    {
        if (isset($_COOKIE[$this->cookieParams['name']])) {
            return base64_decode($_COOKIE[$this->cookieParams['name']], true);
        }

        return false;
    }
}
