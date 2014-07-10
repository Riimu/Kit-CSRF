<?php

namespace Riimu\Kit\CSRF\Storage;

/**
 * Stores the actual token in a session variable.
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2014, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class SessionStorage implements TokenStorage
{
    /**
     * Name of the session variables that stores the actual token.
     * @var string
     */
    private $name;

    /**
     * Creates a new instance of SessionStorage.
     * @param string $name Name of the session variable used to store the token
     */
    public function __construct($name = 'csrf_token')
    {
        $this->name = $name;
    }

    public function storeToken($token)
    {
        $_SESSION[$this->name] = base64_encode($token);
    }

    public function getStoredToken()
    {
        if (!isset($_SESSION[$this->name])) {
            return false;
        }

        return base64_decode($_SESSION[$this->name]);
    }
}
