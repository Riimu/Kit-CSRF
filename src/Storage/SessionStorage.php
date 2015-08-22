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
    /** @var string Name of the session variable used to store the token */
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
        if (!$this->isSessionActive()) {
            throw new TokenStorageException('Error storing CSRF token, no session active');
        }

        $_SESSION[$this->name] = base64_encode($token);
    }

    /**
     * Tells if a session is currently active or not.
     * @return bool True if a session is active, false if not
     */
    protected function isSessionActive()
    {
        return session_status() === PHP_SESSION_ACTIVE;
    }

    public function getStoredToken()
    {
        if (!$this->isSessionActive()) {
            throw new TokenStorageException('Cannot load CSRF token, no session active');
        } elseif (isset($_SESSION[$this->name])) {
            return base64_decode($_SESSION[$this->name], true);
        }

        return false;
    }
}
