<?php

namespace Riimu\Kit\CSRF;

/**
 * Provides validation for tokens that are only accepted once.
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2015, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class NonceValidator extends CSRFHandler
{
    /** @var string Name of the session variable that stores the nonces */
    private $name;

    /**
     * Creates a new instance of NonceValidator.
     * @param string $sessionVariable Name of the session variable used to store the nonces
     */
    public function __construct($sessionVariable = 'nonces')
    {
        parent::__construct(false);
        $this->name = $sessionVariable;
    }

    public function validateToken($token)
    {
        $key = $this->extractKey($token);

        if (!isset($_SESSION[$this->name][$key])) {
            return false;
        }

        unset($_SESSION[$this->name][$key]);
        return parent::validateToken($token);
    }

    public function getToken()
    {
        $token = parent::getToken();
        $_SESSION[$this->name][$this->extractKey($token)] = time();
        return $token;
    }

    public function regenerateToken()
    {
        $_SESSION[$this->name] = [];
        return parent::regenerateToken();
    }

    /**
     * Removes old nonces from the storage until limit is reached.
     * @param integer $limit Maximum number of nonces to store
     */
    public function pruneStorage($limit)
    {
        if (count($_SESSION[$this->name]) > $limit) {
            arsort($_SESSION[$this->name], SORT_NUMERIC);
            $_SESSION[$this->name] = array_slice($_SESSION[$this->name], 0, $limit, true);
        }
    }

    /**
     * Extracts the key from the combined token string.
     * @param string $token The combined token string
     * @return string The key extracted from the combined token string
     */
    private function extractKey($token)
    {
        return substr(base64_decode($token), 0, CSRFHandler::TOKEN_LENGTH);
    }
}
