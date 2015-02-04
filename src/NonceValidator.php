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
    /** @var string Name of the session variable that stores the used nonces */
    private $name;

    /**
     * Creates a new instance of NonceValidator.
     * @param string $sessionVariable Name of the session variable used for storing nonces
     */
    public function __construct($sessionVariable = 'csrf_nonces')
    {
        parent::__construct(false);
        $this->name = $sessionVariable;
    }

    public function validateToken($token)
    {
        $key = $this->extractKey($token);

        if (isset($_SESSION[$this->name][$key])) {
            return false;
        }

        $_SESSION[$this->name][$key] = true;
        return parent::validateToken($token);
    }

    public function getToken()
    {
        $token = parent::getToken();

        // For usability's sake, allow the same token in the unlikely event that it gets recreated
        if (isset($_SESSION[$this->name][$this->extractKey($token)])) {
            unset($_SESSION[$this->name][$this->extractKey($token)]);
        }

        return $token;
    }

    public function regenerateToken()
    {
        $_SESSION[$this->name] = [];
        return parent::regenerateToken();
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
