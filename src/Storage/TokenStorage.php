<?php

namespace Riimu\Kit\CSRF\Storage;

/**
 * Interface for a persistent token storage, which is used to store the actual token.
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2014, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
interface TokenStorage
{
    /**
     * Stores the actual CSRF token in the persistent storage.
     * @param string $token The actual CSRF token
     * @return void
     */
    public function storeToken($token);

    /**
     * Loads the actual CSRF token from the persistent storage.
     * @return string|false The stored token or false if none is stored
     */
    public function getStoredToken();
}
