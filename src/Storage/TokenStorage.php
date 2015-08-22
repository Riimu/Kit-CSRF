<?php

namespace Riimu\Kit\CSRF\Storage;

/**
 * Interface for a persistent token storage.
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2014, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
interface TokenStorage
{
    /**
     * Stores the CSRF token in the persistent storage.
     * @param string $token The CSRF token to store
     * @return void
     * @throws TokenStorageException If the token cannot be successfully stored
     */
    public function storeToken($token);

    /**
     * Loads the CSRF token from the persistent storage.
     * @return string|false The stored token or false if none is stored
     * @throws TokenStorageException If the token cannot be successfully loaded
     */
    public function getStoredToken();
}
