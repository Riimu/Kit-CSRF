<?php

namespace Riimu\Kit\CSRF\Storage;

/**
 * Interface for persistent token storages, which store the actual token.
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2014, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
interface TokenStorage
{
    /**
     * Stores the actual csrf token in persistent storage.
     * @param string $token The actual csrf token
     * @return void
     */
    public function storeToken($token);

    /**
     * Loads the actual csrf token from persistent storage.
     * @return string|false The stored token or false if none is stored
     */
    public function getStoredToken();
}
