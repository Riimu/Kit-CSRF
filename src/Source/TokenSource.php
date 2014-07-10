<?php

namespace Riimu\Kit\CSRF\Source;

/**
 * Interface for token sources.
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2014, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
interface TokenSource
{
    /**
     * Returns the token sent in the request or false if none was found.
     * @return string|false The sent token or false for none
     */
    public function getRequestToken();
}
