<?php

namespace Riimu\Kit\CSRF;

/**
 * Thrown when the CSRF token is missing or is invalid.
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2014, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class InvalidCSRFTokenException extends \UnexpectedValueException
{

}
