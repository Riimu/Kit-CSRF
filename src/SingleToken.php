<?php

namespace Riimu\Kit\CSRF;

/**
 * Provides convenience and efficiency by lazy loading only one token.
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2015, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class SingleToken
{
    /** @var CSRFHandler The handler used to generate the token */
    private $csrf;

    /** @var string The generated token */
    private $token;

    /**
     * Creates a new instance of SingleToken.
     * @param CSRFHandler $csrf The handler used to generate the token
     */
    public function __construct(CSRFHandler $csrf)
    {
        $this->csrf = $csrf;
    }

    /**
     * Returns the generated token.
     *
     * The token is generated the first time this method is called. Further
     * calls to this method will always return the same token.
     *
     * @return string The generated token
     */
    public function getToken()
    {
        if (!isset($this->token)) {
            $this->token = $this->csrf->getToken();
        }

        return $this->token;
    }

    /**
     * Returns the generated token.
     * @return string The generated token
     */
    public function __toString()
    {
        return $this->getToken();
    }
}
