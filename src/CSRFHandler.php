<?php

namespace Riimu\Kit\CSRF;

use Riimu\Kit\SecureRandom\SecureRandom;

/**
 * Secure CSRF token validator and generator.
 *
 * CSRFHandler provides a simple way to generate and validate CSRF tokens.
 * Precautions have been taken to avoid timing and BREACH attacks. The tokens
 * are generated using the SecureRandom library in order to generate secure
 * random byte sequences.
 *
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2014, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class CSRFHandler
{
    /** @var integer Number of bytes used in the CSRF token */
    const TOKEN_LENGTH = 32;

    /** @var string[] List of request methods that need to be validated for the CSRF token */
    protected $validatedMethods = ['POST', 'PUT', 'DELETE'];

    /** @var SecureRandom Secure random generator for generating secure random bytes */
    private $generator;

    /** @var Storage\TokenStorage Persistent storage used to store the actual token */
    private $storage;

    /** @var Source\TokenSource[] Possible sources for submitted tokens */
    private $sources;

    /** @var string The current actual CSRF token */
    private $token;

    /** @var callable Callback used to compare strings in constant time */
    private $compare;

    /**
     * Creates a new instance of CSRFHandler.
     *
     * When creating a new instance, it will be initialized with either cookie
     * storage or session storage depending on whether you pass true or false
     * as the constructor parameter (defaults to cookie). The actual token won't
     * be loaded until the token is validated, though. By default, the handler
     * will also use post and header data to look for submitted tokens.
     *
     * @param boolean $useCookies True for cookie storage, false for session storage
     */
    public function __construct($useCookies = true)
    {
        $this->storage = $useCookies ? new Storage\CookieStorage() : new Storage\SessionStorage();
        $this->sources = [
            new Source\PostSource(),
            new Source\HeaderSource(),
        ];

        $this->compare = version_compare(PHP_VERSION, '5.6', '>=')
            ? 'hash_equals' : [$this, 'compareStrings'];
    }

    /**
     * Sets the random generator for generating secure random bytes.
     * @param SecureRandom $generator Secure random generator
     */
    public function setGenerator(SecureRandom $generator)
    {
        $this->generator = $generator;
    }

    /**
     * Returns the current secure random generator.
     * @return SecureRandom Current secure random generator
     */
    public function getGenerator()
    {
        if (!isset($this->generator)) {
            $this->generator = new SecureRandom();
        }

        return $this->generator;
    }

    /**
     * Sets the persistent storage for the CSRF token.
     *
     * The token storage should be set before you create new tokens or attempt
     * to validate tokens, because the storage is only used the first time the
     * token is needed.
     *
     * @param Storage\TokenStorage $storage Persistent storage handler
     */
    public function setStorage(Storage\TokenStorage $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Sets the possible sources for submitted token.
     *
     * Multiple sources can be added using an array. The handler will look for
     * the token from the sources in the order they appear in the array.
     *
     * @param Source\TokenSource[] $sources List of token sources.
     */
    public function setSources(array $sources)
    {
        $this->sources = array_map(function (Source\TokenSource $source) {
            return $source;
        }, $sources);
    }

    /**
     * Tells if the request method indicates that the CSRF token should be validated.
     * @return boolean True if the token should be validated, false if not
     */
    public function isValidatedRequest()
    {
        return in_array($_SERVER['REQUEST_METHOD'], $this->validatedMethods);
    }

    /**
     * Validates the csrf token in the HTTP request.
     *
     * This method should be called in the beginning of the request. By default,
     * POST, PUT and DELETE requests will be validated for a valid CSRF token.
     * If the request does not provide a valid CSRF token, this method will
     * kill the script and send a HTTP 400 (bad request) response to the
     * browser.
     *
     * This method also accepts a single parameter than can be either true or
     * false. If the parameter is set to true, this method will throw an
     * InvalidCSRFTokenException instead of killing the script if no valid CSRF
     * token was provided in the request.
     *
     * This method will always trigger the token storage. If you are using the
     * cookie storage, this method must be called before the headers have been
     * sent. If you are using the session storage instead, you must start the
     * session before calling this method.
     *
     * @param boolean $throw True to throw an exception on invalid token, false to kill the script
     * @return boolean This method always returns true
     * @throws InvalidCSRFTokenException If throwing is enabled and the csrf token is invalid
     */
    public function validateRequest($throw = false)
    {
        // Ensure that the actual token is generated and stored
        $this->getTrueToken();

        if (!$this->isValidatedRequest()) {
             return true;
        }

        if (!$this->validateRequestToken()) {
            if ($throw) {
                throw new InvalidCSRFTokenException('Invalid CSRF token');
            }

            $this->killScript();
        }

        return true;
    }

    /**
     * Kills the script execution and sends the appropriate header.
     * @codeCoverageIgnore
     */
    protected function killScript()
    {
        header('HTTP/1.0 400 Bad Request');
        exit();
    }

    /**
     * Validates the token sent in the request.
     * @return boolean True if the token sent in the request is valid, false if not
     */
    public function validateRequestToken()
    {
        $token = $this->getRequestToken();
        return is_string($token) && $this->validateToken($token);
    }

    /**
     * Validates the csrf token.
     *
     * The token must be provided as a base64 encoded string which also includes
     * the token encryption key. In other words, you should pass this method the
     * exact same string that has been returned by the `getToken()` method.
     *
     * @param string $token The base64 encoded token provided by getToken()
     * @return boolean True if the token is valid, false if it is not
     */
    public function validateToken($token)
    {
        if (!is_string($token)) {
            return false;
        }

        $token = base64_decode($token);

        if (strlen($token) !== self::TOKEN_LENGTH * 2) {
            return false;
        }

        list($key, $encrypted) = str_split($token, self::TOKEN_LENGTH);

        return call_user_func(
            $this->compare,
            $this->encryptToken($this->getTrueToken(), $key),
            $encrypted
        );
    }

    /**
     * Generates an encrypted token using a one way hashing algorithm.
     * @param string $token The actual token
     * @param string $key The randomly generated key
     * @return string An encrypted token
     */
    private function encryptToken($token, $key)
    {
        return hash_hmac('sha256', $key, $token, true);
    }

    /**
     * Generates a new secure base64 encoded csrf token.
     *
     * This method returns a new string every time it is called, because it
     * always generates a new encryption key for the token. Of course, each of
     * these tokens is a valid CSRF token, unless the `regenerateToken()` method
     * is called.
     *
     * @return string Base64 encoded CSRF token
     */
    public function getToken()
    {
        $key = $this->getGenerator()->getBytes(self::TOKEN_LENGTH);
        return base64_encode($key . $this->encryptToken($this->getTrueToken(), $key));
    }

    /**
     * Regenerates the actual CSRF token.
     *
     * After this method has been called, any token that has been previously
     * generated by `getToken()` is no longer considered valid. It is highly
     * recommended to regenerate the CSRF token after any user authentication.
     *
     * @return CSRFHandler Returns self for call chaining
     */
    public function regenerateToken()
    {
        do {
            $token = $this->getGenerator()->getBytes(self::TOKEN_LENGTH);
        } while ($token === $this->token);

        $this->token = $token;
        $this->storage->storeToken($this->token);

        return $this;
    }

    /**
     * Returns the current actual CSRF token.
     *
     * This returns the current actual 32 byte random string that is used to
     * validate the CSRF tokens submitted in requests.
     *
     * @return string The current actual CSRF token
     */
    public function getTrueToken()
    {
        if (!isset($this->token)) {
            $token = $this->storage->getStoredToken();
            $this->token = is_string($token) ? $token : '';
        }

        if (strlen($this->token) !== self::TOKEN_LENGTH) {
            $this->regenerateToken();
        }

        return $this->token;
    }

    /**
     * Returns the token sent in the request.
     * @return string|false The token sent in the request or false if there is none
     */
    public function getRequestToken()
    {
        $token = false;

        foreach ($this->sources as $source) {
            if (($token = $source->getRequestToken()) !== false) {
                break;
            }
        }

        return $token;
    }

    /**
     * Compares two string in constant time.
     * @param string $knownString String known to be correct by the system
     * @param string $userString String submitted by the user for comparison
     * @return boolean True if the strings are equal, false if not
     */
    private function compareStrings($knownString, $userString)
    {
        $result = "\x00";

        for ($i = 0, $length = strlen($knownString); $i < $length; $i++) {
            $result |= $knownString[$i] ^ $userString[$i];
        }

        return $result === "\x00";
    }
}
