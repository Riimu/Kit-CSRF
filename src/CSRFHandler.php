<?php

namespace Riimu\Kit\CSRF;

use Riimu\Kit\SecureRandom\SecureRandom;

/**
 * CSRF token validator and generator.
 *
 * CSRFHandler provides a simple way to generate and validate CSRF tokens.
 * Precautions have been taken to avoid timing and BREACH attacks. For secure
 * random bytes, the library uses Kit\SecureRandom library to handle
 * generating tokens and random encryption keys for each request.
 *
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2014, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class CSRFHandler
{
    /**
     * List of request methods validated by validateRequest() method.
     * @var string[]
     */
    protected $validatedMethods = ['POST', 'PUT', 'DELETE'];

    /**
     * Number of bytes used in CSRF tokens.
     * @var integer
     */
    protected $tokenLength = 32;

    /**
     * Secure random generator for generating bytes.
     * @var \Riimu\Kit\SecureRandom\SecureRandom
     */
    private $generator;

    /**
     * Persistent storage where to store the actual token.
     * @var Storage\TokenStorage
     */
    private $storage;

    /** @var Source\TokenSource[] Possible sources for submitted tokens */
    private $sources;

    /**
     * Current actual csrf token.
     * @var string
     */
    private $token;

    /** @var callable Callback used to compare strings in constant time */
    private $compare;

    /**
     * Creates a new instance of CSRFHandler.
     * @param boolean $useCookies True to store the token in cookies, false for session
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
     * Returns the current secure random generator
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
     * Sets the persistent storage for tokens.
     * @param Storage\TokenStorage $storage Persistent storage handler for tokens
     */
    public function setStorage(Storage\TokenStorage $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Sets the possible the token sources.
     *
     * Multiple sources can be added using an array. The handler will look for
     * the token from the sources in the order they appear in the array.
     *
     * @param Source\TokenSource[] $sources List of token sources.
     */
    public function setSources(array $sources)
    {
        $this->sources = [];

        foreach ($sources as $source) {
            $this->addSource($source);
        }
    }

    /**
     * Adds additional token source.
     * @param Source\TokenSource $source Token source to use.
     */
    private function addSource(Source\TokenSource $source)
    {
        $this->sources[] = $source;
    }

    /**
     * Tells if CSRF token should be validated for the current request method.
     * @return boolean True if the token should be validated, false if not
     */
    public function isValidatedMethod()
    {
        return in_array($_SERVER['REQUEST_METHOD'], $this->validatedMethods);
    }

    /**
     * Validates the csrf token in the http request.
     *
     * The intention of this method is to be called at the beginning of each
     * request. There is no need to check for the request type, since the
     * token validation will be skipped for all but POST, PUT and DELETE
     * requests.
     *
     * If the token validation fails, the method will send a HTTP 400 response
     * and kill the script. You can alternatively set the throw argument to
     * true, which will cause the method to send an exception instead.
     *
     * For loading and storing the csrf token, this method should be called
     * after the session has been started but before headers have been sent.
     *
     * @param boolean $throw True to throw exception on error instead of dying
     * @return true Always returns true
     * @throws InvalidCSRFTokenException If throwing is enabled and csrf token is invalid
     */
    public function validateRequest($throw = false)
    {
        // Ensure that the actual token is generated and stored
        $this->getTrueToken();

        if (!$this->isValidatedMethod()) {
             return true;
        }

        if (!$this->validateRequestToken()) {
            if ($throw) {
                throw new InvalidCSRFTokenException('Invalid CSRF token');
            } else {
                $this->killScript();
            }
        }

        return true;
    }

    /**
     * Validates the token sent in the request.
     * @return boolean True if the token sent in the request if valid, false if not
     */
    public function validateRequestToken()
    {
        $token = $this->getRequestToken();
        return $token !== false && $this->validateToken($token);
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
     * Validates the csrf token.
     *
     * The token must be provided as a base64 encoded string, which is provided
     * by the getToken() method.
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

        if (strlen($token) !== $this->tokenLength * 2) {
            return false;
        }

        list($key, $encrypted) = str_split($token, $this->tokenLength);
        return call_user_func($this->compare, $this->getTrueToken(), $key ^ $encrypted);
    }

    /**
     * Generates a new secure base64 encoded csrf token for forms.
     *
     * Every time this method called, a new string is returned. The actual token
     * does not change, but a new encryption key for the token is generated on
     * each call.
     *
     * @return string Base64 encoded and encrypted csrf token
     */
    public function getToken()
    {
        $key = $this->getGenerator()->getBytes($this->tokenLength);
        return base64_encode($key . ($key ^ $this->getTrueToken()));
    }

    /**
     * Regenerates the actual csrf token.
     *
     * After this method is called, any token generated previously by getToken()
     * will no longer validate. It is highly recommended to regenerate the
     * csrf token after user authentication.
     *
     * @return CSRFHandler Returns self for call chaining
     */
    public function regenerateToken()
    {
        $this->token = $this->getGenerator()->getBytes($this->tokenLength);
        $this->storage->storeToken($this->token);

        return $this;
    }

    /**
     * Returns the current actual csrf token.
     *
     * This returns the actual 32 byte string that sent tokens are validated
     * against. Note that the bytes are random and should not be used without
     * proper escaping.
     *
     * @return string The current actual token
     */
    public function getTrueToken()
    {
        $token = isset($this->token) ? $this->token : $this->storage->getStoredtoken();

        if ($token === false || strlen($token) !== $this->tokenLength) {
            $this->regenerateToken();
            return $this->token;
        }

        return $this->token = $token;
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
