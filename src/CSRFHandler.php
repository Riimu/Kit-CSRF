<?php

namespace Riimu\Kit\CSRF;

/**
 * CSRF token validator and generator.
 *
 * CSRFHandler provides a simple way to generate and validate CSRF tokens in
 * a secure manner accounting for timing and BREACH attacks. The class also uses
 * openssl_random_pseudo_bytes to securely generate the random tokens and
 * unique encryption tokens for each request.
 *
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2014, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class CSRFHandler
{
    /**
     * List of request methods to validate automatically.
     * @var array
     */
    private $validatedMethods = ['POST', 'PUT', 'DELETE'];

    /**
     * Name of the cookie or session variable used to store the csrf token.
     * @var string
     */
    private $storageName = 'csrf_token';

    /**
     * Name of the input used to send the csrf token in forms.
     * @var string
     */
    private $formFieldName = 'csrf_token';

    /**
     * Name of the custom header used to send the csrf token.
     * @var string
     */
    private $headerName = 'X-CSRF-Token';

    /**
     * Length of the csrf token in bytes.
     * @var int
     */
    private $tokenLength = 32;

    /**
     * Whether to use cookies or session to store the actual csrf token.
     * @var boolean
     */
    private $useCookies;

    /**
     * Current actual csrf token.
     * @var string
     */
    private $token;

    /**
     * Creates a new instance of CSRFHandler.
     */
    public function __construct()
    {
        $this->useCookies = true;
        $this->token = null;
    }

    /**
     * Sets whether to use cookies or sessions to store the csrf token.
     * @param boolean $enabled True to use cookies, false to use sessions
     * @return CSRFHandler Returns self for call chaining
     */
    public function setUseCookies($enabled)
    {
        $this->useCookies = (bool) $enabled;
        return $this;
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
     * @return boolean Always returns true
     * @throws InvalidCSRFTokenException If throwing is enabled and csrf token is invalid
     */
    public function validateRequest($throw = false)
    {
        if (!isset($this->token)) {
            $this->loadToken();
        }

        if (!in_array($_SERVER['REQUEST_METHOD'], $this->validatedMethods)) {
            return true;
        }

        if (!$this->validateToken($this->getSentToken())) {
            if ($throw) {
                throw new InvalidCSRFTokenException("Request token was invalid");
            } else { // @codeCoverageIgnoreStart
                header('HTTP/1.0 400 Bad Request');
                die;
            } // @codeCoverageIgnoreEnd
        }

        return true;
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

        if (strlen($token) != $this->tokenLength * 2) {
            return false;
        }

        if (!$this->timedEquals($this->cryptToken($token), $this->getTrueToken())) {
            return false;
        }

        return true;
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
        $key = $this->getRandomBytes($this->tokenLength);
        return base64_encode($key . $this->cryptToken($key . $this->getTrueToken()));
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
        $this->token = $this->generateToken();
        return $this;
    }

    /**
     * Returns the current actual csrf token string.
     * @return string The current actual token
     */
    private function getTrueToken()
    {
        if (!isset($this->token)) {
            $this->loadToken();
        }

        return $this->token;
    }

    /**
     * Loads the token from storage or generates a new on if doesn't yet exist.
     */
    private function loadToken()
    {
        $token = $this->getStoredToken();

        if ($token === false || strlen($token) !== $this->tokenLength) {
            $token = $this->generateToken();
        }

        $this->token = $token;
    }

    /**
     * Loads the token from cookie or session storage.
     * @return string|boolean The stored token or false if none exists
     */
    private function getStoredToken()
    {
        $token = false;

        if ($this->useCookies) {
            if (!empty($_COOKIE[$this->storageName])) {
                $token = $_COOKIE[$this->storageName];
            }
        } else {
            if (!empty($_SESSION[$this->storageName])) {
                $token = $_SESSION[$this->storageName];
            }
        }

        return is_string($token) ? base64_decode($token) : false;
    }

    /**
     * Generates a new token and stores it in the cookie ro session.
     * @return string The new generated token
     */
    private function generateToken()
    {
        $token = $this->getRandomBytes($this->tokenLength);
        $encoded = base64_encode($token);

        if ($this->useCookies) { // @codeCoverageIgnoreStart
            setcookie($this->storageName, $encoded, 0, '/');
        } else { // @codeCoverageIgnoreEnd
            $_SESSION[$this->storageName] = $encoded;
        }

        return $token;
    }

    /**
     * Gets the token sent in the request.
     * @return string|boolean the token sent in the request or false if none
     */
    private function getSentToken()
    {
        if (!empty($_POST[$this->formFieldName])) {
            $token = $_POST[$this->formFieldName];
        } else {
            $token = $this->getHeaderToken();
        }

        return $token;
    }

    /**
     * Gets the token sent in a header field.
     * @return string|boolean The token sent in a header or false if none exists
     */
    private function getHeaderToken()
    {
        if (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();

            if (isset($headers[$this->headerName])) {
                return $headers[$this->headerName];
            }
        }

        $key = 'HTTP_' . str_replace('-', '_', strtoupper($this->headerName));

        if (isset($_SERVER[$key])) {
            return $_SERVER[$key];
        }

        return false;
    }

    /**
     * Encrypts or decrypts half of the string using xor encryption.
     * @param string $token Key for encryption and string to encrypt
     * @return string The encrypted or decrypted string
     * @throws \RuntimeException If the token has an invalid length
     */
    private function cryptToken($token)
    {
        if (strlen($token) % 2 != 0 || strlen($token) < 2) {
            throw new \RuntimeException("Invalid token length");
        }

        list($key, $value) = str_split($token, strlen($token) / 2);

        return $value ^ $key;
    }

    /**
     * Compares two string in constant time.
     * @param string $a First string to compare
     * @param string $b Second string to compare
     * @return boolean True if the strings are equal, false if not
     */
    private function timedEquals($a, $b) {
        if (strlen($a) !== strlen($b)) {
            return false;
        }

        $result = "\x00";

        for ($i = 0; $i < strlen($a); $i++) {
            $result |= $a[$i] ^ $b[$i];
        }

        return $result === "\x00";
    }

    /**
     * Returns securely generated random bytes.
     * @param integer $count The number of bytes to return
     * @return string Generated random bytes as a string
     * @throws \RuntimeException If the bytes could not be generated securely
     */
    private function getRandomBytes($count)
    {
        $bytes = \openssl_random_pseudo_bytes($count, $strong);

        if (!$strong) {
            throw new \RuntimeException("Byte generation was not strong");
        }

        return $bytes;
    }
}

/**
 * Thrown when the CSRF token is missing or is invalid.
 */
class InvalidCSRFTokenException extends \Exception { }