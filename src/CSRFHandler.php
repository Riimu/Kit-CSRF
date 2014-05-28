<?php

namespace Riimu\Kit\CSRF;

/**
 * CSRF token validator and generator.
 *
 * CSRFHandler provides a simple way to generate and validate CSRF tokens.
 * Precautions have been taken to avoid timing and BREACH attacks. For secure
 * random tokens, the library uses openssl_random_pseudo_bytes to generate
 * tokens and random encryption keys for each request.
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
     * Name of the cookie or session variable used to store the csrf token.
     * @var string
     */
    protected $storageName = 'csrf_token';

    /**
     * Name of the input used to send the csrf token in forms.
     * @var string
     */
    protected $formFieldName = 'csrf_token';

    /**
     * Name of the custom header used to send the csrf token.
     * @var string
     */
    protected $headerName = 'X-CSRF-Token';

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
     * @return true Always returns true
     * @throws InvalidCSRFTokenException If throwing is enabled and csrf token is invalid
     */
    public function validateRequest($throw = false)
    {
        $this->loadToken();

        if (!in_array($_SERVER['REQUEST_METHOD'], $this->validatedMethods)) {
            return true;
        }

        $token = $this->getSentToken();

        if ($token === false || !$this->validateToken($token)) {
            if ($throw) {
                throw new InvalidCSRFTokenException('Request token was invalid');
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

        return $this->timedEquals($this->cryptToken($token), $this->getTrueToken());
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
        $this->loadToken();
        return $this->token;
    }

    /**
     * Loads the token from storage or generates a new one.
     */
    private function loadToken()
    {
        if (!isset($this->token)) {
            $token = $this->getStoredToken();

            if ($token === false || strlen($token) !== $this->tokenLength) {
                $token = $this->generateToken();
            }

            $this->token = $token;
        }
    }

    /**
     * Loads the actual csrf token from persistent storage.
     * @return string|false The stored token or false if none exists
     */
    protected function getStoredToken()
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
     * Generates a new token and stores it in the cookie or session.
     * @return string The new generated token
     */
    private function generateToken()
    {
        $token = $this->getRandomBytes($this->tokenLength);
        $this->storeToken($token);
        return $token;
    }

    /**
     * Stores the actual csrf token in persistent storage.
     * @param string $token The actual csrf token
     */
    protected function storeToken($token)
    {
        if ($this->useCookies) { // @codeCoverageIgnoreStart
            setcookie($this->storageName, base64_encode($token), 0, '/');
        } else { // @codeCoverageIgnoreEnd
            $_SESSION[$this->storageName] = base64_encode($token);
        }
    }

    /**
     * Returns the token sent in the request.
     * @return string|false The token sent in the request or false if none
     */
    protected function getSentToken()
    {
        if (!empty($_POST[$this->formFieldName])) {
            $token = $_POST[$this->formFieldName];
        } else {
            $token = $this->getHeaderToken();
        }

        return $token;
    }

    /**
     * Returns the token sent in a header field.
     * @return string|false The token sent in a header or false if none exists
     */
    private function getHeaderToken()
    {
        if (function_exists('apache_request_headers')) {
            $token = $this->getHeader($this->headerName, apache_request_headers());
            if ($token !== false) {
                return $token;
            }
        }

        return $this->getHeader('HTTP_' . str_replace('-', '_', $this->headerName), $_SERVER);
    }

    /**
     * Returns the case insensitive header from the list of headers.
     * @param string $name name of the header
     * @param array $headers List of headers
     * @return string|false Contents of the header or false if it does not exist
     */
    private function getHeader($name, $headers)
    {
        $headers = array_change_key_case($headers);
        $name = strtolower($name);
        return isset($headers[$name]) ? $headers[$name] : false;
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
            throw new \RuntimeException('Invalid token length');
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
    private function timedEquals($a, $b)
    {
        if (strlen($a) !== strlen($b)) {
            return false;
        }

        $result = "\x00";

        for ($i = 0, $length = strlen($a); $i < $length; $i++) {
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
    protected function getRandomBytes($count)
    {
        $bytes = \openssl_random_pseudo_bytes($count, $strong);

        if (!$strong) {
            throw new \RuntimeException('Byte generation was not strong');
        }

        return $bytes;
    }
}
