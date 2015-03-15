# Changelog #

## v2.3.0 (2015-03-15) ##

  * Added `SingleToken` class, which allows lazy loading the token and
    generating only one token per request.

## v2.2.1 (2015-02-06) ##

  * Implement the missing NonceValidator::getNonceCount() method.

## v2.2.0 (2015-02-04) ##

  * Token length is now stored in a constant CSRFHandler::TOKEN_LENGTH instead
    of a protected member, as it should have been from the start.
  * Use HMAC-SHA256 for generating the encrypted token instead of XOR cipher.
  * CookieStorage now allows secure and httpOnly parameters in the constructor,
    which default to false and true.
  * Added NonceValidator class for using nonce tokens.

## v2.1.0 (2015-02-01) ##

  * Improvements in code quality and documentation
  * The library now prefers hash_equals for constant time string comparison on
    PHP version 5.6 and later.
  * Added CSRFHandler::isValidatedRequest() to tell if the CSRF token should
    be validated according to current request method.
  * Added CSRFHandler::validateRequestToken() to validate the token sent in the
    request.
  * Changed CSRFHandler::getRequestToken() to public from protected
  * CSRFHandler now calls protected method killScript() internally when killing
    the script via validateRequest().
  * The SecureRandom library is now only loaded when needed
  * InvalidCSRFTokenException now extends UnexpectedValueException
  * CSRFHandler::regenerateToken() now prevents the token from being the same
    one as previously (should the astronomically unlikely event occur).

## v2.0.0 (2014-07-10) ##

  * The library now depends on riimu/kit-securerandom for random bytes instead
    of just using openssl_random_pseudo_bytes.
  * Token storage and source methods are now much more modular and separated
    into different interfaces/classes
  * CSRFHandler::setUseCookies() no longer exists. Use the argument in the
    constructor instead.

## v1.0.1 (2014-05-28) ##

  * Token header name is now handled in case insensitive manner
  * Token storage and retrieving methods are now protected to simplify extending
  * Code cleanup and documentation fixes
