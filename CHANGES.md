# Changelog #

## v2.0.0 (2014-07-10) ##

  * The library now depends on Kit\SecureRandom for random bytes, instead of
    just using openssl_random_pseudo_bytes.
  * Token storage and source methods are now much more modular and separated
    into different interfaces/classes
  * CSRFHandler::setUseCookies() no longer exists. Use the argument in the
    constructor instead.

## v1.0.1 (2014-05-28) ##

  * Token header name is now handled in case insensitive manner
  * Token storage and retrieving methods are now protected to simplify extending
  * Code cleanup and documentation fixes
