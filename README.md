# Secure CSRF Prevention #

This library provides a simple and secure way to prevent Cross-Site Request
Forgery. The CSRF token can be stored using cookies (i.e. double submit cookies)
or sessions. In order to provide a more secure way to handle CSRF tokens, the
library has been protected against timing attacks and the provided tokens are
always encrypted to avoid BREACH attacks.

API documentation for the classes can be generated using apigen.

[![Build Status](https://travis-ci.org/Riimu/Kit-CSRF.svg?branch=master)](https://travis-ci.org/Riimu/Kit-CSRF)
[![Coverage Status](https://coveralls.io/repos/Riimu/Kit-CSRF/badge.png?branch=master)](https://coveralls.io/r/Riimu/Kit-CSRF?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Riimu/Kit-CSRF/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Riimu/Kit-CSRF/?branch=master)

## Requirements ##

For generating secure random tokens and encryptions keys, the following PHP
extension is required.

  * [OpenSSL](http://www.php.net/manual/en/book.openssl.php)

## Usage ##

Implementation of this library is intended to be as easy as possible. At the
beginning of each page, you should call the `validateRequest()` method. If
the request has been done using POST, PUT or DELETE, the method will check for
valid CSRF token in the incoming request. By default, the `validateRequest()`
method will return a 400 Bad Request header and kill the script if no valid CSRF
token is included in the request.

The CSRF token should be included in all forms on the website using a hidden
field named 'csrf_token'. The token itself can be generated using the
`getToken()` method.

For example:

```php
<?php
$csrf = new \Riimu\Kit\CSRF\CSRFHandler();
$csrf->validateRequest();

$token = $csrf->getToken();

if (isset($_POST['myname'])) {
    echo "<p>Hello " . htmlspecialchars($_POST['myname']) . "!</p>";
}
?>
<form method="post" action="">
<input type="hidden" name="csrf_token" value="<?=$token?>" />
What is your name?
<input type="text" name="myname" value="" />
<input type="submit" value="Submit" />
</form>
```

## Additional usage notes ##

The `validateRequest($throw = false)` method will automatically validate any
POST, PUT and DELETE request made. If the request method is anything else, the
validation will be ignored. By default, the method will kill the script and
return a 400 Bad Request header to the browser, but this behavior can be changed
by setting the $throw parameter to true, in which case it will throw a
`InvalidCSRFTokenException` exception.

When using AJAX requests and especially in the case of using PUT and DELETE
request, the CSRF token can also provided using a `X-CSRF-Token` header.

In order to avoid session dependency by default, the CSRF token is stored in
cookie named 'csrf_token'. However, if you wish to store the token in sessions
instead, you can set the `setUseCookies($enabled)` to false.

If you want to implement custom triggers on when to validate the request or
provide the CSRF token using some other method, you may also call
`validateToken($token)` with the encrypted token to validate it. The method will
return True if the token is valid, false if not.

To prevent BREACH attacks, the tokens returned by `getToken()` are always
encrypted. Because of this, each call to that method will return a new string,
since a new encryption key is always generated. They are all valid CSRF tokens
until the token is regenerated, of course.

For regenerating the token (for example, when the user logs in), you can use the
`regenerateToken()` method.

## Anatomy of CSRF tokens ##

By default, the library uses 32 byte CSRF tokens. These are random byte strings
provided by the `openssl_random_pseudo_bytes()` function. However, as random
byte string may generate problems in different storage methods, the cookie or
session value is always stored as a base64 encoded string.

Similarly, the `getToken()` will return a base64 encoded string and the
`validateToken($token)` method expects a base64 encoded string. However, when
the token is generated using the `getToken()` method, the actual string is 64
bytes long. This is because it includes the encryption key used to encrypt the
actual token that follows using a simple XOR encryption. A new random
encryption key is generated using `openssl_random_pseudo_bytes()` each time the
method is called. This is used to prevent BREACH attacks taking advantage of
the CSRF token.

## Credits ##

This library is copyright 2014 to Riikka Kalliomäki

Implementation of this library is based on Go library
[nosurf](https://github.com/justinas/nosurf) by Justinas Stankevicius
