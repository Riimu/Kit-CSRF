# Secure CSRF Prevention #

This library provides a simple and secure way to provide CSRF prevention with
use of sessions or cookies (using double posting). In order to provide more
secure environment, the library is protected against timing attacks for the
CSRF tokens and uses a simple XOR encyption on the tokens to avoid HTTPS BREACH
attacks.

API documentation for the classes can be generated using apigen.

## Requirements ##

In order to provide secure random tokens, the library requires the following PHP
extensions to provide secure random bytes:

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

By default, the library will use double posting, which means the actual CSRF
token is stored in a cookie in the browser in order to avoid session dependency.
However, if you wish to use sessions, simply set `setUseCookies($enabled)` to
false, in which case the CSRF token is stored to session variable named
'csrf_token'.

If you want to implement custom triggers on when to validate the request or
provide the CSRF token using some other method, you may also call
`validateToken($token)` with the encrypted token to validate it. The method will
return True if the token is valid, false if not.

Note that each call to `getToken()` will return a different string, because they
are always encrypted using new random string. For performance purposes, it's
recommended to store the returned value if you need to output it into multiple
forms.

For regenerating the token (such as when the user logs in), you can use the
`regenerateToken()` method.

## Anatomy of CSRF tokens ##

By default, the library uses 32 byte CSRF tokens. These are random byte strings
provided by the `openssl_random_pseudo_bytes()` function. However, as random
byte string may generate problems in different storage methods, the cookie or
session value is always stored as a byte64 encoded string.

Similarly, the `getToken()` will return a byte64 encoded string and the
`validateToken($token)` method expects a byte64 encoded string. However, when
the token is generated using the `getToken()` method, the actual string is 64
bytes long. This is because it includes the encryption key used to encrypt the
actual token that follows using a simple XOR encryption. A new random
encryption key is generated using `openssl_random_pseudo_bytes()` each time the
method is called. This is used to avoid possible HTTPS BREACH attacks taking
advantage of the CSRF token.

## Credits ##

This library is copyright 2014 to Riikka Kalliomäki

Implementation of this library is based on Go library
[nosurf](https://github.com/justinas/nosurf) by Justinas Stankevicius
