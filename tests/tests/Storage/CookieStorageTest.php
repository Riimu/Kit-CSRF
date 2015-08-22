<?php

namespace Riimu\Kit\CSRF\Storage;

/**
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2015, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class CookieStorageTest extends \PHPUnit_Framework_TestCase
{
    private static $defaults = [
        'name'     => 'csrf_token',
        'expire'   => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => false,
        'httpOnly' => true,
    ];

    public function testDefaultStorageParameters()
    {
        $storage = $this->getMock('Riimu\Kit\CSRF\Storage\CookieStorage', ['setCookie']);
        $storage->method('setCookie')->with(
            $this->identicalTo(base64_encode('foo')),
            $this->identicalTo(self::$defaults)
        )->will($this->returnValue(true));

        $storage->storeToken('foo');
    }

    public function testExpireTime()
    {
        $params = self::$defaults;
        $params['expire'] = time() + 1;

        $storage = $this->getMock('Riimu\Kit\CSRF\Storage\CookieStorage', ['setCookie'], ['csrf_token', 1]);
        $storage->method('setCookie')->with(
            $this->identicalTo(base64_encode('foo')),
            $this->identicalTo($params)
        )->will($this->returnValue(true));

        $storage->storeToken('foo');
    }

    public function testFailedCookie()
    {
        $storage = $this->getMock('Riimu\Kit\CSRF\Storage\CookieStorage', ['setCookie']);
        $storage->method('setCookie')->will($this->returnValue(false));

        $this->setExpectedException('Riimu\Kit\CSRF\Storage\TokenStorageException');
        $storage->storeToken('foo');
    }
}
