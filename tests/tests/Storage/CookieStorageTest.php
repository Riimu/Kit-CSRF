<?php

namespace Riimu\Kit\CSRF\Storage;

use PHPUnit\Framework\TestCase;

/**
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2015, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class CookieStorageTest extends TestCase
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
        $storage = $this->getMockBuilder(CookieStorage::class)
            ->setMethods(['setCookie'])
            ->getMock();

        $storage->expects($this->once())->method('setCookie')->with(
            $this->identicalTo(base64_encode('foo')),
            $this->identicalTo(self::$defaults)
        )->willReturn(true);

        $storage->storeToken('foo');
    }

    public function testExpireTime()
    {
        $params = self::$defaults;
        $params['expire'] = time() + 1;

        $storage = $this->getMockBuilder(CookieStorage::class)
            ->setMethods(['setCookie'])
            ->setConstructorArgs(['csrf_token', 1])
            ->getMock();

        $storage->expects($this->once())->method('setCookie')->with(
            $this->identicalTo(base64_encode('foo')),
            $this->identicalTo($params)
        )->willReturn(true);

        $storage->storeToken('foo');
    }

    public function testFailedCookie()
    {
        $storage = $this->getMockBuilder(CookieStorage::class)
            ->setMethods(['setCookie'])
            ->getMock();

        $storage->method('setCookie')->will($this->returnValue(false));

        $this->expectException(TokenStorageException::class);
        $storage->storeToken('foo');
    }
}
