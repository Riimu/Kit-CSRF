<?php

namespace Riimu\Kit\CSRF;

use PHPUnit\Framework\TestCase;
use Riimu\Kit\CSRF\Storage\CookieStorage;
use Riimu\Kit\CSRF\Storage\SessionStorage;

/**
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2015, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class HandlerTestCase extends TestCase
{
    private static $state = ['_SERVER', '_SESSION', '_COOKIE', '_POST'];

    private $storedState;

    public static function setUpBeforeClass()
    {
        if (!isset($_SESSION)) {
            $_SESSION = [];
        }
    }

    public function setUp()
    {
        foreach (self::$state as $name) {
            $this->storedState[$name] = $GLOBALS[$name];
        }
    }

    public function tearDown()
    {
        foreach (self::$state as $name) {
            $GLOBALS[$name] = $this->storedState[$name];
        }
    }

    /**
     * Returns a CSRFHandler that uses session storage.
     * @return CSRFHandler Session storage based CSRFHandler
     */
    protected function getSessionHandler()
    {
        $handler = new CSRFHandler(false);

        $storage = $this->getMockBuilder(SessionStorage::class)
            ->setMethods(['isSessionActive'])
            ->getMock();

        $storage->method('isSessionActive')->willReturn(true);
        $handler->setStorage($storage);

        return $handler;
    }

    /**
     * Returns a CSRFHandler that uses cookie storage.
     * @return CSRFHandler Cookie storage based CSRFHandler
     */
    protected function getCookieHandler()
    {
        $handler = new CSRFHandler(true);

        $storage = $this->getMockBuilder(CookieStorage::class)
            ->setMethods(['setCookie'])
            ->getMock();

        $storage->method('setCookie')->will($this->returnCallback(function ($value, $params) {
            $_COOKIE[$params['name']] = $value;

            return true;
        }));

        $handler->setStorage($storage);

        return $handler;
    }
}
