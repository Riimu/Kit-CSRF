<?php

namespace Riimu\Kit\CSRF;

/**
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2014, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class CSRFHandlerTest extends \PHPUnit_Framework_TestCase
{
    public function tearDown()
    {
        if (isset($_SESSION['csrf_token'])) {
            unset($_SESSION['csrf_token']);
        }
        if (isset($_COOKIE['csrf_token'])) {
            unset($_COOKIE['csrf_token']);
        }
        if (isset($_SERVER['REQUEST_METHOD'])) {
            unset($_SERVER['REQUEST_METHOD']);
        }
        if (isset($_POST['csrf_token'])) {
            unset($_POST['csrf_token']);
        }
    }

    public function testTokenRandomness()
    {
        $handler = $this->getHandler();
        $token = $handler->getToken();
        $this->assertNotEquals($token, $handler->getToken());

        $handlerB = $this->getHandler();
        $this->assertNotEquals($token, $handlerB->getToken());
    }

    public function testTokenValidation()
    {
        $handler = $this->getHandler();
        $token = $handler->getToken();
        $this->assertTrue($handler->validateToken($token));
    }

    public function testBadTokens()
    {
        $handler = $this->getHandler();
        $this->assertFalse($handler->validateToken('a'));

        $invalid = base64_decode($handler->getToken());
        $invalid[0] = $invalid[0] ^ "\xFF";
        $this->assertFalse($handler->validateToken(base64_encode($invalid)));
    }

    public function testTokenLoading()
    {
        $handler = $this->getHandler();
        $token = $handler->getToken();

        $handlerB = $this->getHandler();
        $this->assertTrue($handlerB->validateToken($token));

        $_COOKIE['csrf_token'] = $_SESSION['csrf_token'];
        $handlerC = $this->getHandler(true);
        $this->assertTrue($handlerC->validateToken($token));
    }

    public function testSafeMethods()
    {
        $handler = $this->getHandler();

        $_SERVER['REQUEST_METHOD'] = 'GET';
        $this->assertTrue($handler->validateRequest());
        $_SERVER['REQUEST_METHOD'] = 'HEAD';
        $this->assertTrue($handler->validateRequest());
    }

    public function testSentPostToken()
    {
        $handler = $this->getHandler();
        $token = $handler->getToken();
        $_POST['csrf_token'] = $token;
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $this->assertTrue($handler->validateRequest());
    }

    /**
     * @expectedException \Riimu\Kit\CSRF\InvalidCSRFTokenException
     */
    public function testInvalidPostToken()
    {
        $handler = $this->getHandler();
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $handler->validateRequest(true);
    }

    public function testGetTokenFromHeaders()
    {
        $handler = $this->getHandler();
        $token = $handler->getToken();
        $_SERVER['REQUEST_METHOD'] = 'POST';

        $_SERVER['HTTP_X_CSRF_TOKEN'] = $token;
        $this->assertTrue($handler->validateRequest());

        \defineRequestHeadersFunction();

        $handlerB = $this->getHandler();
        $this->assertTrue($handlerB->validateRequest());
        unset($_SERVER['HTTP_X_CSRF_TOKEN']);

        $this->setExpectedException('Riimu\Kit\CSRF\InvalidCSRFTokenException');
        $handlerB->validateRequest(true);
    }

    public function testBadTokenLengthChange()
    {
        $handler = $this->getHandler();
        $original = $handler->getToken();

        $ref = new \ReflectionClass($handler);
        $length = $ref->getProperty('tokenLength');
        $length->setAccessible(true);
        $length->setValue($handler, 31);
        $this->assertNotEquals($original, $handler->getToken());
    }

    public function testComparisonLengthFailure()
    {
        $handler = $this->getHandler();
        $handler->getToken();

        $ref = new \ReflectionClass($handler);
        $length = $ref->getProperty('tokenLength');
        $length->setAccessible(true);
        $length->setValue($handler, 30);
        $this->assertFalse($handler->validateToken(base64_encode(str_repeat('0', 60))));
    }

    public function testTokenRegeneration()
    {
        $handler = $this->getHandler();

        $token = $handler->getToken();
        $this->assertTrue($handler->validateToken($token));
        $handler->regenerateToken();
        $this->assertFalse($handler->validateToken($token));
    }

    public function testInvalidTokenType()
    {
        $handler = $this->getHandler();
        $this->assertFalse($handler->validateToken(0));
    }

    public function testMockedGenerator()
    {
        $handler = $this->getHandler();

        $mock = $this->getMock('Riimu\Kit\SecureRandom\SecureRandom', ['getBytes']);
        $mock->expects($this->once())->method('getBytes')->with(32)->will($this->returnValue(str_repeat(chr(0), 32)));

        $handler->setGenerator($mock);
        $this->assertSame(str_repeat(chr(0), 32), $handler->getTrueToken());
    }

    public function testSetSource()
    {
        $handler = $this->getHandler();
        $_POST['csrf_token'] = $handler->getToken();
        $handler->setSources([new Source\HeaderSource()]);
        $_SERVER['REQUEST_METHOD'] = 'POST';

        $this->setExpectedException('Riimu\Kit\CSRF\InvalidCSRFTokenException');
        $handler->validateRequest(true);
    }

    public function testMissingCookieStorage()
    {
        $handler = new CSRFHandler();

        $mock = $this->getMock('Riimu\Kit\CSRF\Storage\CookieStorage', ['storeToken']);
        $mock->expects($this->once())->method('storeToken');

        $handler->setStorage($mock);
        $handler->getToken();
    }

    public function testConstantTimeComparisonMethod()
    {
        $handler = $this->getHandler();
        $token = $handler->getToken();

        $property = new \ReflectionProperty($handler, 'compare');
        $property->setAccessible(true);
        $property->setValue($handler, [$handler, 'compareStrings']);

        $this->assertTrue($handler->validateToken($token));
    }

    private function getHandler($useCookies = false)
    {
        $handler = new CSRFHandler();

        if (!$useCookies) {
            $handler->setStorage(new Storage\SessionStorage());
        }

        return $handler;
    }
}
