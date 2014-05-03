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
        $handler = new CSRFHandler();
        $handler->setUseCookies(false);
        $token = $handler->getToken();
        $this->assertNotEquals($token, $handler->getToken());

        $handlerB = new CSRFHandler();
        $handlerB->setUseCookies(false);
        $this->assertNotEquals($token, $handlerB->getToken());
    }

    public function testTokenValidation()
    {
        $handler = new CSRFHandler();
        $handler->setUseCookies(false);
        $token = $handler->getToken();
        $this->assertTrue($handler->validateToken($token));
    }

    public function testBadTokens()
    {
        $handler = new CSRFHandler();
        $handler->setUseCookies(false);
        $this->assertFalse($handler->validateToken('a'));

        $invalid = base64_decode($handler->getToken());
        $invalid[0] = $invalid[0] ^ "\xFF";
        $this->assertFalse($handler->validateToken(base64_encode($invalid)));
    }

    public function testTokenLoading()
    {
        $handler = new CSRFHandler();
        $handler->setUseCookies(false);
        $token = $handler->getToken();

        $handlerB = new CSRFHandler();
        $handlerB->setUseCookies(false);
        $this->assertTrue($handlerB->validateToken($token));

        $_COOKIE['csrf_token'] = $_SESSION['csrf_token'];
        $handlerC = new CSRFHandler();
        $this->assertTrue($handlerC->validateToken($token));
    }

    public function testSafeMethods()
    {
        $handler = new CSRFHandler();
        $handler->setUseCookies(false);

        $_SERVER['REQUEST_METHOD'] = 'GET';
        $this->assertTrue($handler->validateRequest());
        $_SERVER['REQUEST_METHOD'] = 'HEAD';
        $this->assertTrue($handler->validateRequest());
    }

    public function testSentPostToken()
    {
        $handler = new CSRFHandler();
        $handler->setUseCookies(false);
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
        $handler = new CSRFHandler();
        $handler->setUseCookies(false);
        $token = $handler->getToken();
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $handler->validateRequest(true);
    }

    public function testGetTokenFromHeaders()
    {
        $handler = new CSRFHandler();
        $handler->setUseCookies(false);
        $token = $handler->getToken();
        $_SERVER['REQUEST_METHOD'] = 'POST';

        $_SERVER['HTTP_X_CSRF_TOKEN'] = $token;
        $this->assertTrue($handler->validateRequest());

        \defineRequestHeadersFunction();

        $handlerB = new CSRFHandler();
        $handlerB->setUseCookies(false);
        $this->assertTrue($handlerB->validateRequest());
        unset($_SERVER['HTTP_X_CSRF_TOKEN']);

        try {
            $handlerB->validateRequest(true);
            $this->fail();
        } catch (\Exception $ex) { }
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testTooShortTokenGeneration()
    {
        $handler = new CSRFHandler();
        $ref = new \ReflectionClass($handler);
        $length = $ref->getProperty('tokenLength');
        $length->setAccessible(true);
        $length->setValue($handler, 0);
        $handler->getToken();
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testBadTokenLengthChange()
    {
        $handler = new CSRFHandler();
        $handler->setUseCookies(false);
        $handler->getToken();

        $ref = new \ReflectionClass($handler);
        $length = $ref->getProperty('tokenLength');
        $length->setAccessible(true);
        $length->setValue($handler, 31);
        $handler->getToken();
    }

    public function testComparisonLengthFailure()
    {
        $handler = new CSRFHandler();
        $handler->setUseCookies(false);
        $handler->getToken();

        $ref = new \ReflectionClass($handler);
        $length = $ref->getProperty('tokenLength');
        $length->setAccessible(true);
        $length->setValue($handler, 30);
        $this->assertFalse($handler->validateToken(base64_encode(str_repeat('0', 60))));
    }

    public function testTokenRegeneration()
    {
        $handler = new CSRFHandler();
        $handler->setUseCookies(false);

        $token = $handler->getToken();
        $this->assertTrue($handler->validateToken($token));
        $handler->regenerateToken();
        $this->assertFalse($handler->validateToken($token));
    }
}
