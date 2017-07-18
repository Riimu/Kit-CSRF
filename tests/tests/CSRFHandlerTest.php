<?php

namespace Riimu\Kit\CSRF;

use Riimu\Kit\CSRF\Storage\TokenStorageException;
use Riimu\Kit\SecureRandom\SecureRandom;

/**
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2014, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class CSRFHandlerTest extends HandlerTestCase
{
    public function testExpectedTokenLength()
    {
        $handler = $this->getSessionHandler();
        $this->assertSame(32, strlen($handler->getTrueToken()));
        $this->assertSame(64, strlen(base64_decode($handler->getToken(), true)));
    }

    public function testKillingScript()
    {
        $mock = $this->getMockBuilder(CSRFHandler::class)
            ->setMethods(['killScript', 'getTrueToken'])
            ->getMock();

        $mock->expects($this->once())->method('killScript');

        $_SERVER['REQUEST_METHOD'] = 'POST';
        $mock->validateRequest();
    }

    public function testTokenValidation()
    {
        $handler = $this->getSessionHandler();
        $token = $handler->getToken();

        // By default, token should not be invalid after first validation
        $this->assertTrue($handler->validateToken($token));
        $this->assertTrue($handler->validateToken($token));
    }

    public function testMultipleTokens()
    {
        $handler = $this->getSessionHandler();

        $tokenA = $handler->getToken();
        $tokenB = $handler->getToken();

        $this->assertInternalType('string', $tokenA);
        $this->assertInternalType('string', $tokenB);
        $this->assertNotSame($tokenA, $tokenB);

        $this->assertTrue($handler->validateToken($tokenA));
        $this->assertTrue($handler->validateToken($tokenB));
    }

    public function testTokenLoading()
    {
        $handler = $this->getSessionHandler();
        $token = $handler->getToken();

        $sessionHandler = $this->getSessionHandler();
        $this->assertTrue($sessionHandler->validateToken($token));

        $_COOKIE['csrf_token'] = $_SESSION['csrf_token'];

        $cookieHandler = $this->getCookieHandler();
        $this->assertTrue($cookieHandler->validateToken($token));
    }

    public function testNotValidatedMethod()
    {
        $handler = $this->getSessionHandler();
        $_SERVER['REQUEST_METHOD'] = 'GET';

        $this->assertTrue($handler->validateRequest());
    }

    /**
     * @param string $method The HTTP method test
     * @param bool $validated Whether the method should be validated or not
     * @dataProvider getMethods
     */
    public function testMethodValidation($method, $validated)
    {
        $handler = $this->getSessionHandler();
        $_SERVER['REQUEST_METHOD'] = $method;

        if ($validated) {
            $this->assertTrue($handler->isValidatedRequest());
        } else {
            $this->assertFalse($handler->isValidatedRequest());
        }
    }

    public function getMethods()
    {
        return [
            ['GET', false],
            ['HEAD', false],
            ['POST', true],
            ['PUT', true],
            ['DELETE', true],
        ];
    }

    public function testPostToken()
    {
        $handler = $this->getSessionHandler();

        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST['csrf_token'] = $handler->getToken();

        $this->assertTrue($handler->validateRequestToken());
    }

    public function testHeaderToken()
    {
        $handler = $this->getSessionHandler();

        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['HTTP_X_CSRF_TOKEN'] = $handler->getToken();

        $this->assertTrue($handler->validateRequestToken());
    }

    public function testInvalidPostToken()
    {
        $handler = $this->getSessionHandler();

        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST['csrf_token'] = $handler->getToken();
        $handler->regenerateToken();

        $this->expectException(InvalidCSRFTokenException::class);
        $handler->validateRequest(true);
    }

    public function testNoTokenAvailable()
    {
        $handler = $this->getSessionHandler();
        $_SERVER['REQUEST_METHOD'] = 'POST';

        $this->expectException(InvalidCSRFTokenException::class);
        $handler->validateRequest(true);
    }

    public function testTokenRegeneration()
    {
        $handler = $this->getSessionHandler();

        $token = $handler->getToken();
        $this->assertTrue($handler->validateToken($token));
        $handler->regenerateToken();
        $this->assertFalse($handler->validateToken($token));
    }

    public function testInvalidTokenLength()
    {
        $handler = $this->getSessionHandler();

        $invalid = substr(base64_decode($handler->getToken(), true), 0, -1);

        $this->assertFalse($handler->validateToken(base64_encode($invalid)));
    }

    public function testInvalidTokenKey()
    {
        $handler = $this->getSessionHandler();

        $invalid = base64_decode($handler->getToken(), true);
        $invalid[0] = $invalid[0] ^ "\xFF";

        $this->assertFalse($handler->validateToken(base64_encode($invalid)));
    }

    public function testInvalidTokenType()
    {
        $handler = $this->getSessionHandler();
        $this->assertFalse($handler->validateToken(0));
    }

    public function testMockedGenerator()
    {
        $handler = $this->getSessionHandler();

        $mock = $this->getMockBuilder(SecureRandom::class)
            ->setMethods(['getBytes'])
            ->getMock();

        $mock->expects($this->once())->method('getBytes')->with(32)->will($this->returnValue(str_repeat(chr(0), 32)));

        $handler->setGenerator($mock);
        $this->assertSame(str_repeat(chr(0), 32), $handler->getTrueToken());
    }

    public function testIncorrectTokenSource()
    {
        $handler = $this->getSessionHandler();
        $handler->setSources([new Source\HeaderSource()]);

        $_POST['csrf_token'] = $handler->getToken();
        $_SERVER['REQUEST_METHOD'] = 'POST';

        $this->expectException(InvalidCSRFTokenException::class);
        $handler->validateRequest(true);
    }

    public function testCookieStorageFailure()
    {
        $handler = new CSRFHandler(true);

        $this->expectException(TokenStorageException::class);
        $handler->getToken();
    }

    public function testSessionStorageFailure()
    {
        $handler = new CSRFHandler(false);

        $this->expectException(TokenStorageException::class);
        $handler->getToken();
    }

    public function testConstantTimeComparisonMethod()
    {
        $handler = $this->getSessionHandler();
        $token = $handler->getToken();

        $property = new \ReflectionProperty($handler, 'compare');
        $property->setAccessible(true);
        $property->setValue($handler, [$handler, 'compareStrings']);

        $this->assertTrue($handler->validateToken($token));
        $handler->regenerateToken();
        $this->assertFalse($handler->validateToken($token));
    }
}
