<?php

namespace Riimu\Kit\CSRF;

/**
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2015, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class NonceValidatorTest extends \PHPUnit_Framework_TestCase
{
    protected static $name = 'csrf_nonces';

    public function tearDown()
    {
        if (isset($_SESSION['csrf_token'])) {
            unset($_SESSION['csrf_token']);
        }
        if (isset($_SESSION[self::$name])) {
            unset($_SESSION[self::$name]);
        }
    }

    public function testFailureOnSecondValidation()
    {
        $nonce = new NonceValidator();
        $token = $nonce->getToken();

        $this->assertTrue($nonce->validateToken($token));
        $this->assertFalse($nonce->validateToken($token));
    }

    public function testAllowSameTokenIfReturnedAgain()
    {
        $nonce = new NonceValidator();
        $random = $this->getMock('Riimu\Kit\SecureRandom\SecureRandom', ['getBytes']);

        $random->expects($this->exactly(3))->method('getBytes')->will(
            $this->returnValue(str_repeat('A', CSRFHandler::TOKEN_LENGTH))
        );
        $nonce->setGenerator($random);

        $tokenA = $nonce->getToken();
        $this->assertTrue($nonce->validateToken($tokenA));

        $tokenB = $nonce->getToken();
        $this->assertSame($tokenA, $tokenB);
        $this->assertTrue($nonce->validateToken($tokenB));
    }

    public function testAllowSameTokenAfterRegeneration()
    {
        $nonce = new NonceValidator();
        $random = $this->getMock('Riimu\Kit\SecureRandom\SecureRandom', ['getBytes']);

        $random->expects($this->exactly(5))->method('getBytes')->will($this->onConsecutiveCalls(
            str_repeat('A', CSRFHandler::TOKEN_LENGTH),
            str_repeat('A', CSRFHandler::TOKEN_LENGTH),
            str_repeat('B', CSRFHandler::TOKEN_LENGTH),
            str_repeat('A', CSRFHandler::TOKEN_LENGTH),
            str_repeat('A', CSRFHandler::TOKEN_LENGTH)
        ));

        $nonce->setGenerator($random);

        $tokenA = $nonce->getToken();
        $this->assertTrue($nonce->validateToken($tokenA));
        $nonce->regenerateToken();
        $nonce->regenerateToken();
        $tokenB = $nonce->getToken();

        $this->assertSame($tokenA, $tokenB);
        $this->assertTrue($nonce->validateToken($tokenB));
    }
}
