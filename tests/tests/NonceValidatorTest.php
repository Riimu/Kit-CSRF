<?php

namespace Riimu\Kit\CSRF;

/**
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2015, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class NonceValidatorTest extends HandlerTestCase
{
    protected static $name = 'csrf_nonces';

    public function testFailureOnSecondValidation()
    {
        $nonce = $this->getNonceValidator();
        $token = $nonce->getToken();

        $this->assertTrue($nonce->validateToken($token));
        $this->assertFalse($nonce->validateToken($token));
    }

    public function testAllowSameTokenIfReturnedAgain()
    {
        $nonce = $this->getNonceValidator();
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
        $nonce = $this->getNonceValidator();
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

    public function testNonceCount()
    {
        $nonce = $this->getNonceValidator();

        $this->assertSame(0, $nonce->getNonceCount());
        $nonce->validateToken($nonce->getToken());
        $this->assertSame(1, $nonce->getNonceCount());
    }

    private function getNonceValidator()
    {
        $storage = $this->getMock('Riimu\Kit\CSRF\Storage\SessionStorage', ['isSessionActive']);
        $storage->method('isSessionActive')->will($this->returnValue(true));

        $validator = new NonceValidator();
        $validator->setStorage($storage);

        return $validator;
    }
}
