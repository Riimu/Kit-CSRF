<?php

namespace Riimu\Kit\CSRF;

/**
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2015, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class NonceValidatorTest extends \PHPUnit_Framework_TestCase
{
    public function tearDown()
    {
        if (isset($_SESSION['csrf_token'])) {
            unset($_SESSION['csrf_token']);
        }
        if (isset($_SESSION['nonces'])) {
            unset($_SESSION['nonces']);
        }
    }

    public function testDoubleFailureOnSecondValidation()
    {
        $nonce = new NonceValidator();
        $token = $nonce->getToken();

        $this->assertTrue($nonce->validateToken($token));
        $this->assertFalse($nonce->validateToken($token));
    }

    public function testClearedNoncesOnRegeneration()
    {
        $nonce = new NonceValidator();

        $token = $nonce->getToken();
        $this->assertNotEquals([], $_SESSION['nonces']);

        $nonce->regenerateToken();
        $this->assertSame([], $_SESSION['nonces']);

        $this->assertFalse($nonce->validateToken($token));
    }

    public function testClearingOldNonces()
    {
        $nonce = new NonceValidator();
        $tokens = [];
        $count = 8;

        for ($i = 0; $i < $count; $i++) {
            $tokens[] = $nonce->getToken();

        }

        shuffle($tokens);

        foreach ($tokens as $i => $token) {
            $_SESSION['nonces'][substr(base64_decode($token), 0, 32)] = $i;
        }

        $this->assertSame($count, count($_SESSION['nonces']));
        $nonce->pruneStorage(2);
        $this->assertSame(2, count($_SESSION['nonces']));

        $this->assertTrue($nonce->validateToken(array_pop($tokens)));
        $this->assertTrue($nonce->validateToken(array_pop($tokens)));

        $this->assertSame(0, count($_SESSION['nonces']));
    }
}
