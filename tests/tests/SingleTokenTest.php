<?php

namespace Riimu\Kit\CSRF;

/**
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2015, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class SingleTokenTest extends \PHPUnit_Framework_TestCase
{
    public function tearDown()
    {
        if (isset($_SESSION['csrf_token'])) {
            unset($_SESSION['csrf_token']);
        }
    }

    public function testLazyLoading()
    {
        $token = $this->getToken();

        $property = new \ReflectionProperty($token, 'token');
        $property->setAccessible(true);

        $this->assertNull($property->getValue($token));
        $token->getToken();
        $this->assertNotNull($property->getValue($token));
    }

    public function testSameToken()
    {
        $token = $this->getToken();
        $this->assertSame($token->getToken(), $token->getToken());
    }

    public function testStringConversion()
    {
        $token = $this->getToken();
        $this->assertSame($token->getToken(), (string) $token);
    }

    private function getToken()
    {
        $csrf = new CSRFHandler(false);
        return new SingleToken($csrf);
    }
}
