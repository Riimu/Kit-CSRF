<?php

namespace Riimu\Kit\CSRF\Storage;

use PHPUnit\Framework\TestCase;

/**
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2015, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class SessionStorageTest extends TestCase
{
    public function testNoActiveSession()
    {
        $storage = new SessionStorage();

        $this->expectException(TokenStorageException::class);
        $storage->storeToken('foo');
    }
}
