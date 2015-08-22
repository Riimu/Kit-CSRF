<?php

namespace Riimu\Kit\CSRF\Storage;

/**
 * @author Riikka Kalliomäki <riikka.kalliomaki@gmail.com>
 * @copyright Copyright (c) 2015, Riikka Kalliomäki
 * @license http://opensource.org/licenses/mit-license.php MIT License
 */
class SessionStorageTest extends \PHPUnit_Framework_TestCase
{
    public function testNoActiveSession()
    {
        $storage = new SessionStorage();

        $this->setExpectedException('Riimu\Kit\CSRF\Storage\TokenStorageException');
        $storage->storeToken('foo');
    }
}
