<?php

require_once '../src/CSRFHandler.php';

function defineRequestHeadersFunction()
{
    function apache_request_headers () {
        return isset($_SERVER['HTTP_X_CSRF_TOKEN']) ? [
            'X-CSRF-Token' => $_SERVER['HTTP_X_CSRF_TOKEN']
        ] : [];
    }
}

?>
