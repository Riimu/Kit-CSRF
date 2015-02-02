<?php

require __DIR__ . '/../vendor/autoload.php';
$csrf = new \Riimu\Kit\CSRF\CSRFHandler();

try {
    $csrf->validateRequest(true);
} catch (\Riimu\Kit\CSRF\InvalidCSRFTokenException $ex) {
    header('HTTP/1.0 400 Bad Request');
    exit('Bad CSRF Token!');
}

$token = $csrf->getToken();

?>
<!DOCTYPE html>
<html>
 <head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <title>Simple Form</title>
 </head>
 <body>
<?php

if (!empty($_POST['my_name'])) {
    printf("  <p>Hello <strong>%s</strong>!</p>" . PHP_EOL, htmlspecialchars($_POST['my_name'], ENT_QUOTES | ENT_HTML5, 'UTF-8'));
}

?>
  <h3>Form with a CSRF token:</h3>
  <form method="post"><div>
    <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($token, ENT_QUOTES | ENT_HTML5, 'UTF-8')?>" />
   What is your name?
   <input type="text" name="my_name" />
   <input type="submit" />
  </div></form>

  <h3>Form without a CSRF token:</h3>
  <form method="post"><div>
   What is your name?
   <input type="text" name="my_name" />
   <input type="submit" />
  </div></form>
 </body>
</html>
