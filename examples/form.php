<?php

require __DIR__ . '/../vendor/autoload.php';

$csrf = new \Riimu\Kit\CSRF\CSRFHandler();
$csrf->validateRequest();

$token = $csrf->getToken();

if (isset($_POST['myname'])) {
    echo "<p>Hello " . htmlspecialchars($_POST['myname']) . "!</p>";
}
?>

<h1>Form with CSRF token</h1>
<form method="post" action="form.php">
<input type="hidden" name="csrf_token" value="<?=$token?>" />
What is your name?
<input type="text" name="myname" value="" />
<input type="submit" value="Submit" />
</form>

<h1>Form without CSRF token</h1>
<form method="post" action="form.php">
What is your name?
<input type="text" name="myname" value="" />
<input type="submit" value="Submit" />
</form>