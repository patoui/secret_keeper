<?php

declare(strict_types=1);

mb_internal_encoding('UTF-8');
mb_http_output('UTF-8');

$is_dev = ($_SERVER['HTTP_HOST'] ?? '') === 'localhost';

if ($is_dev) {
    ini_set('display_errors', 'On');
    ini_set('display_startup_errors', 'On');
    error_reporting(-1);
    ini_set('log_errors', 'On');
} else {
    ini_set('display_errors', 'Off');
    ini_set('display_startup_errors', 'Off');
    error_reporting(E_ALL);
    ini_set('log_errors', 'On');
}

/**
 * Tested with PHP 8.1
 * Required extensions: redis, uuid, openssl
 */

const CIPHER = 'aes-256-cbc';

/**
 * Get the Redis instance (connection)
 * @return Redis
 */
function redis(): Redis
{
    static $redis;

    if ($redis) {
        return $redis;
    }

    $redis = new Redis();
    global $is_dev;
    if ($is_dev) {
        $redis->connect('redis');
    } else {
        $redis->connect('127.0.0.1', 6379);
    }

    return $redis;
}

/**
 * Attempt to retrieve the secret message
 * @param string $id id to reference the message by
 * @param string $password password to gain access to the secret message
 * @return string the secret message or empty string if the password is invalid
 * @throws RuntimeException
 */
function retrieve(string $id, string $password): string {
    $data = redis()->get("sk:$id");

    if (!$data || !($data = json_decode($data, true))) {
        // no results returned
        return '';
    }

    return decrypt($password, $data['content']);
}

/**
 * Encrypt the message
 * @param string $key the key of which to encrypt with
 * @param string $content the content to encrypt
 * @return string the encrypted content
 */
function encrypt(string $key, string $content): string
{
	$ivlen = openssl_cipher_iv_length(CIPHER);
	$iv = openssl_random_pseudo_bytes($ivlen);
	$ciphertext = openssl_encrypt($content, CIPHER, $key, 0, $iv);
	return base64_encode($iv.$ciphertext);
}

/**
 * Attempt to decrypt the message
 * @param string $key the key of which to encrypt with
 * @param string $encrypted_message the encrypted message
 * @return string the decrypted message
 */
function decrypt(string $key, string $encrypted_message): string
{
    $encrypted_message = base64_decode($encrypted_message);

    if (!$encrypted_message) {
        return '';
    }

	// get the length of the initialization vector
	$ivlen = openssl_cipher_iv_length(CIPHER);

	// extract initialization vector from encrypted message
	$iv = substr($encrypted_message, 0, $ivlen);

	// remove initialization vector from encrypted message
	$encrypted_message = substr($encrypted_message, $ivlen);

    if ($decrypted_message = openssl_decrypt($encrypted_message, CIPHER, $key, 0, $iv)) {
        return $decrypted_message;
    }

	return '';
}

/**
 * Persist the secret message
 * @param string $content the secret message content
 * @param string $password the password for which to gain access to the message
 * @param int|null $expiry optional expiry, defaults to 30 seconds
 * @return string the ID of the stored secret message to share with others
 * @throws RuntimeException
 */
function persist(
    string $content,
    string $password,
    int $expiry
): string {
    $id = uuid_create();

    $was_successful = redis()->setex("sk:$id", $expiry, json_encode([
        'content' => encrypt($password, $content),
    ]));

    if (!$was_successful) {
        return '';
    }

    return $id;
}

/**
 * Helper function for the base layout of the application
 * @param string $content
 * @return string
 */
function layout(string $content): string
{
    return <<<HTML
    <!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">

    <title>Secret Keeper</title>
  </head>
  <body>
    <div class="container mt-5">
        <div class="row">
            <div class="col">
                <h1 class="d-inline">Secret Keeper</h1>
                <a href="/c" class="btn btn-primary align-bottom ms-3">Create a Secret</a>
            </div>
        </div>
        <div class="row">
            <div class="col">
                $content
            </div>
        </div>
    </div>
  </body>
</html>
HTML;
}

/**
 * Show the home page
 * @return never
 */
function home(): never
{
    echo layout(<<<HOME
<h2 class="mt-5">Welcome!</h2>
<p>Secret Keeper is a simple service to create shareable links that have a secret message that only those who know the password can reveal it's contents!</p>
HOME);
    die;
}

/**
 * Show the form to unlock a secret
 * @return never
 */
function form(): never
{
    $id = getUriSegments()[1] ?? null;

    if (!$id) {
        notFound();
    }

    $token = csrfToken();
    echo layout(<<<FORM
<form method="POST" action="/u/$id" class="mt-3">
    <input type="hidden" name="token" value="$token" />
    <div class="mb-3">
        <label for="password" class="form-label">Password</label>
        <input type="text" class="form-control" id="password" name="password" aria-describedby="passwordHelp" minlength="8" maxlength="100" required>
        <div id="passwordHelp" class="form-text">The password should have been shared with the link.</div>
    </div>
    <button type="submit" class="btn btn-primary">Unlock!</button>
</form>
FORM);
    die;
}

/**
 * Process the request to unlock the secret
 * @return never
 * @throws RuntimeException
 */
function unlock(): never
{
    checkThrottle();
    checkCsrf();

    $password = filter_input(INPUT_POST, 'password');
    $id = getUriSegments()[1] ?? null;

    if (
        !$id
        || !$password
        || strlen($id) !== 36
        || strlen($password) < 8
        || strlen($password) > 100
        || !uuid_is_valid($id)
        || !($secret = retrieve($id, $password))) {
        notFound();
    }

    echo layout(sprintf('<p class="mt-5">%s</p>', $secret));
    die;
}

/**
 * Show the form to create a secret
 * @return never
 */
function create(): never
{
    $token = csrfToken();
    echo layout(<<<FORM
<form method="POST" action="/c" class="mt-3">
    <input type="hidden" name="token" value="$token" />
    <div class="mb-3">
        <label for="content" class="form-label">The Secret Content!</label>
        <textarea class="form-control" id="content" name="content" rows="3" minlength="3" maxlength="1000" required></textarea>
        <div id="contentHelp" class="form-text">Minimum 3 and maximum of 1000 characters.</div>
    </div>
    <div class="mb-3">
        <label for="password" class="form-label">Password</label>
        <input type="text" class="form-control" id="password" name="password" minlength="8" maxlength="100" required>
        <div id="passwordHelp" class="form-text">Minimum 8 and maximum of 100 characters.</div>
    </div>
    <div class="mb-3">
        <label for="expiry" class="form-label">Expires In (seconds)</label>
        <input type="number" class="form-control" id="expiry" name="expiry" value="86400" min="10" max="604800" required>
        <div id="expiryHelp" class="form-text">Number of seconds which the secret will expire. Minimum 10 seconds and maximum of 604800 seconds (7 days).</div>
        <button type="button" data-expiry="3600" class="expiry-helpers btn btn-secondary btn-sm">1 hour</button>
        <button type="button" data-expiry="86400" class="expiry-helpers btn btn-secondary btn-sm">1 day</button>
        <button type="button" data-expiry="604800" class="expiry-helpers btn btn-secondary btn-sm">7 days</button>
    </div>
    <button type="submit" class="btn btn-primary">Create!</button>
</form>
<script>
document.querySelectorAll('.expiry-helpers').forEach(el => {
    el.addEventListener('click', ev => {
        document.querySelector('#expiry').value = ev.target.dataset.expiry;
    });
});
</script>
FORM);
    die;
}

/**
 * Store the secret
 * @return never
 * @throws RuntimeException
 */
function store(): never
{
    checkThrottle();
    checkCsrf();

    $content  = htmlspecialchars(filter_input(INPUT_POST, 'content'));
    $password = filter_input(INPUT_POST, 'password');
    $expiry   = (int) filter_input(INPUT_POST, 'expiry', FILTER_SANITIZE_NUMBER_INT, FILTER_VALIDATE_INT);

    if (
        !$content
        || !$password
        || !$expiry
        || $expiry < 10
        || $expiry > 604800
        || !($id = persist($content, $password, $expiry))) {
        redirect('/c');
    }

    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '';
    echo layout(<<<SECRET
<p class="mt-5">Your secret link is:</p>
<a href="//$host/u/$id">$host/u/$id</a>
<p class="mt-3">$host/u/$id</p>
SECRET);
    die;
}

/**
 * Get/generate the CSRF token
 * @return string
 * @throws Exception
 */
function csrfToken(): string
{
    if (empty($_SESSION['token'])) {
        $_SESSION['token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['token'];
}

/**
 * Check CSRF token validity
 * @return void
 */
function checkCsrf(): void
{
    $token = filter_input(INPUT_POST, 'token');

    // CSRF token check
    if (!hash_equals($_SESSION['token'], $token)) {
        redirect('/c');
    }
}

/**
 * Check throttle limit, if exceed redirect to the home page
 * @return void
 */
function checkThrottle(): void
{
    $ip = getIp();

    if (!$ip) {
        redirect('/');
    }

    $key = "throttle:$ip";

    $attempts = redis()->get($key);
    if (!$attempts) {
        redis()->incr($key);
        redis()->expire($key, 30);
        return;
    } elseif ($attempts >= 5) {
        redirect('/');
    }

    redis()->incr($key);
}

/**
 * Get the client IP address
 * @return string
 */
function getIp(): string
{
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    }
    return $ip ?? $_SERVER['REMOTE_ADDR'] ?? '';
}

/**
 * Trigger a redirect response
 * @param string $path
 * @return never
 */
function redirect(string $path): never
{
    header("Location: $path");
    die;
}

/**
 * Return a 404 response
 * @return never
 */
function notFound(): never
{
    http_response_code(404);
    echo layout('<h2 class="mt-5">Uh oh, you must be lost!</h2>');
    die;
}

/**
 * Retrieve all the URI segments
 * @return array
 */
function getUriSegments(): array
{
    return explode(
        '/',
        ltrim(strtok($_SERVER['REQUEST_URI'] ?? '/', '?'), '/')
    );
}

session_start();
$path = getUriSegments()[0] ?: '/';

switch($_SERVER['REQUEST_METHOD'] ?? null) {
    case 'GET':
        match ($path) {
            '/'     => home(),
            'c'     => create(),
            'u'     => form(),
            default => notFound(),
        };
    case 'POST':
        match ($path) {
            'c'     => store(),
            'u'     => unlock(),
            default => notFound(),
        };
}

notFound();
