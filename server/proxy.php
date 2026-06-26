<?php

$proxy_ttl = 365 * 24 * 3600;
$proxy_target_proto = "http"; // Hard-coded, we will NOT be dealing with SSL.
$proxy_target_host = @$_SERVER['HTTP_X_FORWARDED_TO'];
$proxy_target_path = @$_SERVER['HTTP_X_FORWARDED_PATH'];

$proxy_public_proto = @$_SERVER['HTTP_X_FORWARDED_PROTO'] ?? 'https';
$proxy_public_host = @$_SERVER['HTTP_X_FORWARDED_HOST'] ?? @$_SERVER['HTTP_HOST'];
$proxy_public_path = @$_SERVER['HTTP_X_FORWARDED_PATH'];

$client_id = "$proxy_public_proto://$proxy_public_host";
$redirect_uri = "$proxy_public_proto://$proxy_public_host/auth";

if(!$proxy_public_host) {
  http_response_code(400);
  echo "Missing X-Forwarded-Host header.";
  exit;
}

if(!$proxy_target_host) {
  http_response_code(400);
  echo "Missing X-Forwarded-To header.";
  exit;
}

if(!$proxy_target_path) {
  http_response_code(400);
  echo "Missing X-Forwarded-Path header.";
  exit;
}

// Optional allow-list: when PROXY_ALLOWED_HOSTS is set (comma-separated
// host:port entries), refuse to proxy to anything not listed.
$proxy_allowed = getenv('PROXY_ALLOWED_HOSTS');

if($proxy_allowed) {
  $allowed = array_map('trim', explode(',', $proxy_allowed));
  if(!in_array($proxy_target_host, $allowed, true)) {
    http_response_code(403);
    echo "Proxy target not allowed.";
    exit;
  }
}

if(!$proxy_public_host) {
  http_response_code(500);
  echo "Missing X-Forwarded-Host header.";
  exit;
}

function fetch_user_from_session() {
  global $signing_key;

  $cookie = @$_COOKIE['nym_session'];
  if(!$cookie || !verify_signed_code($signing_key, 'nym_session', $cookie)) return null;

  $parts = explode(":", $cookie, 3);
  $data = json_decode(base64_url_decode($parts[2]), true);

  if(!$data || !isset($data['me'])) return null;

  return $data;
}

function log_in_via_session($user) {
  global $proxy_ttl, $signing_key, $proxy_public_proto;

  $cookie = create_signed_code($signing_key, 'nym_session', $proxy_ttl, json_encode($user));

  setcookie('nym_session', $cookie, [
    'expires' => time() + $proxy_ttl,
    'path' => '/',
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => $proxy_public_proto == 'https',
  ]);
}

// Bind the in-flight login to the browser that started it: the PKCE verifier
// lives in an httponly cookie, never in the callback URL, so a captured
// callback can't be replayed elsewhere.
function store_verifier($verifier) {
  global $signing_key, $proxy_public_proto;

  $cookie = create_signed_code($signing_key, 'nym_verifier', 5 * 60, $verifier);

  setcookie('nym_verifier', $cookie, [
    'expires' => time() + 5 * 60,
    'path' => '/',
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => $proxy_public_proto == 'https',
  ]);
}

function fetch_verifier() {
  global $signing_key;

  $cookie = @$_COOKIE['nym_verifier'];
  if(!$cookie || !verify_signed_code($signing_key, 'nym_verifier', $cookie)) return null;

  $parts = explode(":", $cookie, 3);
  return base64_url_decode($parts[2]);
}

function clear_verifier() {
  setcookie('nym_verifier', '', ['expires' => time() - 3600, 'path' => '/']);
}

function verify_proxy_code($code, $redirect_uri, $client_id, $verifier) {
  // Inline code verification, avoids an HTTP round-trip to ourselves.
  global $signing_key;

  $parts = explode(":", $code, 3);
  if(count($parts) != 3) return null;

  $payload = json_decode(base64_url_decode($parts[2]), true);
  if(!$payload || !isset($payload['me'])) return null;

  $me = $payload['me'];
  if(!verify_signed_code($signing_key, $me . $redirect_uri . $client_id, $code)) return null;

  // PKCE: prove possession of the verifier the bound challenge was derived from.
  $challenge = base64_url_encode(hash("sha256", $verifier, true));
  if(!isset($payload['challenge']) || !hash_equals($payload['challenge'], $challenge)) return null;

  $meta = query_user($me);
  if(!$meta) return null;

  unset($meta['passphrase']); // Let's not leak the passphrase.

  return ['me' => $me, 'meta' => $meta];
}

function build_public_url($path = null) {
  global $proxy_public_host, $proxy_public_proto, $proxy_public_path;
  return merge_query("$proxy_public_proto://$proxy_public_host$proxy_public_path",
    strip: ['_to', '_path']);
}

function build_target_url() {
  global $proxy_target_host, $proxy_target_proto, $proxy_target_path;
  return merge_query("$proxy_target_proto://$proxy_target_host$proxy_target_path",
    strip: ['_to', '_path', 'code', 'state', 'iss', 'me']);
}

function merge_query($url, $strip = []) {
  $query = array_diff_key($_GET, array_flip($strip));
  if(!empty($query)) $url .= '?' . http_build_query($query);

  return $url;
}

// Strip CR/LF so a stray newline in a value can't inject extra headers.
function strip_crlf($value) {
  return str_replace(["\r", "\n"], '', (string) $value);
}

function proxy_forward($target, $user) {
  $method = $_SERVER['REQUEST_METHOD'];
  $skip = ['host', 'connection', 'keep-alive', 'transfer-encoding',
           'te', 'trailer', 'upgrade', 'proxy-authorization', 'content-length',
           // Strip our own trust headers so a client can't spoof identity.
           'x-forwarded-to', 'x-forwarded-path',
           'x-forwarded-user', 'x-forwarded-userid',
           'x-nym-user', 'x-nym-userid'];

  $headers = [];
  foreach(getallheaders() as $name => $value) {
    $lower = strtolower($name);
    if(in_array($lower, $skip)) continue;
    if($lower === 'cookie') {
      $cookies = array_filter(
        array_map('trim', explode(';', $value)),
        fn($c) => !str_starts_with($c, 'nym_session=')
      );
      $filtered = implode('; ', $cookies);
      if(!empty($filtered)) $headers[] = "Cookie: $filtered";
      continue;
    }
    $headers[] = "$name: $value";
  }

  $headers[] = "X-Nym-UserID: " . strip_crlf($user['me'] ?? '');
  if(isset($user['meta']['username'])) {
    $headers[] = "X-Nym-User: " . strip_crlf($user['meta']['username']);
  }

  $ch = curl_init($target);
  curl_setopt_array($ch, [
    CURLOPT_CUSTOMREQUEST => $method,
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_HEADER => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 30,
  ]);

  if(in_array($method, ['POST', 'PUT', 'PATCH'])) {
    $body = file_get_contents('php://input');
    if($body !== false && strlen($body) > 0) curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
  }

  $response = curl_exec($ch);
  $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
  $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);

  curl_close($ch);

  if($response === false) return false;

  return [$status, substr($response, 0, $header_size), substr($response, $header_size)];
}

function proxy_emit($status, $head, $body) {
  http_response_code($status);

  $skip = ['transfer-encoding', 'connection', 'keep-alive'];

  foreach(explode("\r\n", $head) as $line) {
    $line = trim($line);
    if(empty($line) || str_starts_with($line, 'HTTP/') || !str_contains($line, ':')) continue;
    $name = strtolower(explode(':', $line, 2)[0]);
    if(in_array($name, $skip)) continue;
    header($line, $name != 'set-cookie');
  }
  echo $body;
}

$user = fetch_user_from_session();

// Handle the auth callback; code was issued by Nym and the browser was
// redirected back here through Caddy, so the X-Forwarded-* headers are set
// as normal and code/state/iss arrive in the query.
if(isset($_GET['code'], $_GET['state'], $_GET['iss'])) {
  $code = filter_input_regexp(INPUT_GET, "code", '@^[0-9a-f]+:[0-9a-f]{64}:@');
  $state = $_GET['state'];
  $iss = $_GET['iss'];

  if($iss != $issuer || !$code || !verify_signed_code($signing_key, 'proxy_state', $state)) {
    http_response_code(400);
    echo "Invalid callback parameters.";
    exit;
  }

  $state_parts = explode(":", $state, 3);
  $state_data = json_decode(base64_url_decode($state_parts[2]), true);

  if(!$state_data || !isset($state_data['return'])) {
    http_response_code(400);
    echo "Malformed state.";
    exit;
  }

  $verifier = fetch_verifier();

  if(!is_string($verifier)) {
    clear_verifier();
    http_response_code(401);
    echo "Verification failed: malformed code verifier.";
    exit;
  }

  $result = verify_proxy_code($code, $redirect_uri, $client_id, $verifier);

  if(!$result) {
    clear_verifier();
    http_response_code(401);
    echo "Verification failed: given code was invalid.";
    exit;
  }

  log_in_via_session($result);
  clear_verifier();

  header("Location: " . $state_data['return']);
  exit;
}

// If this is a regular request and the user has been logged in
// reverse proxy to the application.
elseif($user) {
  $result = proxy_forward(build_target_url(), $user);
  if(!$result) { http_response_code(502); echo "Bad gateway."; exit; }
  proxy_emit(...$result);
  exit;
}

// If this is a regular request and the user has not been logged in,
// start an authentication flow.
else {
  $code_verifier = fetch_verifier() ?: base64_url_encode(random_bytes(32));
  $code_challenge = base64_url_encode(hash("sha256", $code_verifier, true));

  store_verifier($code_verifier);

  $state = create_signed_code($signing_key, 'proxy_state', 5 * 60, json_encode([
    'return' => build_public_url(), // Redirect to the current page after authentication.
  ]));

  $params = http_build_query([
    "client_id" => $client_id,
    "redirect_uri" => $redirect_uri,
    "state" => $state,
    "code_challenge" => $code_challenge,
    "code_challenge_method" => 'S256',
  ]);

  header("Location: $issuer?$params");
  exit;
}
