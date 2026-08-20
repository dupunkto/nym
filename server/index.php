<?php
// Identity provider and authentication layer.
// Influenced by/based on Inklings-io/selfauth, which is CC0 and MIT dual-licensed.
//
// Credits to them for the original implementation. Fully copy of the MIT license
// notice is included below:
//
// Copyright (c) 2017
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require_once __DIR__ . "/neuro/std.php";

$issuer = rtrim((string) getenv('ISSUER'), '/');
$ttl = (int) (getenv('SESSION_TTL') ?: 7 * 24 * 3600);

$hmac_signing_key = getenv('HMAC_SIGNING_KEY');
$rsa_signing_key = getenv('RSA_SIGNING_KEY') ?: __DIR__ . '/private.pem';
$token_endpoint = getenv('TOKEN_ENDPOINT') ?: 'https://tokens.indieauth.com/token';

$user_store = getenv('USERS') ?: __DIR__ . '/users.json';
$client_store = getenv('CLIENTS') ?: __DIR__ . '/clients.json';
$state_store = getenv('STATE') ?: __DIR__ . '/state.json';

$oauth_scopes = ['create', 'update', 'delete', 'media'];
$connect_scopes = ['openid', 'profile', 'email'];

$request_path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

$proxy_enabled = in_array(strtolower((string) getenv('PROXY_ENABLE')),
  ['1', 'true', 'on', 'yes'], strict: true);
$enforce_pkce = in_array(strtolower((string) getenv('ENFORCE_PKCE')),
  ['1', 'true', 'on', 'yes'], strict: true);

if(!$issuer) {
  http_response_code(500);
  die("ISSUER environment variable is not set.");
}

if(!$hmac_signing_key) {
  http_response_code(500);
  die("HMAC_SIGNING_KEY environment variable is not set.");
}

if(!$rsa_signing_key) {
  http_response_code(500);
  die("RSA_SIGNING_KEY environment variable is not set.");
}

if(!is_file($rsa_signing_key) || !is_readable($rsa_signing_key)) {
  http_response_code(500);
  die("RSA_SIGNING_KEY cannot be found or is unreadable.");
}

$rsa_private_key = openssl_pkey_get_private(file_get_contents($rsa_signing_key));

if(!$rsa_private_key) {
  http_response_code(500);
  die("RSA_SIGNING_KEY is not a valid private key.");
}

$details = openssl_pkey_get_details($rsa_private_key);

if(!$details
  || $details['type'] != OPENSSL_KEYTYPE_RSA
  || $details['bits'] < 2048
  || !isset($details['rsa']['n'], $details['rsa']['e'])) {
  http_response_code(500);
  die("RSA_SIGNING_KEY must be an RSA private key of at least 2048 bits.");
}

if(!file_exists($user_store) || !is_readable($user_store)) {
  http_response_code(500);
  die("User store not found: $user_store");
}

$users = json_decode(file_get_contents($user_store), true);

if(json_last_error() != JSON_ERROR_NONE) {
  http_response_code(500);
  die("User store is malformed.");
}

if(!is_array($users) || !array_is_list($users)) {
  http_response_code(500);
  die("User store must be a JSON array.");
}

// query_user() resolves a lookup against username, me and sub alike, so all
// three fields share a single namespace: a collision between one user's sub
// and another's username would hand over the wrong account.
$identifiers = [];

foreach($users as $user) {
  $required = ['username', 'passphrase', 'me', 'sub'];
  $optional = ['displayname', 'avatar', 'email'];

  if(!is_array($user)
    || array_diff($required, array_keys($user))
    || array_diff(array_keys($user), $required, $optional)) {
    http_response_code(500);
    die("User store contains an invalid user schema.");
  }

  foreach([...$required, ...$optional] as $key) {
    if(array_key_exists($key, $user) && (!is_string($user[$key]) || $user[$key] == '')) {
      http_response_code(500);
      die("User store contains an empty or non-string user field.");
    }
  }

  $username = $user['username'];

  if(password_get_info($user['passphrase'])['algo'] == null) {
    http_response_code(500);
    die("User '$username' has an invalid passphrase hash.");
  }

  if(!str_starts_with($user['me'], 'https://') && !str_starts_with($user['me'], 'http://')) {
    http_response_code(500);
    die("User '$username' has an invalid profile URL.");
  }

  if(!preg_match('/^[A-Za-z0-9_-]{22,}$/D', $user['sub'])) {
    http_response_code(500);
    die("User '$username' has an invalid OIDC subject.");
  }

  foreach([$user['username'], $user['me'], $user['sub']] as $identifier) {
    if(isset($identifiers[$identifier])) {
      http_response_code(500);
      die("User '$username' has an identifier that is already in use.");
    }

    $identifiers[$identifier] = true;
  }
}

if(!is_file($state_store)
    || !is_readable($state_store)
    || !is_writable($state_store)
    || !is_writable(dirname($state_store))) {
  http_response_code(500);
  die("State store not found: $state_store");
}

$lock = @fopen($state_store . '.lock', 'c+');

if(!$lock) {
  http_response_code(500);
  die("Lock cannot be accessed.");
}

fclose($lock);

if(!is_file($client_store) || !is_readable($client_store)) {
  http_response_code(500);
  die("Client registry not found: $client_store");
}

$registry = json_decode(file_get_contents($client_store), true);

if(json_last_error() != JSON_ERROR_NONE) {
  http_response_code(500);
  die("Client registry is malformed.");
}

if(!is_array($registry) || !array_is_list($registry)) {
  http_response_code(500);
  die("Client registry must be a JSON array.");
}

$clients = [];

foreach($registry as $entry) {
  if(!is_array($entry) || !isset($entry['type'])) {
    http_response_code(500);
    die("Client registry contains an invalid client.");
  }

  $type = $entry['type'];
  $keys = $type == 'confidential'
    ? ['id', 'type', 'secret', 'redirect_uris', 'scopes']
    : ['id', 'type', 'redirect_uris', 'scopes'];

  if(!in_array($type, ['confidential', 'public'], true) || !has_exact_keys($entry, $keys)) {
    http_response_code(500);
    die("Client registry contains an invalid client schema.");
  }

  $id = $entry['id'];

  if(!is_string($id) || $id == '' || isset($clients[$id])) {
    http_response_code(500);
    die("Client IDs must be non-empty and unique.");
  }

  if(!is_nonempty_list($entry['redirect_uris'])) {
    http_response_code(500);
    die("Client '$id' has no redirect URLs.");
  }

  foreach($entry['redirect_uris'] as $redirect_uri) {
    if(!is_url($redirect_uri)) {
      http_response_code(500);
      die("Client '$id' has an invalid redirect URL.");
    }
  }

  if(has_duplicate_keys($entry['redirect_uris'])) {
    http_response_code(500);
    die("Client '$id' has duplicate redirect URLs.");
  }

  if(!is_nonempty_list($entry['scopes'])) {
    http_response_code(500);
    die("Client '$id' has no scopes.");
  }

  foreach($entry['scopes'] as $scope) {
    if(!is_string($scope) || !in_array($scope, $connect_scopes, true)) {
      http_response_code(500);
      die("Client '$id' has an unsupported scope.");
    }
  }

  if(!in_array('openid', $entry['scopes'], true) || has_duplicate_keys($entry['scopes'])) {
    http_response_code(500);
    die("Client '$id' must have unique scopes including openid.");
  }

  if($type == 'confidential') {
    if(!is_string($entry['secret']) || $entry['secret'] == '' || password_get_info($entry['secret'])['algo'] == null) {
      http_response_code(500);
      die("Client '$id' has an invalid secret hash.");
    }
  }

  $clients[$id] = $entry;
}

$rsa_jwk = [
  'kty' => 'RSA',
  'n' => base64_url_encode($details['rsa']['n']),
  'e' => base64_url_encode($details['rsa']['e']),
];

$thumbprint = json_encode(['e' => $rsa_jwk['e'], 'kty' => 'RSA', 'n' => $rsa_jwk['n']], flags: JSON_UNESCAPED_SLASHES);
$rsa_jwk['kid'] = base64_url_encode(hash('sha256', $thumbprint, true));
$rsa_jwk['use'] = 'sig';
$rsa_jwk['alg'] = 'RS256';
$rsa_public_key = $details['key'];

reconcile_state();

// URL-safe base64 encoding (RFC 7515 Appendix C)
function base64_url_encode($string) {
  $string = base64_encode($string);
  $string = rtrim($string, '=');
  $string = strtr($string, '+/', '-_');
  return $string;
}

function base64_url_decode($string) {
  $string = strtr($string, '-_', '+/');
  $padding = strlen($string) % 4;
  if($padding !== 0) {
    $string .= str_repeat('=', 4 - $padding);
  }
  return base64_decode($string);
}

function strict_base64_url_decode($string) {
  if(!is_string($string) || !preg_match('/^[A-Za-z0-9_-]+$/D', $string)) return false;
  $decoded = base64_url_decode($string);
  if($decoded === false || !hash_equals(base64_url_encode($decoded), $string)) return false;
  return $decoded;
}

// Signed codes always have an time-to-live, by default 1 year (31536000 seconds).
function create_signed_code($key, $message, $ttl = 31536000, $appended_data = "") {
  $expires = time() + $ttl;
  $body = $message . $expires . $appended_data;
  $signature = hash_hmac("sha256", $body, $key);
  return dechex($expires) . ":" . $signature . ":" . base64_url_encode($appended_data);
}

function verify_signed_code($key, $message, $code) {
  $code_parts = explode(":", $code, 3);
  if(count($code_parts) !== 3) return false;

  $expires = hexdec($code_parts[0]);
  if(time() > $expires) return false;

  $body = $message . $expires . base64_url_decode($code_parts[2]);
  $signature = hash_hmac("sha256", $body, $key);
  return hash_equals($signature, $code_parts[1]);
}

function filter_input_regexp($type, $variable, $regexp, $flags = null) {
  $options = ['options' => ['regexp' => $regexp]];
  if($flags !== null) $options['flags'] = $flags;

  return filter_input($type, $variable, FILTER_VALIDATE_REGEXP, $options);
}

function get_q_value($mime, $accept) {
  $full_type = preg_replace('@^([^/]+\/).+$@', '$1*', $mime);

  $regex = implode('', [
    '/(?<=^|,)\s*(\*\/\*|',
    preg_quote($full_type, '/'),
    '|',
    preg_quote($mime, '/'),
    ')\s*(?:[^,]*?;\s*q\s*=\s*([0-9.]+))?\s*(?:,|$)/'
  ]);

  preg_match_all($regex, $accept, $matches);
  $types = array_combine($matches[1], $matches[2]);

  $q = match(true) {
    array_key_exists($mime, $types) => $types[$mime],
    array_key_exists($full_type, $types) => $types[$full_type],
    array_key_exists('*/*', $types) => $types['*/*'],
    default => null
  };

  if($q === null) return 0;
  if($q === "") return 1;
  return floatval($q);
}

function query_user($q) {
  global $users;

  if(!is_string($q)) return null;

  foreach($users as $user) {
    if($user['username'] === $q
      || $user['me'] === $q
      || $user['sub'] === $q) return $user;
  }
  return null;
}

function verify_user_password($username, $password) {
  $user = query_user($username);

  if(!$user) {
    // Constant-time dummy hash to prevent timing attacks
    password_verify($password, '$2y$10$abcdefghijklmnopqrstuv1234567890123456789012');
    return false;
  }

  if(password_verify($password, $user['passphrase'])) {
    unset($user['passphrase']);
    return $user;
  }

  return null;
}

function fetch_client_metadata($client_id) {
  $context = stream_context_create([
    'http' => [
      'timeout' => 5,
      'user_agent' => 'Nym/1.0',
    ]
  ]);

  $content = @file_get_contents($client_id, false, $context);
  if($content === false) return null;

  // Look for rel="redirect_uri" links in HTML
  $redirect_uris = [];
  if(preg_match_all('/<link\s+[^>]*rel=["\']redirect_uri["\'][^>]*>/i', $content, $matches)) {
    foreach($matches[0] as $link) {
      if(preg_match('/href=["\']([^"\']+)["\']/i', $link, $href_match)) {
        $redirect_uris[] = $href_match[1];
      }
    }
  }

  return ['redirect_uris' => $redirect_uris];
}

function validate_redirect_uri($client_id, $redirect_uri) {
  // This is very slow so I cannot be bothered to turn it on.
  $metadata = []; // fetch_client_metadata($client_id)

  if($metadata === null || empty($metadata['redirect_uris'])) {
    // Fallback: require same origin as client_id
    $client_parts = parse_url($client_id);
    $redirect_parts = parse_url($redirect_uri);

    if(!$client_parts || !$redirect_parts) return false;

    return $client_parts['scheme'] == $redirect_parts['scheme'] &&
           $client_parts['host'] == $redirect_parts['host'] &&
           ($client_parts['port'] ?? null) == ($redirect_parts['port'] ?? null);
  }

  return in_array($redirect_uri, $metadata['redirect_uris'], true);
}

function append_query_parameters($url, $parameters) {
  return $url . (str_contains($url, '?') ? '&' : '?') . http_build_query($parameters);
}

function passphrase_fingerprint($passphrase_hash) {
  global $hmac_signing_key;
  return hash_hmac('sha256', "nym::session::passphrase::v0\0" . $passphrase_hash, $hmac_signing_key);
}

function validate_state_document($state) {
  if(!has_exact_keys($state, ['authorization_codes', 'login_sessions']) ||
    !is_map($state['authorization_codes']) ||
    !is_map($state['login_sessions'])) {
    http_response_code(500);
    die("State store is malformed.");
  }

  $required = ['client_id', 'redirect_uri', 'sub', 'scope', 'nonce', 'code_challenge', 'code_challenge_method', 'auth_time', 'expires_at'];

  foreach($state['authorization_codes'] as $digest => $entry) {
    if(!is_string($digest) || !preg_match('/^[0-9a-f]{64}$/', $digest) || !has_exact_keys($entry, $required)) {
      http_response_code(500);
      die("State store contains a malformed authorization code.");
    }

    foreach(['client_id', 'redirect_uri', 'sub', 'scope'] as $key) {
      if(!is_string($entry[$key]) || $entry[$key] == '') {
        http_response_code(500);
        die("State store contains malformed authorization data.");
      }
    }

    foreach(['nonce', 'code_challenge', 'code_challenge_method'] as $key) {
      if($entry[$key] !== null && !is_string($entry[$key])) {
        http_response_code(500);
        die("State store contains malformed authorization data.");
      }
    }

    $scopes = explode(' ', $entry['scope']);

    if(!is_url($entry['redirect_uri']) || !preg_match('/^[A-Za-z0-9_-]{22,}$/D', $entry['sub']) ||
      !in_array('openid', $scopes, true) || array_diff($scopes, ['openid', 'profile', 'email']) ||
      ($entry['nonce'] !== null && (strlen($entry['nonce']) > 2048 || !preg_match('/^[\x20-\x7E]*$/D', $entry['nonce']))) ||
      ($entry['code_challenge'] !== null && !preg_match('/^[A-Za-z0-9_-]{43,128}$/D', $entry['code_challenge'])) ||
      !is_int($entry['auth_time']) || !is_int($entry['expires_at']) || $entry['auth_time'] >= $entry['expires_at'] ||
      (($entry['code_challenge'] === null) != ($entry['code_challenge_method'] === null)) ||
      ($entry['code_challenge_method'] !== null && $entry['code_challenge_method'] != 'S256')) {
      http_response_code(500);
      die("State store contains malformed authorization data.");
    }
  }

  $required = ['sub', 'passphrase_fingerprint', 'auth_time', 'expires_at'];

  foreach($state['login_sessions'] as $digest => $entry) {
    if(!is_string($digest) || !preg_match('/^[0-9a-f]{64}$/', $digest) || !has_exact_keys($entry, $required) ||
      !is_string($entry['sub']) || !preg_match('/^[A-Za-z0-9_-]{22,}$/D', $entry['sub']) ||
      !is_string($entry['passphrase_fingerprint']) || !preg_match('/^[0-9a-f]{64}$/', $entry['passphrase_fingerprint']) ||
      !is_int($entry['auth_time']) || !is_int($entry['expires_at']) || $entry['auth_time'] >= $entry['expires_at']) {
      http_response_code(500);
      die("State store contains a malformed login session.");
    }
  }

  return $state;
}

function state_transaction($map, $operation) {
  global $state_store;

  if(!in_array($map, ['authorization_codes', 'login_sessions'], true)) {
    http_response_code(500);
    die("State transaction has an invalid map.");
  }

  $lock = @fopen($state_store . '.lock', 'c+');
  if(!$lock || !flock($lock, LOCK_EX)) {
    if($lock) fclose($lock);
    http_response_code(500);
    die("Could not acquire lock.");
  }

  $contents = @file_get_contents($state_store);

  if($contents === false) {
    http_response_code(500);
    die("State store could not be read.");
  }

  $state = json_decode($contents, true);

  if(json_last_error() != JSON_ERROR_NONE) {
    http_response_code(500);
    die("State store is malformed.");
  }

  $state = validate_state_document($state);

  $now = time();
  foreach($state['authorization_codes'] as $digest => $entry) {
    if($entry['expires_at'] <= $now) unset($state['authorization_codes'][$digest]);
  }

  foreach($state['login_sessions'] as $digest => $entry) {
    $user = query_user($entry['sub']);
    $valid = $entry['expires_at'] > $now &&
      $user &&
      hash_equals(passphrase_fingerprint($user['passphrase']), $entry['passphrase_fingerprint']);

    if(!$valid) unset($state['login_sessions'][$digest]);
  }

  $result = $operation($state[$map]);
  $encoded = json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

  if($encoded === false) {
    http_response_code(500);
    die("State store could not be encoded.");
  }

  $temporary = tempnam(dirname($state_store), basename($state_store) . '.tmp.');

  if($temporary === false) {
    http_response_code(500);
    die("State buffer could not be created.");
  }

  $stream = @fopen($temporary, 'wb');
  $state_contents = $encoded . "\n";

  if(!$stream || fwrite($stream, $state_contents) != strlen($state_contents) || !fflush($stream) ||
    (function_exists('fsync') && !fsync($stream))) {
    if($stream) fclose($stream);
    @unlink($temporary);
    http_response_code(500);
    die("State buffer could not be written.");
  }

  fclose($stream);

  if(!rename($temporary, $state_store)) {
    @unlink($temporary);
    http_response_code(500);
    die("State buffer could not be streamed.");
  }

  flock($lock, LOCK_UN);
  fclose($lock);

  return $result;
}

function reconcile_state() {
  state_transaction('authorization_codes', function($codes) {
    return null;
  });
}

function current_login_session_token() {
  $token = @$_COOKIE['nym_session'];

  if($token === null) return null;
  if(!is_string($token)) return false;

  $decoded = strict_base64_url_decode($token);
  if($decoded === false || strlen($decoded) != 32) return false;

  return $token;
}

function emit_login_session($token, $expires_at) {
  return setcookie('nym_session', $token, [
    'expires' => $expires_at,
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Lax',
  ]);
}

function clear_login_session() {
  return emit_login_session('', time() - 3600);
}

function resolve_login_session() {
  global $ttl;

  $token = current_login_session_token();

  if($token === null) return null;
  if($token === false) {
    clear_login_session();
    return null;
  }

  $digest = hash('sha256', $token);
  $result = state_transaction('login_sessions', function(&$sessions) use ($ttl, $digest) {
    if(!isset($sessions[$digest])) return null;

    $entry = $sessions[$digest];
    $expires_at = time() + $ttl;
    $sessions[$digest]['expires_at'] = $expires_at;

    $user = query_user($entry['sub']);
    unset($user['passphrase']);

    return [
      'user' => $user,
      'auth_time' => $entry['auth_time'],
      'expires_at' => $expires_at,
    ];
  });

  if(!$result) {
    clear_login_session();
    return null;
  }

  emit_login_session($token, $result['expires_at']);
  unset($result['expires_at']);
  return $result;
}

function replace_login_session($user) {
  global $ttl;

  if(!is_array($user) || !is_string(@$user['sub'])) {
    http_response_code(500);
    die("Authenticated user cannot create a login session.");
  }

  $stored_user = query_user($user['sub']);
  if(!$stored_user) {
    http_response_code(500);
    die("Authenticated user cannot create a login session.");
  }

  $token = base64_url_encode(random_bytes(32));
  $digest = hash('sha256', $token);
  $current_token = current_login_session_token();
  $current_digest = is_string($current_token) ? hash('sha256', $current_token) : null;
  $auth_time = time();
  $expires_at = $auth_time + $ttl;
  $entry = [
    'sub' => $stored_user['sub'],
    'passphrase_fingerprint' => passphrase_fingerprint($stored_user['passphrase']),
    'auth_time' => $auth_time,
    'expires_at' => $expires_at,
  ];

  state_transaction('login_sessions', function(&$sessions) use ($digest, $current_digest, $entry) {
    if(isset($sessions[$digest])) {
      http_response_code(500);
      die("Login session collision.");
    }

    if($current_digest !== null && isset($sessions[$current_digest])) {
      unset($sessions[$current_digest]);
    }

    $sessions[$digest] = $entry;
    return null;
  });

  emit_login_session($token, $expires_at);
  unset($stored_user['passphrase']);

  return ['user' => $stored_user, 'auth_time' => $auth_time];
}

function destroy_login_session() {
  $token = current_login_session_token();

  if(is_string($token)) {
    $digest = hash('sha256', $token);
    state_transaction('login_sessions', function(&$sessions) use ($digest) {
      unset($sessions[$digest]);
      return null;
    });
  }

  clear_login_session();
}

if($request_path == '/logout') {
  if($_SERVER['REQUEST_METHOD'] != 'GET') {
    http_response_code(405);
    header('Allow: GET');
    die("Method not allowed.");
  }

  destroy_login_session();
  header("Location: /", response_code: 302);
  exit;
}

// In proxy mode, nym sits in front of another application.
if($request_path == '/proxy' && $proxy_enabled) {
  // Checks whether a user is logged in, and reverse proxies
  // to the configured application, with metadata in the headers.
  // Otherwise, begins an authentication flow.
  require __DIR__ . '/proxy.php';
  exit;
}

if($request_path == '/.well-known/webfinger') {
  require __DIR__ . '/webfinger.php';
  exit;
}

$openid_paths = ['/token', '/meta', '/jwks', '/.well-known/openid-configuration'];

if(in_array($request_path, $openid_paths, true)) {
  require __DIR__ . '/oidc.php';
  exit;
}

if($request_path == '/') {
  if(empty($_GET) and empty($_POST)) {
    ?>
      <!DOCTYPE html>
      <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <meta http-equiv="X-UA-Compatible" content="IE=edge">

          <link rel="canonical" href="https://nym.dupunkto.org">
          <link rel="stylesheet" href="//cdn.dupunkto.org/landing.css" type="text/css">

          <title>Nym</title>
        </head>
        <body>
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="30 60 520 180" height="42">
            <path d="M 50 220 L 50 80 L 170 220 L 170 80" stroke="black" fill="none" stroke-width="10" stroke-linejoin="miter"/>
            <path d="M 210 80 L 270 220 L 330 80" stroke="black" fill="none" stroke-width="10" stroke-linejoin="miter"/>
            <path d="M 370 80 L 370 220 M 370 80 L 450 185 L 530 80 L 530 220" stroke="black" fill="none" stroke-width="10" stroke-linejoin="miter"/>
          </svg>
          <h1>you shall not pass</h1>
          <?php if(resolve_login_session()): ?>
            <p class="buttons">
              <a class="primary" href="/logout">logout</a>
            </p>
          <?php endif; ?>
        </body>
      </html>
    <?php

    exit;
  }

  $scope = @$_GET['scope'] ?: @$_POST['scope'];
  $scopes = is_string($scope) && $scope != '' ? explode(' ', $scope) : [];

  if(in_array('openid', $scopes, true)) {
    require __DIR__ . '/oidc.php';
    exit;
  }

  require __DIR__ . '/indieauth.php';
  exit;
}

http_response_code(404);
die("Not found.");
