<?php
// Identity provider and authentication layer.
// Based on Inklings-io/selfauth (CC0 and MIT dual-licensed).

$issuer = getenv('ISSUER');
$encryption_key = getenv('ENCRYPTION_KEY');
$token_endpoint = getenv('TOKEN_ENDPOINT') ?: 'https://tokens.indieauth.com/token';
$supported_scopes = ['create', 'update', 'delete', 'media'];
$store = getenv('USERS') ?: __DIR__ . '/users.json';

if(!$issuer) {
  http_response_code(500);
  echo "ISSUER environment variable is not set.";
  exit;
}

if(!$encryption_key) {
  http_response_code(500);
  echo "ENCRYPTION_KEY environment variable is not set.";
  exit;
}

if(!file_exists($store)) {
  http_response_code(500);
  echo "Store not found: $store";
  exit;
}

$users = json_decode(file_get_contents($store), true);

if(!is_array($users)) {
  http_response_code(500);
  echo "Invalid store format.";
  exit;
}

if(isset($_GET['metadata'])) {
  header('Content-Type: application/json');
  echo json_encode([
    "issuer" => $issuer,
    "authorization_endpoint" => $issuer,
    "token_endpoint" => $token_endpoint,
    "scopes_supported" => $supported_scopes,
  ]);
  exit;
}

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
  foreach($users as $user) {
    if($user['username'] == $q or $user['me'] == $q) return $user;
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

// Okay, we're ready to rock and roll!!
// The authorization endpoint has three modes:
//
// - Verification, which I *think* verifies codes. Not sure tho.
// - Show an authentication form, and handle submitting it.

// We start with verifying codes. Check if there are any codes to be verified.
// Otherwise, we continue to processing the form below.

$code = filter_input_regexp(INPUT_POST, "code", '@^[0-9a-f]+:[0-9a-f]{64}:@');

if($code !== null) {
  $redirect_uri = filter_input(INPUT_POST, "redirect_uri", FILTER_VALIDATE_URL);
  $client_id = filter_input(INPUT_POST, "client_id", FILTER_VALIDATE_URL);

  if(!is_string($redirect_uri) || !is_string($client_id)) {
    http_response_code(400);
    echo "Verification failed: invalid parameters.";
    exit;
  }

  $code_parts = explode(":", $code, 3);
  $payload = json_decode(base64_url_decode($code_parts[2]), true);

  if(!$payload || !isset($payload['me'])) {
    http_response_code(400);
    echo "Verification failed: invalid code format.";
    exit;
  }

  $me = $payload['me'];

  if(!verify_signed_code($encryption_key, $me . $redirect_uri . $client_id, $code)) {
    http_response_code(400);
    echo "Verification failed: given code was invalid.";
    exit;
  }

  $meta = query_user($me);
  unset($meta['passphrase']);

  $response = ["me" => $me, "meta" => $meta];

  if(isset($payload['scope']) && $payload['scope'] !== null) {
    $response['scope'] = $payload['scope'];
  }

  // Check what kind of response the client wants.
  $accept_header = '*/*';
  if(isset($_SERVER['HTTP_ACCEPT']) and strlen($_SERVER['HTTP_ACCEPT']) > 0) {
      $accept_header = $_SERVER['HTTP_ACCEPT'];
  }

  $json = get_q_value("application/json", $accept_header);
  $form = get_q_value("application/x-www-form-urlencoded", $accept_header);

  if($json === 0 and $form === 0) {
    http_response_code(406);
    echo "Client accepts neither JSON nor form-encoded responses.";
    exit;
  } elseif($json >= $form) {
    header('Content-Type: application/json');
    echo json_encode($response);
    exit;
  } else {
    header('Content-Type: application/x-www-form-urlencoded');
    echo http_build_query($response);
    exit;
  }
}

// Okay, the client apparently wasn't trying to verify a code. So,
// maybe the user has just submitted the form. Collect all data. If
// anything's missing, that means a malformed request, definitely not
// coming from our own form--throw an error.

$client_id = filter_input(INPUT_GET, "client_id", FILTER_VALIDATE_URL);
$redirect_uri = filter_input(INPUT_GET, "redirect_uri", FILTER_VALIDATE_URL);
$state = filter_input_regexp(INPUT_GET, "state", '@^[\x20-\x7E]*$@');
$response_type = filter_input_regexp(INPUT_GET, "response_type", '@^(id|code)?$@');
$scope = filter_input_regexp(INPUT_GET, "scope", '@^([\x21\x23-\x5B\x5D-\x7E]+( [\x21\x23-\x5B\x5D-\x7E]+)*)?$@');

if(!is_string($client_id)) {
  http_response_code(400);
  echo "The 'client_id' was either omitted or not a valid URL.";
  exit;
}

if(!is_string($redirect_uri)) {
  http_response_code(400);
  echo "The 'redirect_uri' was either omitted or not a valid URL.";
  exit;
}

if(!validate_redirect_uri($client_id, $redirect_uri)) {
  http_response_code(400);
  echo "The 'redirect_uri' is not registered for this client.";
  exit;
}

if($state === false) {
  http_response_code(400);
  echo "The 'state' contains illegal characters.";
  exit;
}

if($state === null) {
  http_response_code(400);
  echo "The 'state' parameter is required.";
  exit;
}

if($response_type === false) {
  http_response_code(400);
  echo "The 'response_type' must be either 'id' or 'code'.";
  exit;
}

if($scope === false) {
  http_response_code(400);
  echo "The 'scope' contains illegal characters.";
  exit;
}

// Treat empty scope as omitted.
if($scope === "") $scope = null;

// Okay, everything looks gooooood :D
// If the user submitted their password, it's time to try to
// redirect to the callback.

$username = filter_input(INPUT_POST, "username", FILTER_UNSAFE_RAW);
$password = filter_input(INPUT_POST, "password", FILTER_UNSAFE_RAW);

if($username !== null && $password !== null) {
  $csrf_token = filter_input(INPUT_POST, "_csrf", FILTER_UNSAFE_RAW);

  if($csrf_token === null or !verify_signed_code($encryption_key, $client_id . $redirect_uri . $state, $csrf_token)) {
    http_response_code(400);
    echo "Invalid CSRF token. Please try again.";
    exit;
  }

  $user = verify_user_password($username, $password);

  if(!$user) {
    syslog(LOG_CRIT, "Nym: attempted login from " . $_SERVER['REMOTE_ADDR'] . " for $username");
    http_response_code(403);
    echo "Invalid username or password.";
    exit;
  }

  $scope = filter_input_regexp(INPUT_POST, "scopes", '@^[\x21\x23-\x5B\x5D-\x7E]+$@', FILTER_REQUIRE_ARRAY);

  if($scope !== null) {
    if($scope === false or in_array(false, $scope, true)) {
      http_response_code(400);
      echo "The scopes provided contained illegal characters.";
      exit;
    }
    $scope = implode(' ', $scope);
  }

  $payload = json_encode(['me' => $user['me'], 'scope' => $scope]);
  $code = create_signed_code($encryption_key, $user['me'] . $redirect_uri . $client_id, 5 * 60, $payload);

  $final_uri = $redirect_uri;
  if(strpos($redirect_uri, '?') === false) $final_uri .= '?';
  else $final_uri .= '&';

  $parameters = [
    "code" => $code,
    "me" => $user['me'],
    "iss" => $issuer,
  ];

  if($state !== null) $parameters['state'] = $state;

  $final_uri .= http_build_query($parameters);
  header("Location: $final_uri", response_code: 302);

  syslog(LOG_INFO, "Nym: login from " . $_SERVER['REMOTE_ADDR'] . " for $username");
  exit;
}

$csrf_token = create_signed_code($encryption_key, $client_id . $redirect_uri . $state, 2 * 60);

?><!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="//cdn.geheimesite.nl/tools.css">
    <title>Sign in</title>
  </head>
  <body>
    <header>
      <h1>Nym</h1>
    </header>
    <main>
      <h1>Sign in</h1>

      <div class="client-info">
        <p>
          Logging in to
          <strong><?= htmlspecialchars($client_id) ?></strong>
        </p>
      </div>

      <form action="" method="post">
        <?php if(!empty($scope) and strlen($scope) > 0) { ?>
          <fieldset>
            <legend>Scopes</legend>
            <?php foreach(explode(" ", $scope) as $n => $checkbox) { ?>
              <div>
                <input
                  id="scope_<?= $n ?>"
                  type="checkbox"
                  name="scopes[]"
                  value="<?= htmlspecialchars($checkbox) ?>"
                  checked
                >
                <label for="scope_<?= $n ?>" style="display: inline;">
                  <?= htmlspecialchars($checkbox) ?>
                </label>
              </div>
            <?php } ?>
          </fieldset>
        <?php } ?>

        <input type="hidden" name="_csrf" value="<?= $csrf_token ?>" />

        <label>
          Username
          <input type="text" name="username" id="username" required autofocus>
        </label>

        <label>
          Password
          <input type="password" name="password" id="password" required>
        </label>

        <input type="submit" value="Sign in" />

        <p>
          <small>After logging in, you will be redirected to <?= htmlspecialchars($redirect_uri) ?></small>
        </p>
      </form>
    </main>
  </body>
</html>
