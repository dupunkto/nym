<?php
// OpenID Connect endpoint.

function redirect_error($redirect_uri, $error, $description, $state = null) {
  $parameters = ['error' => $error, 'error_description' => $description];
  if($state !== null) $parameters['state'] = $state;

  header('Cache-Control: no-store');
  header('Location: ' . append_query_parameters($redirect_uri, $parameters), response_code: 302);
  die;
}

function profile_claims($user, $scope) {
  $scopes = explode(' ', $scope);
  $claims = ['sub' => $user['sub']];

  if(in_array('profile', $scopes, true)) {
    if(isset($user['displayname']) && is_string($user['displayname'])) {
      $claims['name'] = $user['displayname'];
    }
    if(isset($user['avatar']) && is_string($user['avatar'])) {
      $claims['picture'] = $user['avatar'];
    }
    if(isset($user['username']) && is_string($user['username'])) {
      $claims['preferred_username'] = $user['username'];
    }
  }

  if(in_array('email', $scopes, true) && isset($user['email']) && is_string($user['email'])) {
    $claims['email'] = $user['email'];
    $claims['email_verified'] = true;
  }

  return $claims;
}

function sign_jwt($claims) {
  global $rsa_private_key, $rsa_jwk;

  $header = [
    'alg' => 'RS256',
    'typ' => 'JWT',
    'kid' => $rsa_jwk['kid'],
  ];
  $encoded_header = base64_url_encode(json_encode($header, JSON_UNESCAPED_SLASHES));
  $encoded_claims = base64_url_encode(json_encode($claims, JSON_UNESCAPED_SLASHES));
  $body = "$encoded_header.$encoded_claims";
  $signature = '';

  if(!openssl_sign($body, $signature, $rsa_private_key, OPENSSL_ALGO_SHA256)) {
    http_response_code(500);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    die(json_encode([
      'error' => 'server_error',
      'error_description' => "Token signing failed.",
    ], JSON_UNESCAPED_SLASHES));
  }

  return $body . '.' . base64_url_encode($signature);
}

if($request_path == '/.well-known/openid-configuration') {
  header('Content-Type: application/json');
  echo json_encode([
    'issuer' => $issuer,
    'authorization_endpoint' => $issuer,
    'token_endpoint' => $issuer . '/token',
    'userinfo_endpoint' => $issuer . '/meta',
    'jwks_uri' => $issuer . '/jwks',
    'response_types_supported' => ['code'],
    'response_modes_supported' => ['query'],
    'grant_types_supported' => ['authorization_code'],
    'subject_types_supported' => ['public'],
    'id_token_signing_alg_values_supported' => ['RS256'],
    'scopes_supported' => $connect_scopes,
    'claims_supported' => ['sub', 'name', 'picture', 'preferred_username', 'email', 'email_verified'],
    'prompt_values_supported' => ['none', 'login', 'consent', 'select_account'],
    'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
    'code_challenge_methods_supported' => ['S256'],
  ], JSON_UNESCAPED_SLASHES);
  exit;
}

if($request_path == '/jwks') {
  header('Content-Type: application/json');
  echo json_encode(['keys' => [$rsa_jwk]], JSON_UNESCAPED_SLASHES);
  exit;
}

if($request_path == '/meta') {
  $authorization = @$_SERVER['HTTP_AUTHORIZATION'] ?: @$_SERVER['REDIRECT_HTTP_AUTHORIZATION'];

  if(!is_string($authorization) ||
    !preg_match('/^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/D', $authorization, $match)) {
    http_response_code(401);
    header('WWW-Authenticate: Bearer');
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    die(json_encode(['error' => 'invalid_token'], JSON_UNESCAPED_SLASHES));
  }

  $parts = explode('.', $match[1]);
  $header_json = strict_base64_url_decode($parts[0]);
  $claims_json = strict_base64_url_decode($parts[1]);
  $signature = strict_base64_url_decode($parts[2]);
  $header = $header_json === false ? null : json_decode($header_json, true);
  $claims = $claims_json === false ? null : json_decode($claims_json, true);

  $valid = $signature !== false &&
    is_array($header) &&
    is_array($claims) &&
    @$header['alg'] == 'RS256' &&
    @$header['typ'] == 'JWT' &&
    @$header['kid'] == $rsa_jwk['kid'];

  if($valid) {
    $valid = openssl_verify(
      $parts[0] . '.' . $parts[1],
      $signature,
      $rsa_public_key,
      OPENSSL_ALGO_SHA256
    ) == 1;
  }

  $valid = $valid &&
    @$claims['iss'] == $issuer &&
    @$claims['aud'] == $issuer . '/meta' &&
    is_string(@$claims['sub']) &&
    is_string(@$claims['client_id']) &&
    is_string(@$claims['scope']) &&
    is_int(@$claims['iat']) &&
    is_int(@$claims['exp']) &&
    $claims['exp'] > time();

  if(!$valid) {
    http_response_code(401);
    header('WWW-Authenticate: Bearer error="invalid_token"');
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    die(json_encode(['error' => 'invalid_token'], JSON_UNESCAPED_SLASHES));
  }

  $user = query_user($claims['sub']);

  if(!$user) {
    http_response_code(401);
    header('WWW-Authenticate: Bearer error="invalid_token"');
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    die(json_encode(['error' => 'invalid_token'], JSON_UNESCAPED_SLASHES));
  }

  header('Content-Type: application/json');
  header('Cache-Control: no-store');
  echo json_encode(profile_claims($user, $claims['scope']), JSON_UNESCAPED_SLASHES);
  exit;
}

if($request_path == '/token') {
  if($_SERVER['REQUEST_METHOD'] != 'POST' ||
    !str_starts_with(strtolower((string) @$_SERVER['CONTENT_TYPE']), 'application/x-www-form-urlencoded')) {
    http_response_code(400);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    die(json_encode([
      'error' => 'invalid_request',
      'error_description' => "The token endpoint requires a form-encoded POST request.",
    ], JSON_UNESCAPED_SLASHES));
  }

  $counts = [];
  $body = file_get_contents('php://input');

  foreach(explode('&', $body) as $pair) {
    if($pair == '') continue;

    $name = urldecode(explode('=', $pair, 2)[0]);

    // PHP folds '.', ' ' and '+' in parameter names into '_' and cuts them at
    // '[', so a name that needs folding lands in $_POST under a key other than
    // the one counted here. Reject those rather than mirroring the parser.
    if(!preg_match('/^[A-Za-z0-9_]+$/D', $name)) {
      http_response_code(400);
      header('Content-Type: application/json');
      header('Cache-Control: no-store');
      die(json_encode([
        'error' => 'invalid_request',
        'error_description' => "Malformed token request parameters.",
      ], JSON_UNESCAPED_SLASHES));
    }

    $counts[$name] = @$counts[$name] + 1;
  }

  foreach(['grant_type', 'code', 'redirect_uri', 'code_verifier'] as $name) {
    if(@$counts[$name] > 1) {
      http_response_code(400);
      header('Content-Type: application/json');
      header('Cache-Control: no-store');
      die(json_encode([
        'error' => 'invalid_request',
        'error_description' => "Duplicate token request parameters.",
      ], JSON_UNESCAPED_SLASHES));
    }
  }

  $authorization = @$_SERVER['HTTP_AUTHORIZATION'] ?: @$_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
  $client_id = filter_input(INPUT_POST, "client_id", FILTER_UNSAFE_RAW);
  $client_secret = filter_input(INPUT_POST, "client_secret", FILTER_UNSAFE_RAW);

  if(@$counts['client_id'] > 1 || @$counts['client_secret'] > 1) {
    http_response_code(401);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    die(json_encode([
      'error' => 'invalid_client',
      'error_description' => "Duplicate client credentials.",
    ], JSON_UNESCAPED_SLASHES));
  }

  if($authorization) {
    if($client_id !== null ||
      $client_secret !== null ||
      !preg_match('/^Basic ([A-Za-z0-9+\/=]+)$/D', $authorization, $match)) {
      http_response_code(401);
      header('WWW-Authenticate: Basic realm="Nym"');
      header('Content-Type: application/json');
      header('Cache-Control: no-store');
      die(json_encode([
        'error' => 'invalid_client',
        'error_description' => "Conflicting or malformed client credentials.",
      ], JSON_UNESCAPED_SLASHES));
    }

    $decoded = base64_decode($match[1], true);

    if($decoded === false || !str_contains($decoded, ':')) {
      http_response_code(401);
      header('WWW-Authenticate: Basic realm="Nym"');
      header('Content-Type: application/json');
      header('Cache-Control: no-store');
      die(json_encode([
        'error' => 'invalid_client',
        'error_description' => "Malformed client credentials.",
      ], JSON_UNESCAPED_SLASHES));
    }

    [$client_id, $client_secret] = array_map('urldecode', explode(':', $decoded, 2));
  }

  if(!is_string($client_id) || $client_id == '' || !isset($clients[$client_id])) {
    http_response_code(401);
    header('WWW-Authenticate: Basic realm="Nym"');
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    die(json_encode([
      'error' => 'invalid_client',
      'error_description' => "Client authentication failed.",
    ], JSON_UNESCAPED_SLASHES));
  }

  $client = $clients[$client_id];

  if($client['type'] == 'confidential') {
    if(!is_string($client_secret) || !password_verify($client_secret, $client['secret'])) {
      http_response_code(401);
      header('WWW-Authenticate: Basic realm="Nym"');
      header('Content-Type: application/json');
      header('Cache-Control: no-store');
      die(json_encode([
        'error' => 'invalid_client',
        'error_description' => "Client authentication failed.",
      ], JSON_UNESCAPED_SLASHES));
    }
  } elseif($authorization || $client_secret !== null) {
    http_response_code(401);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    die(json_encode([
      'error' => 'invalid_client',
      'error_description' => "Public clients use client_id without a secret.",
    ], JSON_UNESCAPED_SLASHES));
  }

  if(filter_input(INPUT_POST, "grant_type", FILTER_UNSAFE_RAW) != 'authorization_code') {
    http_response_code(400);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    die(json_encode(['error' => 'unsupported_grant_type'], JSON_UNESCAPED_SLASHES));
  }

  $code = filter_input(INPUT_POST, "code", FILTER_UNSAFE_RAW);
  $redirect_uri = filter_input(INPUT_POST, "redirect_uri", FILTER_UNSAFE_RAW);
  $verifier = filter_input(INPUT_POST, "code_verifier", FILTER_UNSAFE_RAW);

  if(!$code || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $code) || !$redirect_uri) {
    http_response_code(400);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    die(json_encode([
      'error' => 'invalid_request',
      'error_description' => "The code or redirect_uri is missing or malformed.",
    ], JSON_UNESCAPED_SLASHES));
  }

  if($verifier !== null && !preg_match('/^[A-Za-z0-9._~-]{43,128}$/D', $verifier)) {
    http_response_code(400);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    die(json_encode([
      'error' => 'invalid_request',
      'error_description' => "The code_verifier is malformed.",
    ], JSON_UNESCAPED_SLASHES));
  }

  $digest = hash('sha256', $code);
  $result = oidc_state_transaction(function(&$codes) use ($digest, $client, $redirect_uri, $verifier) {
    if(!isset($codes[$digest])) return ['error' => 'invalid_grant'];

    $entry = $codes[$digest];

    if($entry['client_id'] != $client['id'] || $entry['redirect_uri'] != $redirect_uri) {
      return ['error' => 'invalid_grant'];
    }

    if($entry['code_challenge'] !== null) {
      if($verifier === null) return ['error' => 'invalid_grant'];

      $challenge = base64_url_encode(hash('sha256', $verifier, true));
      if(!hash_equals($entry['code_challenge'], $challenge)) {
        return ['error' => 'invalid_grant'];
      }
    } elseif($client['type'] == 'public') {
      return ['error' => 'invalid_grant'];
    }

    $user = query_user($entry['sub']);
    if(!$user) return ['error' => 'server_error'];

    unset($codes[$digest]);
    return ['entry' => $entry, 'user' => $user];
  });

  if(isset($result['error'])) {
    $status = $result['error'] == 'server_error' ? 500 : 400;
    http_response_code($status);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    die(json_encode(['error' => $result['error']], JSON_UNESCAPED_SLASHES));
  }

  $entry = $result['entry'];
  $profile = profile_claims($result['user'], $entry['scope']);
  $now = time();

  $id_claims = array_merge([
    'iss' => $issuer,
    'sub' => $entry['sub'],
    'aud' => $client['id'],
    'iat' => $now,
    'exp' => $now + 5 * 60,
    'auth_time' => $entry['auth_time'],
  ], array_diff_key($profile, ['sub' => true]));

  if($entry['nonce'] !== null) $id_claims['nonce'] = $entry['nonce'];

  $access_claims = [
    'iss' => $issuer,
    'sub' => $entry['sub'],
    'aud' => $issuer . '/meta',
    'client_id' => $client['id'],
    'scope' => $entry['scope'],
    'iat' => $now,
    'exp' => $now + 3600,
  ];

  $response = [
    'access_token' => sign_jwt($access_claims),
    'token_type' => 'Bearer',
    'expires_in' => 3600,
    'id_token' => sign_jwt($id_claims),
    'scope' => $entry['scope'],
  ];

  header('Content-Type: application/json');
  header('Cache-Control: no-store');
  echo json_encode($response, JSON_UNESCAPED_SLASHES);
  exit;
}

if($request_path != '/') {
  http_response_code(404);
  die("Not found.");
}

if($_SERVER['REQUEST_METHOD'] == 'POST') {
  $bound = filter_input(INPUT_POST, "oidc_request", FILTER_UNSAFE_RAW);
  $request = null;

  if($bound && verify_signed_code($hmac_signing_key, 'oidc_authorization_request', $bound)) {
    $parts = explode(':', $bound, 3);
    $request = json_decode(base64_url_decode($parts[2]), true);
  }

  $keys = [
    'client_id',
    'redirect_uri',
    'response_type',
    'response_mode',
    'scopes',
    'state',
    'nonce',
    'prompts',
    'code_challenge',
    'code_challenge_method',
  ];

  $valid = has_exact_keys($request, $keys) &&
    $request['response_type'] == 'code' &&
    $request['response_mode'] == 'query' &&
    isset($clients[$request['client_id']]);

  if($valid) {
    $client = $clients[$request['client_id']];
    $valid = in_array($request['redirect_uri'], $client['redirect_uris'], true) &&
      is_array($request['scopes']) &&
      array_is_list($request['scopes']) &&
      in_array('openid', $request['scopes'], true) &&
      !array_diff($request['scopes'], $client['scopes']) &&
      is_array($request['prompts']) &&
      !array_diff($request['prompts'], ['login', 'consent', 'select_account']);
  }

  if($valid && $request['state'] !== null) {
    $valid = is_string($request['state']) &&
      preg_match('/^[\x20-\x7E]{0,2048}$/D', $request['state']);
  }

  if($valid && $request['nonce'] !== null) {
    $valid = is_string($request['nonce']) &&
      preg_match('/^[\x20-\x7E]{1,2048}$/D', $request['nonce']);
  }

  if($valid) {
    $challenge = $request['code_challenge'];
    $method = $request['code_challenge_method'];
    $valid = (($challenge === null) == ($method === null)) &&
      ($challenge === null ||
        (preg_match('/^[A-Za-z0-9_-]{43,128}$/D', $challenge) && $method == 'S256')) &&
      !($client['type'] == 'public' && $challenge === null);
  }

  if(!$valid) {
    http_response_code(400);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    die(json_encode([
      'error' => 'invalid_request',
      'error_description' => "The authorization request has expired or was modified.",
    ], JSON_UNESCAPED_SLASHES));
  }
} else {
  $client_id = filter_input(INPUT_GET, "client_id", FILTER_UNSAFE_RAW);

  if(!is_string($client_id) || $client_id == '' || !isset($clients[$client_id])) {
    http_response_code(400);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    die(json_encode([
      'error' => 'unauthorized_client',
      'error_description' => "The client is not registered.",
    ], JSON_UNESCAPED_SLASHES));
  }

  $client = $clients[$client_id];
  $redirect_uri = filter_input(INPUT_GET, "redirect_uri", FILTER_UNSAFE_RAW);

  if(!$redirect_uri || !in_array($redirect_uri, $client['redirect_uris'], true)) {
    http_response_code(400);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    die(json_encode([
      'error' => 'invalid_request',
      'error_description' => "The redirect_uri is not registered for this client.",
    ], JSON_UNESCAPED_SLASHES));
  }

  $state = filter_input_regexp(INPUT_GET, "state", '@^[\x20-\x7E]{0,2048}$@D');
  if($state === false) {
    redirect_error($redirect_uri, 'invalid_request', "The state parameter is malformed.");
  }

  $response_type = filter_input(INPUT_GET, "response_type", FILTER_UNSAFE_RAW);
  if($response_type != 'code') {
    redirect_error($redirect_uri, 'unsupported_response_type', "Only response_type=code is supported.", $state);
  }

  $response_mode = array_key_exists('response_mode', $_GET)
    ? filter_input(INPUT_GET, "response_mode", FILTER_UNSAFE_RAW)
    : 'query';

  if($response_mode != 'query') {
    redirect_error($redirect_uri, 'unsupported_response_mode', "Only query response mode is supported.", $state);
  }

  $scope = filter_input(INPUT_GET, "scope", FILTER_UNSAFE_RAW);
  if(!$scope || !preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*$/D', $scope)) {
    redirect_error($redirect_uri, 'invalid_scope', "The scope is missing or malformed.", $state);
  }

  $scopes = array_values(array_unique(explode(' ', $scope)));
  if(!in_array('openid', $scopes, true) ||
    array_diff($scopes, $connect_scopes) ||
    array_diff($scopes, $client['scopes'])) {
    redirect_error($redirect_uri, 'invalid_scope', "The requested scopes are not allowed.", $state);
  }

  $nonce = filter_input_regexp(INPUT_GET, "nonce", '@^[\x20-\x7E]{1,2048}$@D');
  if($nonce === false) {
    redirect_error($redirect_uri, 'invalid_request', "The nonce parameter is malformed.", $state);
  }

  $prompt = array_key_exists('prompt', $_GET)
    ? filter_input(INPUT_GET, "prompt", FILTER_UNSAFE_RAW)
    : null;

  if(array_key_exists('prompt', $_GET) &&
    ($prompt === null || !preg_match('/^[a-z_]+(?: [a-z_]+)*$/D', $prompt))) {
    redirect_error($redirect_uri, 'invalid_request', "The prompt parameter is malformed.", $state);
  }

  $prompts = $prompt === null ? [] : array_values(array_unique(explode(' ', $prompt)));
  if(array_diff($prompts, ['none', 'login', 'consent', 'select_account']) ||
    (in_array('none', $prompts, true) && count($prompts) > 1)) {
    redirect_error($redirect_uri, 'invalid_request', "The requested prompt combination is not supported.", $state);
  }

  $challenge = array_key_exists('code_challenge', $_GET)
    ? filter_input(INPUT_GET, "code_challenge", FILTER_UNSAFE_RAW)
    : null;
  $method = array_key_exists('code_challenge_method', $_GET)
    ? filter_input(INPUT_GET, "code_challenge_method", FILTER_UNSAFE_RAW)
    : null;

  if(($challenge !== null && !preg_match('/^[A-Za-z0-9_-]{43,128}$/D', $challenge)) ||
    (($challenge === null) != ($method === null)) ||
    ($method !== null && $method != 'S256') ||
    ($client['type'] == 'public' && $challenge === null)) {
    redirect_error($redirect_uri, 'invalid_request', "S256 PKCE parameters are missing or malformed.", $state);
  }

  $request = [
    'client_id' => $client_id,
    'redirect_uri' => $redirect_uri,
    'response_type' => 'code',
    'response_mode' => 'query',
    'scopes' => $scopes,
    'state' => $state,
    'nonce' => $nonce,
    'prompts' => $prompts,
    'code_challenge' => $challenge,
    'code_challenge_method' => $method,
  ];

  // TODO: Add an issuer-domain login session so prompt=none can succeed and repeated password entry can be avoided.
  if(in_array('none', $prompts, true)) {
    redirect_error($redirect_uri, 'login_required', "No issuer login session exists.", $state);
  }
}

if($_SERVER['REQUEST_METHOD'] == 'POST') {
  $username = filter_input(INPUT_POST, "username", FILTER_UNSAFE_RAW);
  $password = filter_input(INPUT_POST, "password", FILTER_UNSAFE_RAW);

  if(!is_string($username) || !is_string($password)) {
    redirect_error($request['redirect_uri'], 'invalid_request', "Username or password is missing.", $request['state']);
  }

  $user = verify_user_password($username, $password);

  if(!$user) {
    syslog(LOG_CRIT, "Nym: attempted login from " . @$_SERVER['REMOTE_ADDR'] . " for $username");
    http_response_code(403);
    die("Invalid username or password.");
  }

  if(!isset($user['sub']) ||
    !is_string($user['sub']) ||
    !preg_match('/^[A-Za-z0-9_-]{22,}$/D', $user['sub'])) {
    redirect_error(
      $request['redirect_uri'],
      'server_error',
      "The authenticated user has no valid OIDC subject.",
      $request['state']
    );
  }

  $code = base64_url_encode(random_bytes(32));
  $digest = hash('sha256', $code);
  $now = time();
  $entry = [
    'client_id' => $request['client_id'],
    'redirect_uri' => $request['redirect_uri'],
    'sub' => $user['sub'],
    'scope' => implode(' ', $request['scopes']),
    'nonce' => $request['nonce'],
    'code_challenge' => $request['code_challenge'],
    'code_challenge_method' => $request['code_challenge_method'],
    'auth_time' => $now,
    'expires_at' => $now + 5 * 60,
  ];

  oidc_state_transaction(function(&$codes) use ($digest, $entry) {
    if(isset($codes[$digest])) {
      http_response_code(500);
      header('Content-Type: application/json');
      header('Cache-Control: no-store');
      die(json_encode([
        'error' => 'server_error',
        'error_description' => "Authorization code collision.",
      ], JSON_UNESCAPED_SLASHES));
    }

    $codes[$digest] = $entry;
    return null;
  });

  $parameters = ['code' => $code];
  if($request['state'] !== null) $parameters['state'] = $request['state'];

  header('Cache-Control: no-store');
  header('Location: ' . append_query_parameters($request['redirect_uri'], $parameters), response_code: 302);
  syslog(LOG_INFO, "Nym: login from " . @$_SERVER['REMOTE_ADDR'] . " for $username[oidc]");
  die;
}

$bound = create_signed_code(
  $hmac_signing_key,
  'oidc_authorization_request',
  2 * 60,
  json_encode($request, JSON_UNESCAPED_SLASHES)
);

$client_id = htmlspecialchars($request['client_id']);
$redirect_uri = htmlspecialchars($request['redirect_uri']);

?><!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="//cdn.dupunkto.org/tools.css">
    <title>Sign in</title>
  </head>
  <body>
    <header>
      <h1>Nym</h1>
    </header>
    <main>
      <h1>Sign in</h1>

      <div class="client-info">
        <p>Logging in to <strong><?= $client_id ?></strong></p>
      </div>

      <form action="?scope=openid" method="post">
        <fieldset>
          <legend>Scopes</legend>
          <?php foreach($request['scopes'] as $number => $scope) { ?>
            <div>
              <input id="scope_<?= $number ?>" type="checkbox" checked disabled>
              <label for="scope_<?= $number ?>" style="display: inline;">
                <?= htmlspecialchars($scope) ?>
              </label>
            </div>
          <?php } ?>
        </fieldset>

        <input type="hidden" name="oidc_request" value="<?= htmlspecialchars($bound) ?>">

        <label>
          Username
          <input type="text" name="username" required autofocus>
        </label>

        <label>
          Password
          <input type="password" name="password" required>
        </label>

        <input type="submit" value="Sign in">

        <p>
          <small>After logging in, you will be redirected to <?= $redirect_uri ?></small>
        </p>
      </form>
    </main>
  </body>
</html>
