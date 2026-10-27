<?php
// OpenID Connect endpoint.

function redirect_error($redirect_uri, $error, $description, $state = null) {
  $parameters = ['error' => $error, 'error_description' => $description];
  if($state !== null) $parameters['state'] = $state;

  header('Cache-Control: no-store');

  header('Location: ' . append_query_parameters($redirect_uri, $parameters), response_code: 302);
  die;
}

function json_error($status, $error, $description = null, $authenticate = 'Basic realm="Nym"') {
  global $client_ip, $client_id, $request_path;

  syslog(LOG_WARNING, "Nym: $request_path rejected request from $client_ip"
    . (is_string($client_id) ? " for client $client_id" : '')
    . ": $error" . ($description === null ? '' : " ($description)"));

  http_response_code($status);

  if($status == 401) header("WWW-Authenticate: $authenticate");

  header('Content-Type: application/json');
  header('Cache-Control: no-store');

  die(json_encode(array_filter(
    ['error' => $error, 'error_description' => $description],
    fn($value) => $value !== null), flags: JSON_UNESCAPED_SLASHES));
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
  $encoded_header = base64_url_encode(json_encode($header, flags: JSON_UNESCAPED_SLASHES));
  $encoded_claims = base64_url_encode(json_encode($claims, flags: JSON_UNESCAPED_SLASHES));
  $body = "$encoded_header.$encoded_claims";
  $signature = '';

  if(!openssl_sign($body, $signature, $rsa_private_key, OPENSSL_ALGO_SHA256)) {
    json_error(500, 'server_error', "Token signing failed.");
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
  ], flags: JSON_UNESCAPED_SLASHES);
  exit;
}

if($request_path == '/jwks') {
  header('Content-Type: application/json');
  echo json_encode(['keys' => [$rsa_jwk]], flags: JSON_UNESCAPED_SLASHES);
  exit;
}

if($request_path == '/meta') {
  $authorization = @$_SERVER['HTTP_AUTHORIZATION'] ?: @$_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
  $rejection = null;
  $malformed_authorization = false;
  $user = null;

  if(!is_string($authorization) ||
    !preg_match('/^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/iD', $authorization, $match)) {
    $rejection = "missing or malformed Authorization header";
    $malformed_authorization = true;
  } else {
    $parts = explode('.', $match[1]);
    $header_json = strict_base64_url_decode($parts[0]);
    $claims_json = strict_base64_url_decode($parts[1]);
    $signature = strict_base64_url_decode($parts[2]);
    $header = $header_json === false ? null : json_decode($header_json, true);
    $claims = $claims_json === false ? null : json_decode($claims_json, true);

    if($signature === false || !is_array($header) || !is_array($claims)) {
      $rejection = "malformed JWT";
    } elseif(@$header['alg'] != 'RS256' ||
      @$header['typ'] != 'JWT' ||
      @$header['kid'] != $rsa_jwk['kid']) {
      $rejection = "unsupported JWT header";
    } elseif(openssl_verify(
      $parts[0] . '.' . $parts[1],
      $signature,
      $rsa_public_key,
      OPENSSL_ALGO_SHA256
    ) != 1) {
      $rejection = "invalid JWT signature";
    } elseif(@$claims['iss'] != $issuer) {
      $rejection = "invalid issuer claim";
    } elseif(@$claims['aud'] != $issuer . '/meta') {
      $rejection = "invalid audience claim";
    } elseif(!is_string(@$claims['sub'])) {
      $rejection = "missing subject claim";
    } elseif(!is_string(@$claims['client_id'])) {
      $rejection = "missing client_id claim";
    } elseif(!is_string(@$claims['scope'])) {
      $rejection = "missing scope claim";
    } elseif(!is_int(@$claims['iat'])) {
      $rejection = "invalid issued-at claim";
    } elseif(!is_int(@$claims['exp'])) {
      $rejection = "invalid expiry claim";
    } elseif($claims['exp'] <= time()) {
      $rejection = "expired token";
    } else {
      $user = query_user($claims['sub']);
      if(!$user) $rejection = "unknown subject";
    }
  }

  if($rejection != null) {
    json_error(401, 'invalid_token', $rejection,
      $malformed_authorization ? 'Bearer' : 'Bearer error="invalid_token"');
  }

  header('Content-Type: application/json');
  header('Cache-Control: no-store');
  echo json_encode(profile_claims($user, $claims['scope']), flags: JSON_UNESCAPED_SLASHES);
  exit;
}

if($request_path == '/token') {
  if($_SERVER['REQUEST_METHOD'] != 'POST' ||
    !str_starts_with(strtolower((string) @$_SERVER['CONTENT_TYPE']), 'application/x-www-form-urlencoded')) {
    json_error(400, 'invalid_request', "The token endpoint requires a form-encoded POST request.");
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
      json_error(400, 'invalid_request', "Malformed token request parameters.");
    }

    $counts[$name] = @$counts[$name] + 1;
  }

  foreach(['grant_type', 'code', 'redirect_uri', 'code_verifier'] as $name) {
    if(@$counts[$name] > 1) {
      json_error(400, 'invalid_request', "Duplicate token request parameters.");
    }
  }

  $authorization = @$_SERVER['HTTP_AUTHORIZATION'] ?: @$_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
  $client_id = filter_input(INPUT_POST, "client_id", FILTER_UNSAFE_RAW);
  $client_secret = filter_input(INPUT_POST, "client_secret", FILTER_UNSAFE_RAW);

  // Some clients send an empty client_secret when none is configured.
  if($client_secret === '') $client_secret = null;

  if(@$counts['client_id'] > 1 || @$counts['client_secret'] > 1) {
    json_error(401, 'invalid_client', "Duplicate client credentials.");
  }

  if($authorization) {
    if($client_secret !== null ||
      !preg_match('/^Basic ([A-Za-z0-9+\/=]+)$/D', $authorization, $match)) {
      json_error(401, 'invalid_client', "Conflicting or malformed client credentials.");
    }

    $decoded = base64_decode($match[1], true);

    if($decoded === false || !str_contains($decoded, ':')) {
      json_error(401, 'invalid_client', "Malformed client credentials.");
    }

    $explicit_client_id = $client_id;

    [$client_id, $client_secret] = array_map('urldecode', explode(':', $decoded, 2));

    if($explicit_client_id != null && $explicit_client_id != $client_id) {
      json_error(401, 'invalid_client', "Conflicting client credentials.");
    }
  }

  if(!is_string($client_id) || $client_id == '' || !isset($clients[$client_id])) {
    json_error(401, 'invalid_client', "Client authentication failed.");
  }

  $client = $clients[$client_id];

  if($client['type'] == 'confidential') {
    if(!is_string($client_secret) || !password_verify($client_secret, $client['secret'])) {
      json_error(401, 'invalid_client', "Client authentication failed.");
    }
  } elseif($authorization || $client_secret !== null) {
    json_error(401, 'invalid_client', "Public clients use client_id without a secret.");
  }

  if(filter_input(INPUT_POST, "grant_type", FILTER_UNSAFE_RAW) != 'authorization_code') {
    json_error(400, 'unsupported_grant_type');
  }

  $code = filter_input(INPUT_POST, "code", FILTER_UNSAFE_RAW);
  $redirect_uri = filter_input(INPUT_POST, "redirect_uri", FILTER_UNSAFE_RAW);
  $verifier = filter_input(INPUT_POST, "code_verifier", FILTER_UNSAFE_RAW);

  if(!$code || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $code) || !$redirect_uri) {
    json_error(400, 'invalid_request', "The code or redirect_uri is missing or malformed.");
  }

  if($verifier !== null && !preg_match('/^[A-Za-z0-9._~-]{43,128}$/D', $verifier)) {
    json_error(400, 'invalid_request', "The code_verifier is malformed.");
  }

  $digest = hash('sha256', $code);
  $result = state_transaction('authorization_codes', function(&$codes) use ($digest, $client, $redirect_uri, $verifier) {
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
    json_error($result['error'] == 'server_error' ? 500 : 400, $result['error']);
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
  echo json_encode($response, flags: JSON_UNESCAPED_SLASHES);
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
    'login_hint',
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

  if($valid && $request['login_hint'] !== null) {
    $valid = is_string($request['login_hint']);
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
    json_error(400, 'invalid_request', "The authorization request has expired or was modified.");
  }
} else {
  $client_id = filter_input(INPUT_GET, "client_id", FILTER_UNSAFE_RAW);

  if(!is_string($client_id) || $client_id == '' || !isset($clients[$client_id])) {
    json_error(400, 'unauthorized_client', "The client is not registered.");
  }

  $client = $clients[$client_id];
  $redirect_uri = filter_input(INPUT_GET, "redirect_uri", FILTER_UNSAFE_RAW);

  if(!$redirect_uri || !in_array($redirect_uri, $client['redirect_uris'], true)) {
    json_error(400, 'invalid_request', "The redirect_uri is not registered for this client.");
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

  $login_hint = array_key_exists('login_hint', $_GET)
    ? filter_input(INPUT_GET, "login_hint", FILTER_UNSAFE_RAW)
    : null;

  if(array_key_exists('login_hint', $_GET) && !is_string($login_hint)) {
    redirect_error($redirect_uri, 'invalid_request', "The login_hint parameter is malformed.", $state);
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
    'login_hint' => $login_hint,
    'code_challenge' => $challenge,
    'code_challenge_method' => $method,
  ];

}

if($client['trusted_ips'] && !in_array(
  @inet_pton((string) $client_ip),
  array_map('inet_pton', $client['trusted_ips']),
  strict: true
)) {
  syslog(LOG_WARNING, "Nym: untrusted IP $client_ip for client {$client['id']}");
  redirect_error(
    $request['redirect_uri'],
    'access_denied',
    "Authentication is not allowed from this network.",
    $request['state']
  );
}

$session = resolve_login_session();
$authentication = null;

$has_login_prompt = in_array('login', $request['prompts'], true);
$has_consent_prompt = in_array('consent', $request['prompts'], true);
$has_account_prompt = in_array('select_account', $request['prompts'], true);

$show_credentials = false;
$show_confirmation = false;
$totp_challenge = null;

if($_SERVER['REQUEST_METHOD'] == 'POST') {
  $action = filter_input(INPUT_POST, "action", FILTER_UNSAFE_RAW);
  $username = filter_input(INPUT_POST, "username", FILTER_UNSAFE_RAW);
  $password = filter_input(INPUT_POST, "password", FILTER_UNSAFE_RAW);

  if($action === null && ($username !== null || $password !== null)) $action = 'password';

  if($action == 'authorize') {
    if($session && !$has_login_prompt && ($has_consent_prompt || $has_account_prompt)) {
      $authentication = $session;
    } else {
      $show_credentials = true;
    }
  }

  elseif($action == 'other_account') {
    if($has_login_prompt || (!$has_consent_prompt && !$has_account_prompt)) {
      redirect_error(
        $request['redirect_uri'],
        'invalid_request',
        "The authorization action is not available.",
        $request['state']
      );
    }

    $show_credentials = true;
  }

  elseif($action == 'password') {
    if(!is_string($username) || !is_string($password)) {
      redirect_error($request['redirect_uri'], 'invalid_request', "Username or password is missing.", $request['state']);
    }

    $user = verify_user_password($username, $password);

    if(!$user) {
      syslog(LOG_CRIT, "Nym: attempted login from " . $client_ip . " for $username");
      http_response_code(403);
      die("Invalid username or password.");
    }

    $totp_challenge = create_totp_challenge($user);

    if(!$totp_challenge) {
      $authentication = replace_login_session($user);
      syslog(LOG_INFO, "Nym: login from " . $client_ip . " for $username");
    }
  }

  elseif($action == 'totp') {
    $user = verify_totp_challenge(
      filter_input(INPUT_POST, "totp_challenge", FILTER_UNSAFE_RAW),
      filter_input(INPUT_POST, "totp", FILTER_UNSAFE_RAW)
    );

    if(!$user) {
      syslog(LOG_CRIT, "Nym: invalid TOTP code from " . $client_ip);
      http_response_code(403);
      die("Invalid or expired code.");
    }

    $authentication = replace_login_session($user);
    syslog(LOG_INFO, "Nym: login from " . $client_ip . " for {$user['username']}");
  }
  else {
    redirect_error(
      $request['redirect_uri'],
      'invalid_request',
      "The authorization action is missing or malformed.",
      $request['state']
    );
  }
}
elseif(in_array('none', $request['prompts'], true)) {
  if(!$session) {
    redirect_error(
      $request['redirect_uri'],
      'login_required',
      "No issuer login session exists.",
      $request['state']
    );
  }

  $authentication = $session;
}
elseif($has_login_prompt) {
  $show_credentials = true;
}
elseif($session) {
  if($has_consent_prompt || $has_account_prompt) $show_confirmation = true;
  else $authentication = $session;
}
else {
  $show_credentials = true;
}

if($authentication) {
  $user = $authentication['user'];

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

  if($client['allowed_users'] && !in_array($user['sub'], $client['allowed_users'], true)) {
    syslog(LOG_WARNING, "Nym: user {$user['username']} not allowed for client {$client['id']}");
    redirect_error(
      $request['redirect_uri'],
      'access_denied',
      "This account is not allowed to use this client.",
      $request['state']
    );
  }

  $code = base64_url_encode(random_bytes(32));
  $digest = hash('sha256', $code);
  $entry = [
    'client_id' => $request['client_id'],
    'redirect_uri' => $request['redirect_uri'],
    'sub' => $user['sub'],
    'scope' => implode(' ', $request['scopes']),
    'nonce' => $request['nonce'],
    'code_challenge' => $request['code_challenge'],
    'code_challenge_method' => $request['code_challenge_method'],
    'auth_time' => $authentication['auth_time'],
    'expires_at' => time() + 5 * 60,
  ];

  state_transaction('authorization_codes', function(&$codes) use ($digest, $entry) {
    if(isset($codes[$digest])) {
      json_error(500, 'server_error', "Authorization code collision.");
    }

    $codes[$digest] = $entry;
    return null;
  });

  $parameters = ['code' => $code];
  if($request['state'] !== null) $parameters['state'] = $request['state'];

  header('Cache-Control: no-store');
  header('Location: ' . append_query_parameters($request['redirect_uri'], $parameters), response_code: 302);
  die;
}

$bound = create_signed_code(
  $hmac_signing_key,
  'oidc_authorization_request',
  ttl: 2 * 60,
  appended_data: json_encode($request, flags: JSON_UNESCAPED_SLASHES)
);

$client_id = htmlspecialchars($request['client_id']);
$redirect_uri = htmlspecialchars($request['redirect_uri']);
$scopes = array_values(array_diff($request['scopes'], ['openid']));

$title = $show_credentials || $totp_challenge ? "Sign in" : "Authorize";
$hinted_user = $request['login_hint'] === null ? null : query_user($request['login_hint']);

?><!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="//cdn.dupunkto.org/tools.css">
    <title><?= $title ?></title>
  </head>
  <body>
    <header>
      <h1>Nym</h1>
    </header>
    <main>
      <h1><?= $title ?></h1>

      <div class="client-info">
        <p>
          Logging in to <strong><?= $client_id ?></strong>
          <?php if($hinted_user) { ?>
            as <strong><?= htmlspecialchars($hinted_user['username']) ?></strong>
          <?php } ?>
        </p>
      </div>

      <form action="?scope=openid" method="post">
        <?php if($scopes) { ?>
          <fieldset>
            <legend>Scopes</legend>
            <?php foreach($scopes as $number => $scope) { ?>
              <div>
                <input id="scope_<?= $number ?>" type="checkbox" checked disabled>
                <label for="scope_<?= $number ?>" style="display: inline;">
                  <?= htmlspecialchars($scope) ?>
                </label>
              </div>
            <?php } ?>
          </fieldset>
        <?php } ?>

        <input type="hidden" name="oidc_request" value="<?= htmlspecialchars($bound) ?>">

        <?php if($totp_challenge) { ?>
          <input type="hidden" name="action" value="totp">
          <input type="hidden" name="totp_challenge" value="<?= htmlspecialchars($totp_challenge) ?>">

          <label>
            2FA code
            <input type="text" name="totp" inputmode="numeric" autocomplete="one-time-code" required autofocus>
          </label>

          <input type="submit" value="Verify">
        <?php } elseif($show_credentials) { ?>
          <input type="hidden" name="action" value="password">

          <?php if($hinted_user) { ?>
            <input type="hidden" name="username" value="<?= htmlspecialchars($request['login_hint']) ?>">
          <?php } else { ?>
          <label>
            Username
            <input type="text" name="username" required autofocus>
          </label>
          <?php } ?>

          <label>
            Password
            <input type="password" name="password" required<?= $hinted_user ? " autofocus" : "" ?>>
          </label>

          <input type="submit" value="Sign in">
        <?php } elseif($show_confirmation) { ?>
          <button type="submit" name="action" value="authorize">
            Continue as <?= htmlspecialchars($session['user']['username']) ?> &rarr;
          </button>
          <button type="submit" name="action" value="other_account" style="margin-top: -7px">
            Use other account
          </button>
        <?php } ?>

        <p>
          <small>After logging in, you will be redirected to <?= $redirect_uri ?></small>
        </p>
      </form>
    </main>
  </body>
</html>
