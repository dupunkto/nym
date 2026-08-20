<?php
// IndieAuth endpoint.

if(isset($_GET['metadata'])) {
  header('Content-Type: application/json');
  echo json_encode([
    "issuer" => $issuer,
    "authorization_endpoint" => $issuer,
    "token_endpoint" => $token_endpoint,
    "scopes_supported" => $oauth_scopes,
  ], flags: JSON_UNESCAPED_SLASHES);
  exit;
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

  if(!verify_signed_code($hmac_signing_key, $me . $redirect_uri . $client_id, $code)) {
    http_response_code(400);
    echo "Verification failed: given code was invalid.";
    exit;
  }

  // PKCE: a supplied verifier must match the bound challenge. A missing
  // verifier is fatal only in strict mode; otherwise it is tolerated so proxy
  // token endpoints that drop it (e.g. tokens.indieauth.com) can still redeem.
  if(isset($payload['challenge']) && $payload['challenge'] != null) {
    $verifier = filter_input(INPUT_POST, "code_verifier", FILTER_UNSAFE_RAW);

    if(is_string($verifier)) {
      $hash = base64_url_encode(hash("sha256", $verifier, true));

      if(!hash_equals($payload['challenge'], $hash)) {
        http_response_code(400);
        echo "Verification failed: given code verifier was invalid.";
        exit;
      }
    } elseif($enforce_pkce) {
      http_response_code(400);
      echo "Verification failed: malformed code verifier.";
      exit;
    }
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
$code_challenge = filter_input_regexp(INPUT_GET, "code_challenge", '@^[A-Za-z0-9\-_]{43,128}$@');
$code_challenge_method = filter_input_regexp(INPUT_GET, "code_challenge_method", '@^S256$@');

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

if($code_challenge === false) {
  http_response_code(400);
  echo "The 'code_challenge' is malformed.";
  exit;
}

// We only support S256; reject a present challenge without it (incl. 'plain').
if($code_challenge != null && $code_challenge_method != 'S256') {
  http_response_code(400);
  echo "Only the S256 code_challenge_method is supported.";
  exit;
}

$session = resolve_login_session();
$authentication = null;
$show_credentials = !$session;

// Okay, everything looks gooooood :D
// If the user submitted the form, it's time to try to
// redirect to the callback.

if($_SERVER['REQUEST_METHOD'] == 'POST') {
  $csrf_token = filter_input(INPUT_POST, "_csrf", FILTER_UNSAFE_RAW);

  if($csrf_token === null or !verify_signed_code($hmac_signing_key, $client_id . $redirect_uri . $state, $csrf_token)) {
    http_response_code(400);
    die("Invalid CSRF token. Please try again.");
  }

  $scope = filter_input_regexp(
    INPUT_POST,
    "scopes",
    '@^[\x21\x23-\x5B\x5D-\x7E]+$@',
    flags: FILTER_REQUIRE_ARRAY
  );

  if($scope !== null) {
    if($scope === false ||
      in_array(false, $scope, true) ||
      array_diff($scope, explode(' ', (string) @$_GET['scope']))) {
      http_response_code(400);
      die("The scopes provided were malformed or not requested.");
    }
  }

  $action = filter_input(INPUT_POST, "action", FILTER_UNSAFE_RAW);
  $username = filter_input(INPUT_POST, "username", FILTER_UNSAFE_RAW);
  $password = filter_input(INPUT_POST, "password", FILTER_UNSAFE_RAW);

  if($action === null && ($username !== null || $password !== null)) $action = 'password';

  if($action == 'authorize') {
    if($session) $authentication = $session;
    else $show_credentials = true;
  }
  elseif($action == 'other_account') {
    $show_credentials = true;
  }
  elseif($action == 'password') {
    if(!is_string($username) || !is_string($password)) {
      http_response_code(400);
      die("Username or password is missing.");
    }

    $user = verify_user_password($username, $password);

    if(!$user) {
      syslog(LOG_CRIT, "Nym: attempted login from " . @$_SERVER['REMOTE_ADDR'] . " for $username");
      http_response_code(403);
      die("Invalid username or password.");
    }

    $authentication = replace_login_session($user);
    syslog(LOG_INFO, "Nym: login from " . @$_SERVER['REMOTE_ADDR'] . " for $username");
  } else {
    http_response_code(400);
    die("Unknown authorization action.");
  }
}

if($authentication) {
  $user = $authentication['user'];
  if($scope !== null) $scope = implode(' ', $scope);
  $payload = json_encode(['me' => $user['me'], 'scope' => $scope, 'challenge' => $code_challenge]);
  $code = create_signed_code(
    $hmac_signing_key,
    $user['me'] . $redirect_uri . $client_id,
    ttl: 5 * 60,
    appended_data: $payload
  );
  $parameters = [
    "code" => $code,
    "me" => $user['me'],
    "iss" => $issuer,
  ];

  if($state !== null) $parameters['state'] = $state;

  header("Location: " . append_query_parameters($redirect_uri, $parameters), response_code: 302);
  exit;
}

$csrf_token = create_signed_code(
  $hmac_signing_key,
  $client_id . $redirect_uri . $state,
  ttl: 2 * 60
);

$title = $show_credentials ? "Sign in" : "Authorize";

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
          Logging in to
          <strong><?= htmlspecialchars($client_id) ?></strong>
        </p>
      </div>

      <form action="" method="post">
        <?php if(!empty($_GET['scope'])) { ?>
          <fieldset>
            <legend>Scopes</legend>
            <?php foreach(explode(" ", $_GET['scope']) as $n => $checkbox) { ?>
              <div>
                <input
                  id="scope_<?= $n ?>"
                  type="checkbox"
                  name="scopes[]"
                  value="<?= htmlspecialchars($checkbox) ?>"
                  <?= $_SERVER['REQUEST_METHOD'] != 'POST' || in_array($checkbox, $scope ?: [], true) ? 'checked' : '' ?>
                >
                <label for="scope_<?= $n ?>" style="display: inline;">
                  <?= htmlspecialchars($checkbox) ?>
                </label>
              </div>
            <?php } ?>
          </fieldset>
        <?php } ?>

        <input type="hidden" name="_csrf" value="<?= $csrf_token ?>">

        <?php if($show_credentials) { ?>
          <input type="hidden" name="action" value="password">

          <label>
            Username
            <input type="text" name="username" id="username" required autofocus>
          </label>

          <label>
            Password
            <input type="password" name="password" id="password" required>
          </label>

          <input type="submit" value="Sign in">
        <?php } else { ?>
          <button type="submit" name="action" value="authorize">
            <?= !empty($_GET['scope'])
              ? "Grant access"
              : "Continue with " . htmlspecialchars($session['user']['email']) ?>
          </button>
          <button type="submit" name="action" value="other_account">Use other account</button>
        <?php } ?>

        <p>
          <small>After logging in, you will be redirected to <?= htmlspecialchars($redirect_uri) ?></small>
        </p>
      </form>
    </main>
  </body>
</html>
