<?php
// WebFinger endpoint.

$issuer_rel = 'http://openid.net/specs/connect/1.0/issuer';

header('Access-Control-Allow-Origin: *');
header('Content-Type: application/jrd+json');

if($_SERVER['REQUEST_METHOD'] != 'GET') {
  http_response_code(405);
  header('Allow: GET');
  die(json_encode(['error' => "Method not allowed."], flags: JSON_UNESCAPED_SLASHES));
}

$resource = filter_input(INPUT_GET, "resource", FILTER_UNSAFE_RAW);
$rel = filter_input(INPUT_GET, "rel", FILTER_UNSAFE_RAW);

if(!is_string($resource) || strncasecmp($resource, 'acct:', 5) != 0 || strlen($resource) == 5 ||
  ($rel !== null && !is_string($rel))) {
  http_response_code(400);
  die(json_encode(['error' => "Invalid WebFinger request."], flags: JSON_UNESCAPED_SLASHES));
}

$email = substr($resource, 5);
$matches = array_values(array_filter($users, function($user) use ($email) {
  return isset($user['email']) && strcasecmp($user['email'], $email) == 0;
}));

if(count($matches) > 1) {
  http_response_code(500);
  die(json_encode(['error' => "User store contains a duplicate email address."], flags: JSON_UNESCAPED_SLASHES));
}

if(!$matches) {
  http_response_code(404);
  die(json_encode(['error' => "Resource not found."], flags: JSON_UNESCAPED_SLASHES));
}

$user = $matches[0];
$links = [];

if($rel === null || $rel == $issuer_rel) {
  $links[] = [
    'rel' => $issuer_rel,
    'href' => $issuer,
  ];
}

echo json_encode([
  'subject' => 'acct:' . $user['email'],
  'links' => $links,
], flags: JSON_UNESCAPED_SLASHES);
