<?php
/* 추억보관함 서버 저장 v1 (v2.10.60)
 * index.html 과 같은 폴더에 올리세요. PHP 7.0 이상.
 * 비밀번호를 잊었을 때: FTP로 data 폴더 안의 _config.php 파일만 지우고 다시 접속하면 새 비밀번호를 정할 수 있어요.
 * (글·사진은 지워지지 않아요)
 */
error_reporting(0);
@ini_set('display_errors', '0');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

define('APP_ID', 'memory-archive');
define('API_VER', 1);
define('DIR', __DIR__ . '/data');
define('IMG', DIR . '/img');
define('GUARD', "<?php exit; ?>\n");
define('MAX_TOKENS', 30);
define('MAX_IMG', 15 * 1024 * 1024);
define('MAX_UPLOAD', 200 * 1024 * 1024);

function out($a, $code = 200) { http_response_code($code); echo json_encode($a, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); exit; }
function fail($msg, $code = 400, $extra = array()) { out(array_merge(array('ok' => false, 'error' => $msg), $extra), $code); }
function rnd($n) { if (function_exists('random_bytes')) return bin2hex(random_bytes($n)); return bin2hex(openssl_random_pseudo_bytes($n)); }
function ensure_dirs() {
  if (!is_dir(DIR) && !@mkdir(DIR, 0755, true)) fail('data 폴더를 만들 수 없어요. 호스팅의 폴더 쓰기 권한을 확인해 주세요.', 500);
  if (!is_dir(IMG)) @mkdir(IMG, 0755, true);
  if (!file_exists(DIR . '/index.html')) @file_put_contents(DIR . '/index.html', '');
  if (!file_exists(IMG . '/index.html')) @file_put_contents(IMG . '/index.html', '');
  /* 임시 조각 파일 직접 접근 차단 (아파치 2.2/2.4 모두). 실패해도 동작에는 영향 없음 */
  if (!file_exists(DIR . '/.htaccess')) @file_put_contents(DIR . '/.htaccess', "<FilesMatch \"\\.tmp$\">\n  <IfModule mod_authz_core.c>\n    Require all denied\n  </IfModule>\n  <IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n  </IfModule>\n</FilesMatch>\n");
}
function read_guarded($f) {
  if (!file_exists($f)) return null;
  $s = @file_get_contents($f);
  if ($s === false) return null;
  if (strpos($s, GUARD) === 0) $s = substr($s, strlen(GUARD));
  return $s;
}
function write_atomic($f, $data) {
  $tmp = $f . '.' . rnd(4) . '.tmp';
  if (@file_put_contents($tmp, $data, LOCK_EX) === false) return false;
  if (!@rename($tmp, $f)) { @unlink($f); if (!@rename($tmp, $f)) { @unlink($tmp); return false; } }
  return true;
}
function conf_path() { return DIR . '/_config.php'; }
function load_conf() { $s = read_guarded(conf_path()); if ($s === null) return null; $c = json_decode($s, true); return is_array($c) ? $c : null; }
function save_conf($c) { if (!write_atomic(conf_path(), GUARD . json_encode($c))) fail('설정을 저장하지 못했어요. 폴더 쓰기 권한을 확인해 주세요.', 500); }
function meta() { $s = read_guarded(DIR . '/_meta.php'); $m = $s ? json_decode($s, true) : null; return is_array($m) ? $m : array('rev' => 0, 'updatedAt' => null, 'site' => null); }
function save_meta($m) { write_atomic(DIR . '/_meta.php', GUARD . json_encode($m)); }
function site_id() { $m = meta(); if (empty($m['site'])) { $m['site'] = rnd(6); save_meta($m); } return $m['site']; }
function param($k, $d = '') { return isset($_POST[$k]) ? (string)$_POST[$k] : (isset($_GET[$k]) ? (string)$_GET[$k] : $d); }
function hash_tok($t) { return hash('sha256', $t); }
function issue_token(&$c, $label) {
  $t = rnd(24);
  if (!isset($c['tokens']) || !is_array($c['tokens'])) $c['tokens'] = array();
  $c['tokens'][] = array('h' => hash_tok($t), 'at' => time(), 'used' => time(), 'label' => substr($label, 0, 80));
  usort($c['tokens'], function ($a, $b) { return $b['used'] - $a['used']; });
  $c['tokens'] = array_slice($c['tokens'], 0, MAX_TOKENS);
  return $t;
}
function require_owner(&$c) {
  $t = param('token');
  if ($t === '' || !$c || empty($c['tokens'])) fail('로그인이 필요해요.', 401, array('auth' => false));
  $h = hash_tok($t);
  foreach ($c['tokens'] as $i => $row) {
    if (hash_equals($row['h'], $h)) {
      if (time() - $row['used'] > 3600) { $c['tokens'][$i]['used'] = time(); save_conf($c); }
      return true;
    }
  }
  fail('로그인이 만료됐어요. 다시 로그인해 주세요.', 401, array('auth' => false));
}
function check_rate(&$c) {
  $now = time();
  if (!empty($c['lockUntil']) && $c['lockUntil'] > $now) fail('비밀번호를 여러 번 틀렸어요. ' . ceil(($c['lockUntil'] - $now) / 60) . '분 뒤에 다시 시도해 주세요.', 429);
}
function bad_try(&$c) {
  $c['fails'] = (isset($c['fails']) ? $c['fails'] : 0) + 1;
  if ($c['fails'] >= 5) { $c['lockUntil'] = time() + 600; $c['fails'] = 0; }
  save_conf($c);
}
function ua() { return isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''; }

$a = param('a', 'status');
$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
if ($a !== 'status' && $method !== 'POST') fail('POST로 요청해 주세요.', 405);

if ($a === 'status') {
  $c = load_conf(); $m = meta();
  $writable = is_dir(DIR) ? is_writable(DIR) : is_writable(__DIR__);
  out(array('ok' => true, 'app' => APP_ID, 'api' => API_VER, 'setup' => (bool)$c, 'rev' => (int)$m['rev'], 'updatedAt' => $m['updatedAt'],
    'site' => $c ? site_id() : null, 'hasPublic' => file_exists(DIR . '/public.json'), 'writable' => $writable, 'php' => PHP_VERSION,
    'limits' => array('post' => ini_get('post_max_size'), 'upload' => ini_get('upload_max_filesize'))));
}

if ($a === 'setup') {
  ensure_dirs();
  $c = load_conf();
  if ($c) fail('이미 주인 비밀번호가 정해져 있어요.', 409);
  $pw = param('password');
  if (mb_strlen($pw, 'UTF-8') < 6) fail('비밀번호는 6자 이상으로 정해 주세요.');
  $c = array('pw' => password_hash($pw, PASSWORD_DEFAULT), 'tokens' => array(), 'createdAt' => time(), 'fails' => 0);
  $t = issue_token($c, ua());
  save_conf($c);
  out(array('ok' => true, 'token' => $t, 'site' => site_id()));
}

if ($a === 'login') {
  $c = load_conf();
  if (!$c) fail('아직 주인 비밀번호가 없어요.', 409, array('setup' => false));
  check_rate($c);
  if (!password_verify(param('password'), $c['pw'])) { bad_try($c); fail('비밀번호가 맞지 않아요.', 403); }
  $c['fails'] = 0;
  $t = issue_token($c, ua());
  save_conf($c);
  out(array('ok' => true, 'token' => $t, 'site' => site_id()));
}

if ($a === 'hit') {
  /* 방문자 수 (TODAY/TOTAL). count=1 이면 1 올리고, 0이면 읽기만. 한국 시간 기준 */
  ensure_dirs();
  $f = DIR . '/_hits.php';
  $fp = @fopen($f, 'c+');
  if (!$fp) out(array('ok' => true, 'today' => 0, 'total' => 0));
  @flock($fp, LOCK_EX);
  $raw = stream_get_contents($fp);
  if (strpos($raw, GUARD) === 0) $raw = substr($raw, strlen(GUARD));
  $h = json_decode($raw, true); if (!is_array($h)) $h = array('total' => 0, 'days' => array());
  $tz = new DateTimeZone('Asia/Seoul'); $now = new DateTime('now', $tz); $day = $now->format('Y-m-d');
  if (param('count') === '1') {
    $h['total'] = (int)$h['total'] + 1;
    $h['days'][$day] = (isset($h['days'][$day]) ? (int)$h['days'][$day] : 0) + 1;
    if (count($h['days']) > 60) { ksort($h['days']); $h['days'] = array_slice($h['days'], -60, 60, true); }
    ftruncate($fp, 0); rewind($fp); fwrite($fp, GUARD . json_encode($h));
  }
  @flock($fp, LOCK_UN); fclose($fp);
  out(array('ok' => true, 'today' => isset($h['days'][$day]) ? (int)$h['days'][$day] : 0, 'total' => (int)$h['total']));
}

$c = load_conf();
if (!$c) fail('아직 주인 비밀번호가 없어요.', 409, array('setup' => false));
require_owner($c);
ensure_dirs();

if ($a === 'check') out(array('ok' => true, 'rev' => (int)meta()['rev']));

if ($a === 'logout') {
  $h = hash_tok(param('token'));
  $c['tokens'] = array_values(array_filter($c['tokens'], function ($r) use ($h) { return !hash_equals($r['h'], $h); }));
  save_conf($c); out(array('ok' => true));
}
if ($a === 'logout_all') { $c['tokens'] = array(); save_conf($c); out(array('ok' => true)); }
if ($a === 'passwd') {
  check_rate($c);
  if (!password_verify(param('old'), $c['pw'])) { bad_try($c); fail('지금 비밀번호가 맞지 않아요.', 403); }
  $pw = param('password');
  if (mb_strlen($pw, 'UTF-8') < 6) fail('새 비밀번호는 6자 이상으로 정해 주세요.');
  $c['pw'] = password_hash($pw, PASSWORD_DEFAULT); $c['tokens'] = array();
  $t = issue_token($c, ua()); save_conf($c);
  out(array('ok' => true, 'token' => $t));
}

if ($a === 'load_owner') {
  $m = meta(); $s = read_guarded(DIR . '/_state.php');
  out(array('ok' => true, 'rev' => (int)$m['rev'], 'updatedAt' => $m['updatedAt'], 'state' => $s ? json_decode($s) : null));
}

if ($a === 'save') {
  /* 큰 데이터는 조각으로 나눠 보냄: sid, idx, total, chunk / 마지막 조각에서 baseRev 확인 후 반영 */
  $sid = param('sid'); $idx = (int)param('idx'); $total = (int)param('total'); $chunk = param('chunk');
  if (!preg_match('/^[a-z0-9]{8,40}$/', $sid) || $total < 1 || $total > 2000 || $idx < 0 || $idx >= $total) fail('잘못된 저장 요청이에요.');
  $tmp = DIR . '/_up_' . $sid . '.tmp';
  foreach (glob(DIR . '/_up_*.tmp') as $old) { if (filemtime($old) < time() - 3600) @unlink($old); }
  if ($idx === 0) { if (@file_put_contents($tmp, $chunk, LOCK_EX) === false) fail('임시 파일을 쓸 수 없어요.', 500); }
  else {
    if (!file_exists($tmp)) fail('저장 조각이 사라졌어요. 다시 저장해 주세요.', 409);
    if (filesize($tmp) + strlen($chunk) > MAX_UPLOAD) { @unlink($tmp); fail('데이터가 너무 커요.', 413); }
    @file_put_contents($tmp, $chunk, FILE_APPEND | LOCK_EX);
  }
  if ($idx < $total - 1) out(array('ok' => true, 'part' => $idx));
  $raw = @file_get_contents($tmp); @unlink($tmp);
  $payload = json_decode($raw, true);
  if (!is_array($payload) || !isset($payload['full'])) fail('저장 데이터가 깨졌어요. 다시 저장해 주세요.');
  $m = meta();
  $base = (int)param('baseRev', '-1');
  if (param('force') !== '1' && $base !== (int)$m['rev']) fail('다른 기기에서 먼저 바뀌었어요.', 409, array('conflict' => true, 'rev' => (int)$m['rev'], 'updatedAt' => $m['updatedAt']));
  $full = json_encode($payload['full'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  $pub = isset($payload['public']) ? json_encode($payload['public'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : 'null';
  if (file_exists(DIR . '/_state.php')) @copy(DIR . '/_state.php', DIR . '/_state_prev.php');
  if (!write_atomic(DIR . '/_state.php', GUARD . $full)) fail('저장하지 못했어요. 호스팅 용량이나 권한을 확인해 주세요.', 507);
  write_atomic(DIR . '/public.json', $pub);
  $m['rev'] = (int)$m['rev'] + 1; $m['updatedAt'] = gmdate('c'); if (empty($m['site'])) $m['site'] = rnd(6);
  save_meta($m);
  out(array('ok' => true, 'rev' => $m['rev'], 'updatedAt' => $m['updatedAt'], 'bytes' => strlen($full) + strlen($pub)));
}

if ($a === 'upload') {
  $name = param('name');
  if (!preg_match('/^[a-z0-9]{8,64}$/', $name)) fail('잘못된 파일 이름이에요.');
  if (empty($_FILES['file']) || !is_uploaded_file($_FILES['file']['tmp_name'])) fail('사진이 전달되지 않았어요. (호스팅 업로드 한도: ' . ini_get('upload_max_filesize') . ')', 400);
  $f = $_FILES['file'];
  if ($f['size'] > MAX_IMG) fail('사진이 너무 커요.', 413);
  $info = @getimagesize($f['tmp_name']);
  $map = array('image/jpeg' => 'jpg', 'image/png' => 'png', 'image/webp' => 'webp', 'image/gif' => 'gif');
  if (!$info || !isset($map[$info['mime']])) fail('사진 파일만 올릴 수 있어요.', 415);
  $ext = $map[$info['mime']];
  $dest = IMG . '/' . $name . '.' . $ext;
  if (!file_exists($dest) && !@move_uploaded_file($f['tmp_name'], $dest)) fail('사진을 저장하지 못했어요. 호스팅 용량을 확인해 주세요.', 507);
  @chmod($dest, 0644);
  out(array('ok' => true, 'url' => 'data/img/' . $name . '.' . $ext, 'size' => filesize($dest)));
}

if ($a === 'usage') {
  $n = 0; $bytes = 0;
  foreach (glob(IMG . '/*.{jpg,png,webp,gif}', GLOB_BRACE) as $f) { $n++; $bytes += filesize($f); }
  $st = file_exists(DIR . '/_state.php') ? filesize(DIR . '/_state.php') : 0;
  $pub = file_exists(DIR . '/public.json') ? filesize(DIR . '/public.json') : 0;
  out(array('ok' => true, 'images' => $n, 'imageBytes' => $bytes, 'stateBytes' => $st, 'publicBytes' => $pub, 'devices' => count($c['tokens'])));
}

fail('알 수 없는 요청이에요.', 404);
