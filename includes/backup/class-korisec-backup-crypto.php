<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Backup encryption: key ring, recovery keys, and the streamed .kbackup format.
 *
 * .kbackup layout (version 1):
 *   "KSB1" | u8 version | u8 flags | 8-byte key id | 24-byte secretstream header
 *   then records: u32 big-endian length | XChaCha20-Poly1305 secretstream ciphertext
 * Each record's plaintext is an independently raw-deflated block, so a writer can
 * stop between HTTP requests and resume with only the secretstream state. The last
 * record carries TAG_FINAL; a file without it is truncated and rejected.
 */
class Korisec_Backup_Crypto {
    const OPTION_KEYRING = 'korisec_backup_keyring';
    const MAGIC = 'KSB1';
    const FORMAT_VERSION = 1;
    const FLAG_DEFLATE = 1;
    const HEADER_LEN = 38;
    const MAX_RECORD = 67108864;

    public static function available() {
        return function_exists('sodium_crypto_secretstream_xchacha20poly1305_init_push')
            && function_exists('gzdeflate')
            && function_exists('hash_hkdf');
    }

    /** Key used only to protect secrets at rest in wp_options (derived from wp-config salts). */
    private static function wrap_key() {
        $material = (defined('AUTH_KEY') ? AUTH_KEY : '') . '|' . (defined('SECURE_AUTH_KEY') ? SECURE_AUTH_KEY : '') . '|' . (defined('AUTH_SALT') ? AUTH_SALT : '');
        return hash_hkdf('sha256', $material, 32, 'korisec-backup-wrap-v1', 'korisec');
    }

    public static function seal_local($plaintext) {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return base64_encode($nonce . sodium_crypto_secretbox((string) $plaintext, $nonce, self::wrap_key()));
    }

    /** @return string|false */
    public static function open_local($sealed) {
        $raw = base64_decode((string) $sealed, true);
        if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            return false;
        }
        $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $nonce, self::wrap_key());
    }

    public static function key_id($key) {
        return substr(hash('sha256', 'korisec-kid|' . $key, true), 0, 8);
    }

    private static function keyring() {
        $ring = get_option(self::OPTION_KEYRING, array());
        if (!is_array($ring) || !isset($ring['keys']) || !is_array($ring['keys'])) {
            $ring = array('active' => '', 'keys' => array(), 'acknowledged' => false);
        }
        return $ring;
    }

    private static function save_keyring($ring) {
        update_option(self::OPTION_KEYRING, $ring, false);
    }

    public static function has_active_key() {
        $ring = self::keyring();
        return $ring['active'] !== '' && isset($ring['keys'][$ring['active']]);
    }

    /**
     * Ensure an active key exists. Returns true when a new key was generated.
     */
    public static function ensure_key() {
        if (self::has_active_key()) {
            return false;
        }
        $key = random_bytes(32);
        $kid = bin2hex(self::key_id($key));
        $ring = self::keyring();
        $ring['keys'][$kid] = array('wrapped' => self::seal_local($key), 'created' => time());
        $ring['active'] = $kid;
        $ring['acknowledged'] = false;
        self::save_keyring($ring);
        return true;
    }

    /** @return string|WP_Error Raw 32-byte key. */
    public static function key_for($kid_hex = '') {
        $ring = self::keyring();
        if ($kid_hex === '') {
            $kid_hex = $ring['active'];
        }
        if ($kid_hex === '' || !isset($ring['keys'][$kid_hex])) {
            return new WP_Error('backup_key_missing', __('The encryption key for this backup is not on this site. Enter the recovery key that was saved when the backup was made.', 'korisec'));
        }
        $key = self::open_local($ring['keys'][$kid_hex]['wrapped']);
        if ($key === false || strlen($key) !== 32) {
            return new WP_Error('backup_key_locked', __('The backup encryption key could not be unlocked (the WordPress security salts may have changed). Enter your recovery key again.', 'korisec'));
        }
        return $key;
    }

    public static function active_key_id() {
        $ring = self::keyring();
        return $ring['active'];
    }

    public static function recovery_acknowledged() {
        $ring = self::keyring();
        return !empty($ring['acknowledged']);
    }

    public static function acknowledge_recovery() {
        $ring = self::keyring();
        $ring['acknowledged'] = true;
        self::save_keyring($ring);
    }

    /** Human-friendly recovery key: KSK1-xxxxxxxx-…-cccc (64 hex digits + checksum). */
    public static function recovery_key() {
        $key = self::key_for();
        if (is_wp_error($key)) {
            return $key;
        }
        $hex = bin2hex($key);
        $check = substr(hash('sha256', 'korisec-rk|' . $key), 0, 4);
        return 'KSK1-' . implode('-', str_split($hex, 8)) . '-' . $check;
    }

    /**
     * Import a recovery key. Becomes active only if no active key exists or $make_active.
     *
     * @return string|WP_Error Key id hex.
     */
    public static function import_recovery_key($text, $make_active = false) {
        $clean = strtolower(preg_replace('/[^0-9a-zA-Z]/', '', (string) $text));
        if (strpos($clean, 'ksk1') === 0) {
            $clean = substr($clean, 4);
        }
        if (!preg_match('/^[0-9a-f]{68}$/', $clean)) {
            return new WP_Error('bad_recovery_key', __('That does not look like a Korisec recovery key (KSK1-…).', 'korisec'));
        }
        $key = hex2bin(substr($clean, 0, 64));
        if (!hash_equals(substr(hash('sha256', 'korisec-rk|' . $key), 0, 4), substr($clean, 64, 4))) {
            return new WP_Error('bad_recovery_key', __('The recovery key checksum does not match. Check for typos.', 'korisec'));
        }
        $kid = bin2hex(self::key_id($key));
        $ring = self::keyring();
        $ring['keys'][$kid] = array('wrapped' => self::seal_local($key), 'created' => time());
        if ($make_active || $ring['active'] === '' || !isset($ring['keys'][$ring['active']]) || is_wp_error(self::key_for($ring['active']))) {
            $ring['active'] = $kid;
            $ring['acknowledged'] = true;
        }
        self::save_keyring($ring);
        return $kid;
    }

    /**
     * Open a token bundle sealed by the Korisec relay to our one-time X25519 key.
     *
     * @return array|false
     */
    public static function open_relay_seal($sealed_b64u, $site_secret, $public_key) {
        $raw = self::b64u_decode($sealed_b64u);
        if ($raw === false || strlen($raw) < 32 + 12 + 16) {
            return false;
        }
        $eph_pub = substr($raw, 0, 32);
        $nonce = substr($raw, 32, 12);
        $ct = substr($raw, 44);
        $shared = sodium_crypto_scalarmult($site_secret, $eph_pub);
        $key = hash_hkdf('sha256', $shared, 32, 'korisec-gdrive-v1', $eph_pub . $public_key);
        $plain = sodium_crypto_aead_chacha20poly1305_ietf_decrypt($ct, 'korisec-gdrive-v1', $nonce, $key);
        if ($plain === false) {
            return false;
        }
        $data = json_decode($plain, true);
        return is_array($data) ? $data : false;
    }

    public static function b64u($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function b64u_decode($value) {
        $value = strtr((string) $value, '-_', '+/');
        $pad = strlen($value) % 4;
        if ($pad) {
            $value .= str_repeat('=', 4 - $pad);
        }
        return base64_decode($value, true);
    }

    /* ---------------------------------------------------------------------
     * Streamed writer (resumable across requests)
     * ------------------------------------------------------------------- */

    /**
     * Start a new encrypted file. Returns writer state to persist between requests.
     *
     * @return array|WP_Error
     */
    public static function writer_open($path) {
        $key = self::key_for();
        if (is_wp_error($key)) {
            return $key;
        }
        list($state, $header) = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
        $fh = fopen($path, 'wb');
        if (!$fh) {
            return new WP_Error('backup_write', __('Could not create the backup file in the temporary folder.', 'korisec'));
        }
        $prefix = self::MAGIC . chr(self::FORMAT_VERSION) . chr(self::FLAG_DEFLATE) . self::key_id($key) . $header;
        fwrite($fh, $prefix);
        fclose($fh);
        return array(
            'path' => $path,
            'state' => base64_encode($state),
            'kid' => bin2hex(self::key_id($key)),
            'plain_bytes' => 0,
        );
    }

    /** Encrypt one plaintext block (a whole record) and append it. */
    public static function writer_push(array &$writer, $plaintext, $final = false) {
        $state = base64_decode($writer['state']);
        $block = gzdeflate((string) $plaintext, 6);
        $tag = $final ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
        $ct = sodium_crypto_secretstream_xchacha20poly1305_push($state, $block, '', $tag);
        $fh = fopen($writer['path'], 'ab');
        if (!$fh) {
            return new WP_Error('backup_write', __('Could not write to the backup file.', 'korisec'));
        }
        $ok = fwrite($fh, pack('N', strlen($ct)) . $ct);
        fclose($fh);
        if ($ok === false) {
            return new WP_Error('backup_write', __('Could not write to the backup file (disk full?).', 'korisec'));
        }
        $writer['state'] = base64_encode($state);
        $writer['plain_bytes'] += strlen((string) $plaintext);
        return true;
    }

    public static function writer_close(array &$writer) {
        return self::writer_push($writer, '', true);
    }

    /* ---------------------------------------------------------------------
     * Streamed reader (resumable across requests)
     * ------------------------------------------------------------------- */

    /** @return array|WP_Error */
    public static function reader_open($path) {
        $fh = fopen($path, 'rb');
        if (!$fh) {
            return new WP_Error('backup_read', __('Could not open the downloaded backup file.', 'korisec'));
        }
        $head = fread($fh, self::HEADER_LEN);
        fclose($fh);
        if (strlen($head) !== self::HEADER_LEN || substr($head, 0, 4) !== self::MAGIC) {
            return new WP_Error('backup_corrupt', __('This file is not a Korisec backup.', 'korisec'));
        }
        if (ord($head[4]) !== self::FORMAT_VERSION) {
            return new WP_Error('backup_version', __('This backup was made by a newer version of Korisec. Update the plugin and try again.', 'korisec'));
        }
        $kid = bin2hex(substr($head, 6, 8));
        $key = self::key_for($kid);
        if (is_wp_error($key)) {
            return $key;
        }
        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull(substr($head, 14, 24), $key);
        return array(
            'path' => $path,
            'state' => base64_encode($state),
            'offset' => self::HEADER_LEN,
            'deflate' => (ord($head[5]) & self::FLAG_DEFLATE) === self::FLAG_DEFLATE,
            'done' => false,
        );
    }

    /**
     * Read and decrypt the next record. Returns plaintext string, null at the end,
     * or WP_Error when the file is corrupted or truncated.
     */
    public static function reader_next(array &$reader) {
        if (!empty($reader['done'])) {
            return null;
        }
        $fh = fopen($reader['path'], 'rb');
        if (!$fh) {
            return new WP_Error('backup_read', __('Could not read the backup file.', 'korisec'));
        }
        fseek($fh, $reader['offset']);
        $len_raw = fread($fh, 4);
        if ($len_raw === false || strlen($len_raw) !== 4) {
            fclose($fh);
            return new WP_Error('backup_corrupt', __('The backup file is truncated (no end marker).', 'korisec'));
        }
        $len = unpack('N', $len_raw)[1];
        if ($len < 17 || $len > self::MAX_RECORD) {
            fclose($fh);
            return new WP_Error('backup_corrupt', __('The backup file is corrupted.', 'korisec'));
        }
        $ct = '';
        while (strlen($ct) < $len && !feof($fh)) {
            $chunk = fread($fh, $len - strlen($ct));
            if ($chunk === false || $chunk === '') {
                break;
            }
            $ct .= $chunk;
        }
        fclose($fh);
        if (strlen($ct) !== $len) {
            return new WP_Error('backup_corrupt', __('The backup file is truncated.', 'korisec'));
        }
        $state = base64_decode($reader['state']);
        $res = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $ct);
        if ($res === false) {
            return new WP_Error('backup_corrupt', __('The backup failed its integrity check (wrong key or damaged file).', 'korisec'));
        }
        list($block, $tag) = $res;
        $plain = $reader['deflate'] ? gzinflate($block) : $block;
        if ($plain === false) {
            return new WP_Error('backup_corrupt', __('A backup block could not be decompressed.', 'korisec'));
        }
        $reader['state'] = base64_encode($state);
        $reader['offset'] += 4 + $len;
        if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
            $reader['done'] = true;
        }
        return $plain;
    }

    /** Fully decrypt a small file (e.g. a manifest) into memory. */
    public static function decrypt_small_file($path) {
        $reader = self::reader_open($path);
        if (is_wp_error($reader)) {
            return $reader;
        }
        $out = '';
        while (true) {
            $block = self::reader_next($reader);
            if (is_wp_error($block)) {
                return $block;
            }
            if ($block === null) {
                break;
            }
            $out .= $block;
            if (strlen($out) > 8388608) {
                return new WP_Error('backup_corrupt', __('Manifest is unexpectedly large.', 'korisec'));
            }
        }
        if (empty($reader['done'])) {
            return new WP_Error('backup_corrupt', __('The backup file is truncated.', 'korisec'));
        }
        return $out;
    }

    /** Peek at the key id stored in a .kbackup header without decrypting. */
    public static function file_key_id($path) {
        $fh = fopen($path, 'rb');
        if (!$fh) {
            return '';
        }
        $head = fread($fh, self::HEADER_LEN);
        fclose($fh);
        if (strlen($head) !== self::HEADER_LEN || substr($head, 0, 4) !== self::MAGIC) {
            return '';
        }
        return bin2hex(substr($head, 6, 8));
    }
}
