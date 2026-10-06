<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Google Drive storage (drive.file scope: Korisec can only see files it created).
 *
 * OAuth goes through the stateless Korisec relay because a public plugin cannot
 * hold a Google client secret. Backup bytes go directly from this site to Google.
 */
class Korisec_GDrive implements Korisec_Storage_Provider {
    const OPTION = 'korisec_gdrive';
    const PENDING_PREFIX = 'korisec_gd_pending_';
    const TOKEN_TRANSIENT = 'korisec_gd_access';
    const CHUNK = 8388608;
    const API = 'https://www.googleapis.com/drive/v3';
    const UPLOAD_API = 'https://www.googleapis.com/upload/drive/v3';
    const FOLDER_MIME = 'application/vnd.google-apps.folder';

    public function id() {
        return 'gdrive';
    }

    public static function relay_base() {
        return untrailingslashit(Korisec_API::base_url()) . '/api/v1/plugin/gdrive';
    }

    private static function state() {
        $s = get_option(self::OPTION, array());
        return is_array($s) ? $s : array();
    }

    public function is_connected() {
        $s = self::state();
        return !empty($s['refresh']);
    }

    public static function account_email() {
        $s = self::state();
        return isset($s['email']) ? (string) $s['email'] : '';
    }

    public static function folder_label() {
        return 'Korisec Backups/' . Korisec_Backup_Store::site_host();
    }

    /* ------------------------------ connect ----------------------------- */

    public static function return_url() {
        return admin_url('admin.php?page=korisec&korisec_tab=backups');
    }

    /** Build the relay URL and remember the one-time key pair for this user. */
    public static function connect_url() {
        $kp = sodium_crypto_box_keypair();
        $pk = sodium_crypto_box_publickey($kp);
        $sk = sodium_crypto_box_secretkey($kp);
        $nonce = Korisec_Backup_Crypto::b64u(random_bytes(18));
        set_transient(
            self::PENDING_PREFIX . get_current_user_id(),
            array(
                'n' => $nonce,
                'sk' => Korisec_Backup_Crypto::seal_local($sk),
                'pk' => base64_encode($pk),
            ),
            20 * MINUTE_IN_SECONDS
        );
        return add_query_arg(
            array(
                'r' => rawurlencode(self::return_url()),
                'pk' => Korisec_Backup_Crypto::b64u($pk),
                'n' => $nonce,
            ),
            self::relay_base() . '/start'
        );
    }

    /**
     * Handle the redirect back from the relay. Returns true, WP_Error, or null if
     * the request is not an OAuth return.
     */
    public static function handle_return() {
        // phpcs:disable WordPress.Security.NonceVerification.Recommended -- the one-time nonce below plays the CSRF role; it is bound to the current user via the transient.
        if (!isset($_GET['korisec_gd_n'])) {
            return null;
        }
        $n = sanitize_text_field(wp_unslash($_GET['korisec_gd_n']));
        $sealed = isset($_GET['korisec_gd']) ? sanitize_text_field(wp_unslash($_GET['korisec_gd'])) : '';
        $error = isset($_GET['korisec_gd_error']) ? sanitize_key(wp_unslash($_GET['korisec_gd_error'])) : '';
        // phpcs:enable
        $key = self::PENDING_PREFIX . get_current_user_id();
        $pending = get_transient($key);
        delete_transient($key);
        if (!is_array($pending) || empty($pending['n']) || !hash_equals($pending['n'], $n)) {
            return new WP_Error('gd_state', __('Google Drive connection link expired or was started in another browser. Please connect again.', 'korisec'));
        }
        if ($error !== '') {
            $msg = $error === 'access_denied'
                ? __('Google Drive access was not granted.', 'korisec')
                : ($error === 'scope_missing'
                    ? __('Please tick the Google Drive permission on the Google consent screen and try again.', 'korisec')
                    : __('Google Drive connection failed. Please try again.', 'korisec'));
            return new WP_Error('gd_denied', $msg);
        }
        $sk = Korisec_Backup_Crypto::open_local($pending['sk']);
        $pk = base64_decode($pending['pk']);
        $data = $sk ? Korisec_Backup_Crypto::open_relay_seal($sealed, $sk, $pk) : false;
        if (!$data || empty($data['refresh_token'])) {
            return new WP_Error('gd_seal', __('Could not read the Google Drive authorization. Please connect again.', 'korisec'));
        }
        update_option(
            self::OPTION,
            array(
                'refresh' => Korisec_Backup_Crypto::seal_local($data['refresh_token']),
                'email' => isset($data['email']) ? sanitize_email($data['email']) : '',
                'connected_at' => time(),
                'folder_id' => '',
            ),
            false
        );
        if (!empty($data['access_token']) && !empty($data['expires_in'])) {
            self::cache_access_token($data['access_token'], (int) $data['expires_in']);
        }
        Korisec_Backup_Store::log('DRIVE_CONNECTED', '', isset($data['email']) ? 'Google Drive connected (' . sanitize_email($data['email']) . ')' : 'Google Drive connected');
        return true;
    }

    public static function disconnect() {
        $s = self::state();
        if (!empty($s['refresh'])) {
            $refresh = Korisec_Backup_Crypto::open_local($s['refresh']);
            if ($refresh) {
                wp_remote_post('https://oauth2.googleapis.com/revoke', array('timeout' => 10, 'body' => array('token' => $refresh)));
            }
        }
        delete_option(self::OPTION);
        delete_transient(self::TOKEN_TRANSIENT);
        Korisec_Backup_Store::log('DRIVE_DISCONNECTED');
    }

    /* ------------------------------ tokens ------------------------------ */

    private static function cache_access_token($token, $expires_in) {
        set_transient(self::TOKEN_TRANSIENT, Korisec_Backup_Crypto::seal_local($token), max(60, $expires_in - 120));
    }

    /** @return string|WP_Error */
    private function access_token($force = false) {
        if (!$force) {
            $cached = get_transient(self::TOKEN_TRANSIENT);
            if ($cached) {
                $tok = Korisec_Backup_Crypto::open_local($cached);
                if ($tok) {
                    return $tok;
                }
            }
        }
        $s = self::state();
        $refresh = !empty($s['refresh']) ? Korisec_Backup_Crypto::open_local($s['refresh']) : false;
        if (!$refresh) {
            return new WP_Error('gd_not_connected', __('Google Drive is not connected.', 'korisec'));
        }
        $res = wp_remote_post(
            self::relay_base() . '/refresh',
            array(
                'timeout' => 20,
                'headers' => array('Content-Type' => 'application/json', 'Accept' => 'application/json', 'User-Agent' => 'Korisec-WP/' . KORISEC_VERSION),
                'body' => wp_json_encode(array('refresh_token' => $refresh)),
            )
        );
        if (is_wp_error($res)) {
            return new WP_Error('gd_transient', __('Could not reach the Korisec Drive relay to refresh access.', 'korisec'));
        }
        $code = (int) wp_remote_retrieve_response_code($res);
        $body = json_decode(wp_remote_retrieve_body($res), true);
        if ($code === 401) {
            return new WP_Error('gd_reauth', __('Google Drive access was revoked or expired. Reconnect Google Drive in Korisec → Backups.', 'korisec'));
        }
        if ($code !== 200 || empty($body['access_token'])) {
            return new WP_Error('gd_transient', __('Google Drive token refresh failed. Will retry.', 'korisec'));
        }
        self::cache_access_token($body['access_token'], isset($body['expires_in']) ? (int) $body['expires_in'] : 3600);
        return $body['access_token'];
    }

    /**
     * Authenticated request with one forced token refresh on 401.
     *
     * @return array|WP_Error wp_remote_request response.
     */
    private function request($method, $url, array $args = array()) {
        for ($attempt = 0; $attempt < 2; $attempt++) {
            $token = $this->access_token($attempt > 0);
            if (is_wp_error($token)) {
                return $token;
            }
            $args['method'] = $method;
            $args['timeout'] = isset($args['timeout']) ? $args['timeout'] : 60;
            $args['headers'] = array_merge(isset($args['headers']) ? $args['headers'] : array(), array('Authorization' => 'Bearer ' . $token));
            $res = wp_remote_request($url, $args);
            if (is_wp_error($res)) {
                return new WP_Error('gd_transient', __('Network error talking to Google Drive.', 'korisec'));
            }
            if ((int) wp_remote_retrieve_response_code($res) !== 401) {
                return $res;
            }
        }
        return new WP_Error('gd_reauth', __('Google Drive rejected the access token. Reconnect Google Drive.', 'korisec'));
    }

    private static function api_error($res, $what) {
        $code = (int) wp_remote_retrieve_response_code($res);
        $body = json_decode(wp_remote_retrieve_body($res), true);
        $reason = isset($body['error']['errors'][0]['reason']) ? $body['error']['errors'][0]['reason'] : '';
        if ($reason === 'storageQuotaExceeded') {
            return new WP_Error('gd_quota', __('Your Google Drive is full. Free up space or lower the number of backups kept.', 'korisec'));
        }
        $transient = $code === 429 || $code >= 500 || in_array($reason, array('rateLimitExceeded', 'userRateLimitExceeded', 'backendError'), true);
        /* translators: 1: operation, 2: HTTP status */
        return new WP_Error($transient ? 'gd_transient' : 'gd_error', sprintf(__('Google Drive %1$s failed (HTTP %2$d).', 'korisec'), $what, $code));
    }

    /* ------------------------------ folders ----------------------------- */

    /** @return string|WP_Error Folder id for this site's backups. */
    public function ensure_folder() {
        $s = self::state();
        if (!empty($s['folder_id'])) {
            $meta = $this->request('GET', self::API . '/files/' . rawurlencode($s['folder_id']) . '?fields=id,trashed');
            if (!is_wp_error($meta) && (int) wp_remote_retrieve_response_code($meta) === 200) {
                $m = json_decode(wp_remote_retrieve_body($meta), true);
                if (empty($m['trashed'])) {
                    return $s['folder_id'];
                }
            } elseif (is_wp_error($meta)) {
                return $meta;
            }
        }
        $root = $this->find_or_create_folder('Korisec Backups', 'root', array('korisec_kind' => 'root'));
        if (is_wp_error($root)) {
            return $root;
        }
        $site = $this->find_or_create_folder(Korisec_Backup_Store::site_host(), $root, array('korisec_kind' => 'site', 'korisec_host' => Korisec_Backup_Store::site_host()));
        if (is_wp_error($site)) {
            return $site;
        }
        $s = self::state();
        $s['folder_id'] = $site;
        update_option(self::OPTION, $s, false);
        return $site;
    }

    private function find_or_create_folder($name, $parent, array $props) {
        $q = sprintf(
            "mimeType = '%s' and trashed = false and '%s' in parents and name = '%s'",
            self::FOLDER_MIME,
            str_replace("'", "\\'", $parent),
            str_replace(array('\\', "'"), array('\\\\', "\\'"), $name)
        );
        $res = $this->request('GET', self::API . '/files?' . http_build_query(array('q' => $q, 'fields' => 'files(id)', 'pageSize' => 1, 'spaces' => 'drive')));
        if (is_wp_error($res)) {
            return $res;
        }
        if ((int) wp_remote_retrieve_response_code($res) === 200) {
            $body = json_decode(wp_remote_retrieve_body($res), true);
            if (!empty($body['files'][0]['id'])) {
                return $body['files'][0]['id'];
            }
        }
        $res = $this->request(
            'POST',
            self::API . '/files?fields=id',
            array(
                'headers' => array('Content-Type' => 'application/json'),
                'body' => wp_json_encode(array('name' => $name, 'mimeType' => self::FOLDER_MIME, 'parents' => array($parent), 'appProperties' => $props)),
            )
        );
        if (is_wp_error($res)) {
            return $res;
        }
        if ((int) wp_remote_retrieve_response_code($res) !== 200) {
            return self::api_error($res, 'folder create');
        }
        $body = json_decode(wp_remote_retrieve_body($res), true);
        return !empty($body['id']) ? $body['id'] : new WP_Error('gd_error', __('Google Drive did not return a folder id.', 'korisec'));
    }

    /* ------------------------------ upload ------------------------------ */

    public function upload_step($local_path, $remote_name, array $app_properties, array $session, $deadline) {
        $size = filesize($local_path);
        if ($size === false) {
            return new WP_Error('backup_read', __('Backup file to upload is missing.', 'korisec'));
        }
        if (empty($session['uri'])) {
            $folder = $this->ensure_folder();
            if (is_wp_error($folder)) {
                return $folder;
            }
            $res = $this->request(
                'POST',
                self::UPLOAD_API . '/files?uploadType=resumable&fields=id,size,md5Checksum',
                array(
                    'headers' => array(
                        'Content-Type' => 'application/json; charset=UTF-8',
                        'X-Upload-Content-Type' => 'application/octet-stream',
                        'X-Upload-Content-Length' => (string) $size,
                    ),
                    'body' => wp_json_encode(
                        array(
                            'name' => $remote_name,
                            'parents' => array($folder),
                            'mimeType' => 'application/octet-stream',
                            'appProperties' => $app_properties,
                        )
                    ),
                )
            );
            if (is_wp_error($res)) {
                return $res;
            }
            $uri = wp_remote_retrieve_header($res, 'location');
            if ((int) wp_remote_retrieve_response_code($res) !== 200 || !$uri) {
                return self::api_error($res, 'upload start');
            }
            $session = array('uri' => $uri, 'offset' => 0, 'size' => $size, 'done' => false);
        }

        $fh = fopen($local_path, 'rb');
        if (!$fh) {
            return new WP_Error('backup_read', __('Could not read the backup file for upload.', 'korisec'));
        }
        while (!$session['done'] && microtime(true) < $deadline) {
            $offset = (int) $session['offset'];
            fseek($fh, $offset);
            $chunk = $size > 0 ? fread($fh, self::CHUNK) : '';
            $len = strlen($chunk);
            $headers = array('Content-Length' => (string) $len);
            if ($size > 0) {
                $headers['Content-Range'] = 'bytes ' . $offset . '-' . ($offset + $len - 1) . '/' . $size;
            }
            $token = $this->access_token();
            if (is_wp_error($token)) {
                fclose($fh);
                return $token;
            }
            $headers['Authorization'] = 'Bearer ' . $token;
            $res = wp_remote_request($session['uri'], array('method' => 'PUT', 'timeout' => 120, 'headers' => $headers, 'body' => $chunk));
            if (is_wp_error($res)) {
                fclose($fh);
                return new WP_Error('gd_transient', __('Network error during Google Drive upload. Will resume.', 'korisec'));
            }
            $code = (int) wp_remote_retrieve_response_code($res);
            if ($code === 308) {
                $range = wp_remote_retrieve_header($res, 'range');
                $session['offset'] = preg_match('/bytes=0-(\d+)/', (string) $range, $m) ? ((int) $m[1] + 1) : 0;
                continue;
            }
            if ($code === 200 || $code === 201) {
                $body = json_decode(wp_remote_retrieve_body($res), true);
                $session['done'] = true;
                $session['remote_id'] = isset($body['id']) ? $body['id'] : '';
                $session['size'] = isset($body['size']) ? (int) $body['size'] : -1;
                $session['md5'] = isset($body['md5Checksum']) ? $body['md5Checksum'] : '';
                break;
            }
            fclose($fh);
            if ($code === 404 || $code === 410) {
                return new WP_Error('gd_session_expired', __('Google Drive upload session expired. Restarting upload.', 'korisec'));
            }
            return self::api_error($res, 'upload');
        }
        fclose($fh);
        return $session;
    }

    /* ----------------------------- download ----------------------------- */

    public function download_step($remote_id, $destination, array $session, $deadline) {
        if (empty($session)) {
            $meta = $this->get_metadata($remote_id);
            if (is_wp_error($meta)) {
                return $meta;
            }
            file_put_contents($destination, '');
            $session = array('offset' => 0, 'size' => (int) $meta['size'], 'md5' => $meta['md5'], 'done' => $meta['size'] === 0);
        }
        while (!$session['done'] && microtime(true) < $deadline) {
            $start = (int) $session['offset'];
            $end = min($session['size'], $start + self::CHUNK) - 1;
            $tmp = $destination . '.part';
            $res = $this->request(
                'GET',
                self::API . '/files/' . rawurlencode($remote_id) . '?alt=media',
                array('timeout' => 120, 'headers' => array('Range' => 'bytes=' . $start . '-' . $end), 'stream' => true, 'filename' => $tmp)
            );
            if (is_wp_error($res)) {
                return $res;
            }
            $code = (int) wp_remote_retrieve_response_code($res);
            if ($code !== 206 && $code !== 200) {
                wp_delete_file($tmp);
                return self::api_error($res, 'download');
            }
            $got = (int) filesize($tmp);
            if ($code === 200 && $start > 0) {
                wp_delete_file($tmp);
                return new WP_Error('gd_error', __('Google Drive ignored the byte range request.', 'korisec'));
            }
            $in = fopen($tmp, 'rb');
            $out = fopen($destination, 'ab');
            stream_copy_to_stream($in, $out);
            fclose($in);
            fclose($out);
            wp_delete_file($tmp);
            $session['offset'] = $start + $got;
            if ($got <= 0) {
                return new WP_Error('gd_transient', __('Empty response from Google Drive. Will retry.', 'korisec'));
            }
            if ($session['offset'] >= $session['size'] || $code === 200) {
                $session['done'] = true;
            }
        }
        return $session;
    }

    /* ------------------------------- misc ------------------------------- */

    public function delete($remote_id) {
        if ($remote_id === '') {
            return true;
        }
        $res = $this->request('DELETE', self::API . '/files/' . rawurlencode($remote_id));
        if (is_wp_error($res)) {
            return $res;
        }
        $code = (int) wp_remote_retrieve_response_code($res);
        if ($code === 204 || $code === 200 || $code === 404) {
            return true;
        }
        return self::api_error($res, 'delete');
    }

    public function get_metadata($remote_id) {
        $res = $this->request('GET', self::API . '/files/' . rawurlencode($remote_id) . '?fields=id,name,size,md5Checksum,trashed,appProperties');
        if (is_wp_error($res)) {
            return $res;
        }
        $code = (int) wp_remote_retrieve_response_code($res);
        if ($code === 404) {
            return new WP_Error('gd_missing', __('The backup file is no longer in Google Drive.', 'korisec'));
        }
        if ($code !== 200) {
            return self::api_error($res, 'metadata');
        }
        $b = json_decode(wp_remote_retrieve_body($res), true);
        return array(
            'id' => isset($b['id']) ? $b['id'] : '',
            'name' => isset($b['name']) ? $b['name'] : '',
            'size' => isset($b['size']) ? (int) $b['size'] : 0,
            'md5' => isset($b['md5Checksum']) ? $b['md5Checksum'] : '',
            'trashed' => !empty($b['trashed']),
            'app_properties' => isset($b['appProperties']) && is_array($b['appProperties']) ? $b['appProperties'] : array(),
        );
    }

    /**
     * Find Korisec manifests in Drive (for disaster recovery on a fresh install).
     *
     * @return array|WP_Error
     */
    public function list_manifests() {
        $q = "appProperties has { key='korisec_part' and value='manifest' } and trashed = false";
        $out = array();
        $page = '';
        for ($i = 0; $i < 10; $i++) {
            $args = array('q' => $q, 'fields' => 'nextPageToken,files(id,name,size,createdTime,appProperties)', 'pageSize' => 100, 'orderBy' => 'createdTime desc', 'spaces' => 'drive');
            if ($page !== '') {
                $args['pageToken'] = $page;
            }
            $res = $this->request('GET', self::API . '/files?' . http_build_query($args));
            if (is_wp_error($res)) {
                return $res;
            }
            if ((int) wp_remote_retrieve_response_code($res) !== 200) {
                return self::api_error($res, 'list');
            }
            $body = json_decode(wp_remote_retrieve_body($res), true);
            foreach (isset($body['files']) ? $body['files'] : array() as $f) {
                $out[] = $f;
            }
            $page = isset($body['nextPageToken']) ? $body['nextPageToken'] : '';
            if ($page === '') {
                break;
            }
        }
        return $out;
    }
}
