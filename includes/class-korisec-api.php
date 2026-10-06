<?php

if (!defined('ABSPATH')) {
    exit;
}

class Korisec_API {
    const OPTION_KEY = 'korisec_license_key';
    const OPTION_STATE = 'korisec_state';
    const OPTION_PIN = 'korisec_pin_origin';
    const ORIGIN_HINT_HOST = 'mail.korisec.com';
    const ORIGIN_FALLBACK_IP = '15.235.147.167';

    public static function init() {
        add_action('http_api_curl', array(__CLASS__, 'curl_pin_origin'), 10, 3);
    }

    public static function origin_ip() {
        if (defined('KORISEC_ORIGIN_IP') && KORISEC_ORIGIN_IP) {
            return KORISEC_ORIGIN_IP;
        }
        $ip = gethostbyname(self::ORIGIN_HINT_HOST);
        if ($ip && $ip !== self::ORIGIN_HINT_HOST && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $ip;
        }
        return self::ORIGIN_FALLBACK_IP;
    }

    public static function pin_origin_enabled() {
        if (defined('KORISEC_PIN_ORIGIN')) {
            return (bool) KORISEC_PIN_ORIGIN;
        }
        return (string) get_option(self::OPTION_PIN, '1') !== '0';
    }

    public static function enable_pin_origin() {
        if (defined('KORISEC_PIN_ORIGIN') && !KORISEC_PIN_ORIGIN) {
            return false;
        }
        update_option(self::OPTION_PIN, '1', false);
        return true;
    }

    private static function maybe_enable_pin_and_retry($parsed) {
        if (self::pin_origin_enabled()) {
            return false;
        }
        $code = isset($parsed['code']) ? $parsed['code'] : '';
        $status = isset($parsed['status']) ? (int) $parsed['status'] : 0;
        if ($code !== 'cloudflare_blocked' && $status !== 403 && $status !== 0) {
            return false;
        }
        return self::enable_pin_origin();
    }

    /**
     * Pin api.korisec.com to Korisec origin so hosting firewalls / Cloudflare
     * bot challenges do not block wp_remote_* . On by default; no wp-config edit.
     */
    public static function curl_pin_origin($handle, $r = null, $url = '') {
        if (!self::pin_origin_enabled()) {
            return;
        }
        if (defined('KORISEC_API_BASE') && KORISEC_API_BASE) {
            return;
        }
        if (!is_string($url) || strpos($url, 'https://api.korisec.com/') !== 0) {
            return;
        }
        $ip = self::origin_ip();
        if (!$ip) {
            return;
        }
        if (defined('CURLOPT_RESOLVE')) {
            // http_api_curl is the WordPress hook for CURLOPT_* on wp_remote_*.
            // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt -- DNS pin for wp_remote_request, not a raw cURL client.
            curl_setopt($handle, CURLOPT_RESOLVE, array('api.korisec.com:443:' . $ip));
        }
        if (defined('CURLOPT_IPRESOLVE') && defined('CURL_IPRESOLVE_V4')) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt -- same http_api_curl handle as above.
            curl_setopt($handle, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        }
    }

    public static function base_url() {
        if (defined('KORISEC_API_BASE') && KORISEC_API_BASE) {
            return untrailingslashit(KORISEC_API_BASE);
        }
        return 'https://api.korisec.com';
    }

    public static function get_key() {
        return (string) get_option(self::OPTION_KEY, '');
    }

    public static function get_state() {
        $state = get_option(self::OPTION_STATE, array());
        return is_array($state) ? $state : array();
    }

    public static function save_state($state) {
        update_option(self::OPTION_STATE, $state, false);
    }

    public static function site_payload() {
        $host = wp_parse_url(home_url(), PHP_URL_HOST);
        return array(
            'plugin_version' => KORISEC_VERSION,
            'wp_version' => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
            'site_url' => site_url(),
            'home_url' => home_url(),
            'site_host' => $host ? $host : '',
        );
    }

    public static function request($method, $path, $body = null, $timeout = 15) {
        $key = self::get_key();
        $args = array(
            'method' => strtoupper($method),
            'timeout' => $timeout,
            'redirection' => 2,
            'headers' => array(
                'Authorization' => 'Bearer ' . $key,
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'User-Agent' => 'Korisec-WP/' . KORISEC_VERSION,
            ),
        );
        if (null !== $body) {
            $args['body'] = wp_json_encode($body);
        }

        $res = wp_remote_request(self::base_url() . $path, $args);
        $parsed = self::parse($res);
        if (!$parsed['ok'] && self::maybe_enable_pin_and_retry($parsed)) {
            $res = wp_remote_request(self::base_url() . $path, $args);
            $parsed = self::parse($res);
        }
        return $parsed;
    }

    public static function request_binary($path, $timeout = 90) {
        $key = self::get_key();
        $args = array(
            'method' => 'GET',
            'timeout' => $timeout,
            'redirection' => 2,
            'headers' => array(
                'Authorization' => 'Bearer ' . $key,
                'Accept' => 'application/pdf, application/json',
                'User-Agent' => 'Korisec-WP/' . KORISEC_VERSION,
            ),
        );
        $res = wp_remote_get(self::base_url() . $path, $args);
        $parsed_try = is_wp_error($res) ? array('ok' => false, 'status' => 0, 'code' => 'network') : self::parse($res);
        if (is_wp_error($res) || (isset($parsed_try['ok']) && !$parsed_try['ok'])) {
            if (self::maybe_enable_pin_and_retry($parsed_try)) {
                $res = wp_remote_get(self::base_url() . $path, $args);
            }
        }
        if (is_wp_error($res)) {
            return array(
                'ok' => false,
                'status' => 0,
                'message' => $res->get_error_message(),
                'body' => '',
                'filename' => 'report.pdf',
                'content_type' => '',
            );
        }
        $status = (int) wp_remote_retrieve_response_code($res);
        $body = (string) wp_remote_retrieve_body($res);
        $type = (string) wp_remote_retrieve_header($res, 'content-type');
        $disp = (string) wp_remote_retrieve_header($res, 'content-disposition');
        $filename = 'korisec-report.pdf';
        if (preg_match('/filename="?([^";]+)"?/i', $disp, $m)) {
            $filename = basename($m[1]);
        }
        if ($status < 200 || $status >= 300 || (stripos($type, 'pdf') === false && substr($body, 0, 4) !== '%PDF')) {
            $parsed = self::parse($res);
            return array(
                'ok' => false,
                'status' => $status,
                'code' => $parsed['code'],
                'message' => Korisec_API::human_error($parsed),
                'body' => '',
                'filename' => $filename,
                'content_type' => $type,
            );
        }
        return array(
            'ok' => true,
            'status' => $status,
            'message' => '',
            'body' => $body,
            'filename' => $filename,
            'content_type' => $type,
        );
    }

    public static function parse($res) {
        if (is_wp_error($res)) {
            return array(
                'ok' => false,
                'status' => 0,
                'code' => 'network',
                'message' => $res->get_error_message(),
                'data' => null,
            );
        }

        $status = (int) wp_remote_retrieve_response_code($res);
        $raw = wp_remote_retrieve_body($res);
        $cf_mitigated = (string) wp_remote_retrieve_header($res, 'cf-mitigated');
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            $data = array();
        }

        $code = '';
        $message = '';
        $detail = isset($data['detail']) ? $data['detail'] : null;
        if (is_array($detail) && isset($detail['code'])) {
            $code = (string) $detail['code'];
            $message = isset($detail['message']) ? (string) $detail['message'] : '';
        } elseif (is_array($detail) && isset($detail[0]['msg'])) {
            $message = (string) $detail[0]['msg'];
        } elseif (is_string($detail) && $detail !== '') {
            $message = $detail;
        }

        $looks_like_cf = ($cf_mitigated !== '')
            || (strpos($raw, 'cdn-cgi/challenge-platform') !== false)
            || (stripos($raw, 'Just a moment') !== false);

        if ($looks_like_cf && $status === 403) {
            $code = 'cloudflare_blocked';
            $message = __('Korisec could not reach this WordPress site. Wait a moment and click Connect again.', 'korisec');
        }

        if (!$message) {
            if ($status === 401 && $code === 'revoked') {
                $message = __('This key was revoked in Korisec. Create a new key and paste it here.', 'korisec');
            } elseif ($status === 402) {
                $code = $code ? $code : 'plan_lapsed';
                $message = __('Your Korisec service plan ended. Cloud checks are paused until the account is renewed.', 'korisec');
            } elseif ($status === 403 && $code === 'host_mismatch') {
                $message = isset($detail['message']) ? $detail['message'] : __('This key is bound to another website.', 'korisec');
            } elseif ($status < 200 || $status >= 300) {
                $message = $status
                    ? sprintf(
                        /* translators: %d: HTTP status code */
                        __('Korisec could not complete this request (HTTP %d).', 'korisec'),
                        $status
                    )
                    : __('Korisec could not complete this request.', 'korisec');
            }
        }

        return array(
            'ok' => $status >= 200 && $status < 300,
            'status' => $status,
            'code' => $code,
            'message' => $message,
            'data' => $data,
        );
    }

    public static function human_error($result) {
        if (!empty($result['message'])) {
            return $result['message'];
        }
        return __('Korisec could not complete this request.', 'korisec');
    }

    public static function apply_auth_failure($result) {
        $code = isset($result['code']) ? $result['code'] : '';
        $status = isset($result['status']) ? (int) $result['status'] : 0;
        if ($status === 401 && ($code === 'revoked' || $code === 'invalid_key')) {
            $state = self::get_state();
            $state['connected'] = false;
            $state['last_error'] = self::human_error($result);
            $state['last_error_code'] = $code;
            self::save_state($state);
        }
        if ($status === 402) {
            $state = self::get_state();
            $state['plan_lapsed'] = true;
            $state['last_error'] = self::human_error($result);
            $state['last_error_code'] = 'plan_lapsed';
            self::save_state($state);
        }
        return $result;
    }
}
