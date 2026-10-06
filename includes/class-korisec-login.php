<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Local login / brute-force hardening (not cloud scanning).
 *
 * Defaults on for every install. Stores only short-lived attempt counters
 * keyed by IP hash in WordPress transients — nothing is sent to Korisec.
 */
class Korisec_Login {
    const OPTION = 'korisec_login_protection';
    const TRANSIENT_PREFIX = 'korisec_login_';

    public static function init() {
        add_filter('authenticate', array(__CLASS__, 'block_if_locked'), 30, 3);
        add_action('wp_login_failed', array(__CLASS__, 'record_failure'));
        add_action('wp_login', array(__CLASS__, 'clear_failures'), 10, 2);
        add_filter('shake_error_codes', array(__CLASS__, 'shake_error_codes'));
    }

    /**
     * @return array{enabled:bool,max_attempts:int,lockout_minutes:int}
     */
    public static function settings() {
        $defaults = array(
            'enabled' => true,
            'max_attempts' => 5,
            'lockout_minutes' => 15,
        );
        $stored = get_option(self::OPTION, array());
        if (!is_array($stored)) {
            $stored = array();
        }
        $out = array_merge($defaults, $stored);
        $out['enabled'] = !empty($out['enabled']);
        $out['max_attempts'] = max(3, min(20, (int) $out['max_attempts']));
        $out['lockout_minutes'] = max(5, min(1440, (int) $out['lockout_minutes']));
        return $out;
    }

    /**
     * @param array $input Raw settings.
     * @return array{enabled:bool,max_attempts:int,lockout_minutes:int}
     */
    public static function save_settings($input) {
        if (!is_array($input)) {
            $input = array();
        }
        $settings = array(
            'enabled' => !empty($input['enabled']),
            'max_attempts' => isset($input['max_attempts']) ? (int) $input['max_attempts'] : 5,
            'lockout_minutes' => isset($input['lockout_minutes']) ? (int) $input['lockout_minutes'] : 15,
        );
        $settings['max_attempts'] = max(3, min(20, $settings['max_attempts']));
        $settings['lockout_minutes'] = max(5, min(1440, $settings['lockout_minutes']));
        update_option(self::OPTION, $settings, false);
        return $settings;
    }

    /**
     * @return string
     */
    private static function client_ip() {
        $ip = '';
        if (!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        }
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return 'unknown';
        }
        return $ip;
    }

    /**
     * @param string $ip Client IP.
     * @return string
     */
    private static function transient_key($ip) {
        return self::TRANSIENT_PREFIX . md5($ip . '|' . wp_salt('auth'));
    }

    /**
     * @param string $ip Client IP.
     * @return array{count:int,locked_until:int}
     */
    private static function state_for($ip) {
        $raw = get_transient(self::transient_key($ip));
        if (!is_array($raw)) {
            return array('count' => 0, 'locked_until' => 0);
        }
        return array(
            'count' => isset($raw['count']) ? (int) $raw['count'] : 0,
            'locked_until' => isset($raw['locked_until']) ? (int) $raw['locked_until'] : 0,
        );
    }

    /**
     * @param string $ip Client IP.
     * @param array  $state Attempt state.
     * @param int    $ttl Seconds.
     */
    private static function store_state($ip, $state, $ttl) {
        set_transient(self::transient_key($ip), $state, max(60, (int) $ttl));
    }

    /**
     * @param string $ip Client IP.
     */
    private static function delete_state($ip) {
        delete_transient(self::transient_key($ip));
    }

    /**
     * @param WP_User|WP_Error|null $user     Auth result so far.
     * @param string                $username Attempted username.
     * @param string                $password Attempted password.
     * @return WP_User|WP_Error|null
     */
    public static function block_if_locked($user, $username, $password) {
        $settings = self::settings();
        if (!$settings['enabled']) {
            return $user;
        }
        if ($username === '' && $password === '') {
            return $user;
        }

        $ip = self::client_ip();
        $state = self::state_for($ip);
        $now = time();
        if ($state['locked_until'] > $now) {
            $mins = (int) ceil(($state['locked_until'] - $now) / 60);
            return new WP_Error(
                'korisec_login_locked',
                sprintf(
                    /* translators: %d: minutes remaining */
                    __('Too many failed login attempts. Try again in %d minute(s).', 'korisec'),
                    max(1, $mins)
                )
            );
        }
        return $user;
    }

    /**
     * @param string $username Attempted username.
     */
    public static function record_failure($username) {
        unset($username);
        $settings = self::settings();
        if (!$settings['enabled']) {
            return;
        }
        $ip = self::client_ip();
        $state = self::state_for($ip);
        $now = time();
        if ($state['locked_until'] > $now) {
            return;
        }
        $state['count'] = $state['count'] + 1;
        $lockout_seconds = $settings['lockout_minutes'] * MINUTE_IN_SECONDS;
        if ($state['count'] >= $settings['max_attempts']) {
            $state['locked_until'] = $now + $lockout_seconds;
            $state['count'] = 0;
            self::store_state($ip, $state, $lockout_seconds);
            return;
        }
        self::store_state($ip, $state, $lockout_seconds);
    }

    /**
     * @param string  $user_login Username.
     * @param WP_User $user       User object.
     */
    public static function clear_failures($user_login, $user) {
        unset($user_login, $user);
        self::delete_state(self::client_ip());
    }

    /**
     * @param string[] $codes Shake error codes.
     * @return string[]
     */
    public static function shake_error_codes($codes) {
        $codes[] = 'korisec_login_locked';
        return $codes;
    }
}
