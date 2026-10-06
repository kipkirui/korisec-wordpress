<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Detects when WP-Cron is not running, because scheduled backups (and Korisec's daily
 * heartbeat) depend on it.
 *
 * - On activation (and on demand) a probe task is scheduled for "now" and wp-cron.php is
 *   called over loopback, the same way WordPress triggers it. Seeing the probe run proves
 *   scheduled tasks work.
 * - An hourly ping task records when cron last ran. If it falls behind for long enough the
 *   site is flagged, so cron that breaks later is caught too.
 */
class Korisec_Cron_Health {
    const OPTION = 'korisec_cron_health';
    const OPTION_SEEN = 'korisec_cron_seen';
    const HOOK_PING = 'korisec_cron_ping';
    const HOOK_PROBE = 'korisec_cron_probe';
    const NOTICE_TRANSIENT = 'korisec_cron_activation_notice';
    const LATE = 2 * HOUR_IN_SECONDS;
    /* Admin visits spawn cron themselves, so lateness must persist before it counts. */
    const CONFIRM = 15 * MINUTE_IN_SECONDS;

    public static function init() {
        add_action(self::HOOK_PING, array(__CLASS__, 'mark_seen'));
        add_action(self::HOOK_PROBE, array(__CLASS__, 'mark_seen'));
        add_action('admin_notices', array(__CLASS__, 'admin_notice'));
        if (!wp_next_scheduled(self::HOOK_PING)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'hourly', self::HOOK_PING);
        }
    }

    public static function activate() {
        if (!wp_next_scheduled(self::HOOK_PING)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'hourly', self::HOOK_PING);
        }
        set_transient(self::NOTICE_TRANSIENT, 1, HOUR_IN_SECONDS);
        /* The plugin is only marked active after this hook, and wp-cron.php must load it to run the probe. */
        add_action(
            'activated_plugin',
            function ($plugin) {
                if ($plugin === plugin_basename(KORISEC_PLUGIN_FILE)) {
                    self::run_check();
                }
            }
        );
    }

    public static function deactivate() {
        wp_clear_scheduled_hook(self::HOOK_PING);
        wp_unschedule_hook(self::HOOK_PROBE);
    }

    public static function cron_disabled() {
        return defined('DISABLE_WP_CRON') && DISABLE_WP_CRON;
    }

    /** Runs inside the cron process. Kept to a separate option so it never races the admin side. */
    public static function mark_seen($token = '') {
        $seen = self::seen();
        $seen['at'] = time();
        if (is_string($token) && $token !== '') {
            $seen['probe'] = $token;
        }
        update_option(self::OPTION_SEEN, $seen, false);
    }

    private static function health() {
        $h = get_option(self::OPTION, array());
        return wp_parse_args(is_array($h) ? $h : array(), array(
            'status' => 'unknown',
            'reason' => '',
            'detail' => '',
            'checked' => 0,
            'token' => '',
            'since' => 0,
        ));
    }

    private static function save(array $h) {
        update_option(self::OPTION, $h, false);
    }

    /** Read straight from the database: the cron process writes it, so caches may be stale. */
    private static function seen() {
        global $wpdb;
        $raw = $wpdb->get_var($wpdb->prepare("SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", self::OPTION_SEEN)); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $seen = $raw !== null ? maybe_unserialize($raw) : array();
        return wp_parse_args(is_array($seen) ? $seen : array(), array('at' => 0, 'probe' => ''));
    }

    /** WordPress's cron lock, read past caches the same way wp-cron.php does. */
    private static function cron_lock() {
        global $wpdb;
        if (wp_using_ext_object_cache()) {
            return (float) wp_cache_get('doing_cron', 'transient', true);
        }
        return (float) $wpdb->get_var($wpdb->prepare("SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", '_transient_doing_cron')); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
    }

    /**
     * Schedule a probe for now, trigger wp-cron.php over loopback, and wait briefly for it.
     *
     * @return array status() payload.
     */
    public static function run_check() {
        $token = wp_generate_password(16, false);
        $h = self::health();
        $h['token'] = $token;
        $h['checked'] = time();
        $h['since'] = 0;
        $h['detail'] = '';
        self::save($h);
        wp_schedule_single_event(time() - 1, self::HOOK_PROBE, array($token));

        if (self::cron_disabled() || (defined('ALTERNATE_WP_CRON') && ALTERNATE_WP_CRON)) {
            $h['status'] = 'pending';
            $h['reason'] = self::cron_disabled() ? 'disabled' : 'alternate';
            self::save($h);
            return self::status();
        }

        /*
         * A cron run started by this very request often holds the lock, and wp-cron.php skips
         * requests that do not own it. Give that run a moment (it may pick up the probe), then
         * claim the lock the same way spawn_cron() does so our request is not skipped.
         */
        $deadline = microtime(true) + 3;
        while (microtime(true) < $deadline && self::seen()['probe'] !== $token) {
            $lock = self::cron_lock();
            if (!$lock || $lock + (defined('WP_CRON_LOCK_TIMEOUT') ? WP_CRON_LOCK_TIMEOUT : 60) < microtime(true)) {
                break;
            }
            usleep(500000);
        }
        if (self::seen()['probe'] === $token) {
            $h = self::health();
            $h['status'] = 'ok';
            $h['reason'] = '';
            self::save($h);
            return self::status();
        }
        $doing_wp_cron = sprintf('%.22F', microtime(true));
        set_transient('doing_cron', $doing_wp_cron);

        $res = wp_remote_post(
            add_query_arg('doing_wp_cron', $doing_wp_cron, site_url('wp-cron.php')),
            array(
                'timeout' => 10,
                'blocking' => true,
                'redirection' => 0,
                'sslverify' => apply_filters('https_local_ssl_verify', false), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals -- core filter
            )
        );
        $loopback_error = '';
        if (is_wp_error($res)) {
            $loopback_error = $res->get_error_message();
        } else {
            $code = (int) wp_remote_retrieve_response_code($res);
            if ($code >= 300) {
                /* translators: %d: HTTP status code */
                $loopback_error = sprintf(__('wp-cron.php answered with HTTP %d', 'korisec'), $code);
            }
        }

        /* wp-cron.php may answer before it runs tasks (fastcgi_finish_request), so poll briefly. */
        $ran = false;
        if ($loopback_error === '') {
            for ($i = 0; $i < 12 && !$ran; $i++) {
                $ran = self::seen()['probe'] === $token;
                if (!$ran) {
                    usleep(500000);
                }
            }
        }

        $h = self::health();
        if ($ran) {
            $h['status'] = 'ok';
            $h['reason'] = '';
        } elseif ($loopback_error !== '') {
            $h['status'] = 'broken';
            $h['reason'] = 'loopback';
            $h['detail'] = $loopback_error;
        } else {
            $h['status'] = 'pending';
            $h['reason'] = 'slow';
        }
        self::save($h);
        return self::status();
    }

    /**
     * Current health, re-evaluated against when cron last ran.
     *
     * @return array{status:string, reason:string, message:string, fix:string, disabled:bool, last_run:int, checked:int, cron_url:string}
     */
    public static function status() {
        $h = self::health();
        $seen = self::seen();
        $now = time();
        $before = $h;

        /* Any cron run after the moment the current verdict was reached proves cron works again. */
        $verdict_at = max((int) $h['checked'], (int) $h['since']);
        if ($h['status'] !== 'ok' && $verdict_at && (int) $seen['at'] >= $verdict_at) {
            $h['status'] = 'ok';
            $h['reason'] = '';
            $h['detail'] = '';
            $h['since'] = 0;
        }

        $last = max((int) $seen['at'], $h['status'] === 'ok' ? (int) $h['checked'] : 0);
        $next = wp_next_scheduled(self::HOOK_PING);
        $late = $next && $next < $now - 30 * MINUTE_IN_SECONDS && $now - $last > self::LATE;
        if ($h['status'] === 'pending' && $h['checked'] && $now - (int) $h['checked'] > self::LATE) {
            $late = true;
        }
        if ($late) {
            if (!$h['since']) {
                $h['since'] = $now;
            }
            if ($now - (int) $h['since'] >= self::CONFIRM && $h['status'] !== 'broken') {
                $h['status'] = 'broken';
                $h['reason'] = self::cron_disabled() ? 'disabled' : 'stalled';
            }
        } elseif ($h['since'] && $h['status'] !== 'broken') {
            $h['since'] = 0;
        }

        if ($h !== $before) {
            self::save($h);
        }
        return self::payload($h, $last);
    }

    private static function payload(array $h, $last) {
        $cron_url = site_url('wp-cron.php');
        $message = '';
        $fix = '';
        switch ($h['status']) {
            case 'ok':
                $message = __('WP-Cron is running, so automatic backups will start on schedule.', 'korisec');
                break;
            case 'pending':
                if ($h['reason'] === 'disabled') {
                    $message = __('WP-Cron is turned off in wp-config.php (DISABLE_WP_CRON). Korisec is waiting to see your server’s cron job run scheduled tasks, which should happen within an hour.', 'korisec');
                } else {
                    $message = __('Korisec is still confirming that WP-Cron runs scheduled tasks on this site. This usually resolves within an hour.', 'korisec');
                }
                break;
            case 'broken':
                if ($h['reason'] === 'loopback') {
                    /* translators: %s: error message */
                    $message = sprintf(__('WP-Cron is not working: WordPress could not reach its own wp-cron.php (%s). Automatic backups will not start.', 'korisec'), $h['detail']);
                    $fix = __('This is usually caused by password protection (HTTP authentication), a firewall or security plugin blocking requests from the server to itself, or DNS that does not resolve on the server. Ask your host to allow loopback requests, or set up a server cron job.', 'korisec');
                } elseif ($h['reason'] === 'disabled') {
                    $message = $last
                        /* translators: %s: time span, e.g. "5 hours" */
                        ? sprintf(__('WP-Cron is turned off in wp-config.php (DISABLE_WP_CRON) and no server cron job has run scheduled tasks for %s. Automatic backups will not start.', 'korisec'), human_time_diff($last))
                        : __('WP-Cron is turned off in wp-config.php (DISABLE_WP_CRON) and no server cron job is running scheduled tasks. Automatic backups will not start.', 'korisec');
                    $fix = __('Remove DISABLE_WP_CRON from wp-config.php, or ask your host to add a server cron job for wp-cron.php.', 'korisec');
                } else {
                    $message = $last
                        /* translators: %s: time span, e.g. "5 hours" */
                        ? sprintf(__('WP-Cron has not run scheduled tasks for %s. Automatic backups will not start until it does.', 'korisec'), human_time_diff($last))
                        : __('WP-Cron is not running scheduled tasks on this site. Automatic backups will not start until it does.', 'korisec');
                    $fix = __('Ask your host to add a server cron job for wp-cron.php, or check whether a plugin or firewall blocks it.', 'korisec');
                }
                break;
        }
        return array(
            'status' => $h['status'],
            'reason' => $h['reason'],
            'message' => $message,
            'fix' => $fix,
            'disabled' => self::cron_disabled(),
            'last_run' => (int) $last,
            'checked' => (int) $h['checked'],
            'cron_url' => $cron_url,
            'cron_line' => sprintf('*/5 * * * * wget -q -O - %s >/dev/null 2>&1', $cron_url),
            'browser_note' => __('Backups you start from the Backups screen still run while that page is open.', 'korisec'),
        );
    }

    public static function admin_notice() {
        if (!current_user_can('manage_options')) {
            return;
        }
        $screen = function_exists('get_current_screen') ? get_current_screen() : null;
        $id = $screen ? (string) $screen->id : '';
        $on_korisec = strpos($id, 'korisec') !== false;
        if (!in_array($id, array('dashboard', 'plugins'), true) && !$on_korisec) {
            return;
        }
        $just_activated = $id === 'plugins' && get_transient(self::NOTICE_TRANSIENT);
        $st = self::status();

        if ($st['status'] === 'broken') {
            $settings = class_exists('Korisec_Backup_Store') ? Korisec_Backup_Store::settings() : array('schedule' => 'off');
            $scheduled = $settings['schedule'] !== 'off' && class_exists('Korisec_Backup_Jobs') && Korisec_Backup_Jobs::provider()->is_connected();
            if (!$scheduled && !$just_activated && !$on_korisec) {
                return;
            }
            delete_transient(self::NOTICE_TRANSIENT);
            $link = admin_url('admin.php?page=korisec&korisec_tab=backups');
            echo '<div class="notice notice-error"><p><strong>' . esc_html__('Korisec:', 'korisec') . '</strong> ' . esc_html($st['message']) . '</p>';
            if ($st['fix'] !== '') {
                echo '<p>' . esc_html($st['fix']) . '</p>';
            }
            if (!$on_korisec) {
                echo '<p><a href="' . esc_url($link) . '">' . esc_html__('See how to fix it on the Backups screen', 'korisec') . '</a></p>';
            }
            echo '</div>';
            return;
        }
        if (!$just_activated) {
            return;
        }
        delete_transient(self::NOTICE_TRANSIENT);
        $type = $st['status'] === 'ok' ? 'success' : 'info';
        echo '<div class="notice notice-' . esc_attr($type) . ' is-dismissible"><p><strong>' . esc_html__('Korisec checked WP-Cron:', 'korisec') . '</strong> ' . esc_html($st['message']) . '</p></div>';
    }
}
