<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Korisec → Backups screen: AJAX endpoints, OAuth return, recovery key download.
 * Works without a Korisec plugin key (free feature).
 */
class Korisec_Backup_Admin {
    const NOTICE_PREFIX = 'korisec_backup_notice_';

    public static function init() {
        add_action('admin_init', array(__CLASS__, 'maybe_handle_oauth_return'));
        add_action('admin_post_korisec_backup_key', array(__CLASS__, 'download_recovery_key'));
        $actions = array(
            'state', 'step', 'start', 'restore', 'cancel', 'undo', 'keep', 'delete', 'settings',
            'drive_connect', 'drive_disconnect', 'recovery_key', 'ack_key', 'import_key', 'sync', 'cron_check',
        );
        foreach ($actions as $a) {
            add_action('wp_ajax_korisec_backup_' . $a, array(__CLASS__, 'ajax_' . $a));
        }
    }

    private static function guard() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('You do not have permission to manage backups.', 'korisec')), 403);
        }
        check_ajax_referer('korisec_admin', 'nonce');
        Korisec_Backup_Store::maybe_install();
    }

    public static function maybe_handle_oauth_return() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- validated against a per-user one-time nonce in handle_return()
        if (!isset($_GET['page'], $_GET['korisec_gd_n']) || $_GET['page'] !== 'korisec' || !current_user_can('manage_options')) {
            return;
        }
        Korisec_Backup_Store::maybe_install();
        $r = Korisec_GDrive::handle_return();
        if (is_wp_error($r)) {
            set_transient(self::NOTICE_PREFIX . get_current_user_id(), array('type' => 'error', 'message' => $r->get_error_message()), 300);
        } elseif ($r === true) {
            $new_key = Korisec_Backup_Crypto::ensure_key();
            Korisec_Backup_Jobs::reschedule();
            set_transient(
                self::NOTICE_PREFIX . get_current_user_id(),
                array('type' => 'success', 'message' => $new_key ? __('Google Drive connected. Save your recovery key below before anything else.', 'korisec') : __('Google Drive connected.', 'korisec')),
                300
            );
        }
        wp_safe_redirect(admin_url('admin.php?page=korisec&korisec_tab=backups'));
        exit;
    }

    /* ------------------------------------------------------------- payload */

    public static function state_payload() {
        Korisec_Backup_Store::maybe_install();
        $provider = Korisec_Backup_Jobs::provider();
        $job = Korisec_Backup_Jobs::current();
        if ($job) {
            unset($job['token'], $job['backup'], $job['restore']);
        }
        $undo = Korisec_Backup_Jobs::undo_info();
        $verified = Korisec_Backup_Store::verified_backups();
        $last = null;
        foreach ($verified as $v) {
            if ($v['backup_type'] !== 'safety') {
                $last = $v;
                break;
            }
        }
        $rows = array();
        foreach (Korisec_Backup_Store::list_backups(60) as $b) {
            $rows[] = array(
                'uuid' => $b['backup_uuid'],
                'status' => $b['status'],
                'type' => $b['backup_type'],
                'scope' => $b['scope'],
                'created' => strtotime($b['created_at'] . ' UTC'),
                'tables' => $b['table_count'],
                'files' => $b['file_count'],
                'db_size' => $b['db_size'],
                'files_size' => $b['files_size'],
                'stored' => $b['stored_size'],
                'host' => $b['site_host'],
                'error' => $b['error_message'] ? $b['error_message'] : '',
                'key_ok' => !is_wp_error(Korisec_Backup_Crypto::key_for($b['key_id'])),
            );
        }
        $notice = get_transient(self::NOTICE_PREFIX . get_current_user_id());
        if ($notice) {
            delete_transient(self::NOTICE_PREFIX . get_current_user_id());
        }
        $workdir = Korisec_Backup_Store::workdir();
        return array(
            'env' => array(
                'ok' => Korisec_Backup_Crypto::available() && !is_multisite(),
                'multisite' => is_multisite(),
                'crypto' => Korisec_Backup_Crypto::available(),
                'disk_free' => (!is_wp_error($workdir) && function_exists('disk_free_space')) ? (int) @disk_free_space($workdir) : null, // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
            ),
            'drive' => array(
                'connected' => $provider->is_connected(),
                'email' => Korisec_GDrive::account_email(),
                'folder' => Korisec_GDrive::folder_label(),
            ),
            'key' => array(
                'has' => Korisec_Backup_Crypto::has_active_key(),
                'acknowledged' => Korisec_Backup_Crypto::recovery_acknowledged(),
                'download_url' => add_query_arg(array('action' => 'korisec_backup_key', '_wpnonce' => wp_create_nonce('korisec_backup_key')), admin_url('admin-post.php')),
            ),
            'settings' => Korisec_Backup_Store::settings(),
            'job' => $job,
            'undo' => $undo ? array(
                'source' => $undo['source'],
                'restored_at' => (int) $undo['restored_at'],
                'expires' => (int) $undo['expires'],
                'files' => !empty($undo['files']),
                'siteurl_changed' => !empty($undo['siteurl_changed']),
            ) : null,
            'last' => $last ? array('created' => strtotime($last['created_at'] . ' UTC'), 'stored' => $last['stored_size'], 'tables' => $last['table_count'], 'db_size' => $last['db_size'], 'files' => $last['file_count']) : null,
            'restore_points' => count($verified),
            'recent_failure' => Korisec_Backup_Store::last_failed_since(time() - 7 * DAY_IN_SECONDS) ? true : false,
            'next' => Korisec_Backup_Jobs::next_scheduled(),
            'backups' => $rows,
            'events' => Korisec_Backup_Store::recent_events(25),
            'notice' => $notice ? $notice : null,
            'host' => Korisec_Backup_Store::site_host(),
            'cron' => Korisec_Cron_Health::status(),
        );
    }

    private static function ok($extra = array()) {
        wp_send_json_success(array_merge(array('state' => self::state_payload()), $extra));
    }

    private static function err(WP_Error $e) {
        wp_send_json_error(array('message' => $e->get_error_message(), 'state' => self::state_payload()));
    }

    /* --------------------------------------------------------------- AJAX */

    public static function ajax_state() {
        self::guard();
        self::ok();
    }

    public static function ajax_step() {
        self::guard();
        session_write_close();
        $r = Korisec_Backup_Jobs::tick();
        self::ok(array('tick' => $r));
    }

    public static function ajax_start() {
        self::guard();
        $r = Korisec_Backup_Jobs::start_backup('manual');
        if (is_wp_error($r)) {
            self::err($r);
        }
        self::ok();
    }

    public static function ajax_restore() {
        self::guard();
        $uuid = isset($_POST['uuid']) ? sanitize_text_field(wp_unslash($_POST['uuid'])) : '';
        $confirm = isset($_POST['confirm']) ? sanitize_text_field(wp_unslash($_POST['confirm'])) : '';
        if ($confirm !== 'RESTORE') {
            self::err(new WP_Error('confirm', __('Type RESTORE to confirm.', 'korisec')));
        }
        $r = Korisec_Backup_Jobs::start_restore($uuid, !empty($_POST['include_files']));
        if (is_wp_error($r)) {
            self::err($r);
        }
        self::ok();
    }

    public static function ajax_cancel() {
        self::guard();
        $r = Korisec_Backup_Jobs::cancel();
        if (is_wp_error($r)) {
            self::err($r);
        }
        self::ok();
    }

    public static function ajax_undo() {
        self::guard();
        $r = Korisec_Backup_Jobs::undo_restore();
        if (is_wp_error($r)) {
            self::err($r);
        }
        self::ok(array('message' => __('Restore undone. Your site is back to how it was before the restore.', 'korisec')));
    }

    public static function ajax_keep() {
        self::guard();
        $r = Korisec_Backup_Jobs::keep_restore();
        if (is_wp_error($r)) {
            self::err($r);
        }
        self::ok();
    }

    public static function ajax_delete() {
        self::guard();
        $uuid = isset($_POST['uuid']) ? sanitize_text_field(wp_unslash($_POST['uuid'])) : '';
        $r = Korisec_Backup_Jobs::delete_backup($uuid);
        if (is_wp_error($r)) {
            self::err($r);
        }
        self::ok();
    }

    public static function ajax_settings() {
        self::guard();
        $in = array(
            'schedule' => isset($_POST['schedule']) ? sanitize_key(wp_unslash($_POST['schedule'])) : 'daily',
            'hour' => isset($_POST['hour']) ? (int) $_POST['hour'] : 2,
            'scope' => isset($_POST['scope']) ? sanitize_key(wp_unslash($_POST['scope'])) : 'full',
            'include_uploads' => !empty($_POST['include_uploads']),
            'retention' => isset($_POST['retention']) ? (int) $_POST['retention'] : 14,
            'all_tables' => !empty($_POST['all_tables']),
            'notify_failures' => !empty($_POST['notify_failures']),
        );
        Korisec_Backup_Store::save_settings($in);
        Korisec_Backup_Jobs::reschedule();
        $message = __('Backup settings saved.', 'korisec');
        if (!Korisec_Backup_Jobs::is_running() && Korisec_Backup_Jobs::provider()->is_connected()) {
            $r = Korisec_Backup_Jobs::apply_retention(microtime(true) + 15);
            if ($r['deleted'] > 0) {
                $message .= ' ' . sprintf(
                    /* translators: %d: number of backups removed */
                    _n('Removed %d old backup to match the new limit.', 'Removed %d old backups to match the new limit.', $r['deleted'], 'korisec'),
                    $r['deleted']
                );
            }
            if (!$r['done']) {
                Korisec_Backup_Jobs::schedule_maintenance_soon();
                $message .= ' ' . __('The rest will be removed in the background.', 'korisec');
            }
        }
        self::ok(array('message' => $message));
    }

    public static function ajax_cron_check() {
        self::guard();
        Korisec_Cron_Health::run_check();
        self::ok();
    }

    public static function ajax_drive_connect() {
        self::guard();
        if (!Korisec_Backup_Crypto::available()) {
            self::err(new WP_Error('backup_env', __('This server is missing PHP sodium or zlib, which Korisec needs to encrypt backups.', 'korisec')));
        }
        wp_send_json_success(array('url' => Korisec_GDrive::connect_url()));
    }

    public static function ajax_drive_disconnect() {
        self::guard();
        if (Korisec_Backup_Jobs::is_running()) {
            self::err(new WP_Error('backup_busy', __('Wait for the running job to finish first.', 'korisec')));
        }
        Korisec_GDrive::disconnect();
        Korisec_Backup_Jobs::reschedule();
        self::ok();
    }

    public static function ajax_recovery_key() {
        self::guard();
        Korisec_Backup_Crypto::ensure_key();
        $k = Korisec_Backup_Crypto::recovery_key();
        if (is_wp_error($k)) {
            self::err($k);
        }
        wp_send_json_success(array('key' => $k));
    }

    public static function ajax_ack_key() {
        self::guard();
        Korisec_Backup_Crypto::acknowledge_recovery();
        Korisec_Backup_Store::log('RECOVERY_KEY_SAVED', '', 'Administrator confirmed the recovery key was saved');
        self::ok();
    }

    public static function ajax_import_key() {
        self::guard();
        $text = isset($_POST['key']) ? sanitize_text_field(wp_unslash($_POST['key'])) : '';
        $r = Korisec_Backup_Crypto::import_recovery_key($text, !empty($_POST['make_active']));
        if (is_wp_error($r)) {
            self::err($r);
        }
        Korisec_Backup_Store::log('RECOVERY_KEY_IMPORTED', '', 'Key id ' . $r);
        self::ok(array('message' => __('Recovery key added.', 'korisec')));
    }

    public static function ajax_sync() {
        self::guard();
        $r = Korisec_Backup_Jobs::sync_remote();
        if (is_wp_error($r)) {
            self::err($r);
        }
        if ($r['locked'] > 0) {
            /* translators: 1: added count, 2: locked count */
            $msg = sprintf(__('Found %1$d new backup(s). %2$d more need a different recovery key.', 'korisec'), $r['added'], $r['locked']);
        } else {
            /* translators: %d: number of backups */
            $msg = sprintf(__('Found %d new backup(s) in Google Drive.', 'korisec'), $r['added']);
        }
        self::ok(array('message' => $msg));
    }

    public static function download_recovery_key() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to do that.', 'korisec'), '', array('response' => 403));
        }
        check_admin_referer('korisec_backup_key');
        Korisec_Backup_Crypto::ensure_key();
        $k = Korisec_Backup_Crypto::recovery_key();
        if (is_wp_error($k)) {
            wp_die(esc_html($k->get_error_message()));
        }
        $host = Korisec_Backup_Store::site_host();
        $body = "Korisec backup recovery key\n"
            . "Site: {$host}\n"
            . 'Saved: ' . gmdate('Y-m-d H:i') . " UTC\n\n"
            . $k . "\n\n"
            . "Keep this somewhere safe and offline (password manager).\n"
            . "Anyone with this key and access to your Google Drive backups can read them.\n"
            . "Without it you cannot restore these backups on a new server.\n";
        nocache_headers();
        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="korisec-recovery-key-' . sanitize_file_name($host) . '.txt"');
        echo $body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- plain-text download
        exit;
    }
}
