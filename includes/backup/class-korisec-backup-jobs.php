<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Backup / restore job runner.
 *
 * Work runs in short time slices ("ticks") so it survives PHP time limits. Ticks
 * are driven by the open admin page, a non-blocking loopback request, and a
 * WP-Cron fallback. A database-level lock keeps ticks from overlapping.
 *
 * Backup:  init → db → scan → files → verify_local → seal → upload → verify_remote → register → retention → cleanup
 * Restore: manifest → safety backup → download → verify_download → db_import → db_validate → files_extract → swap
 */
class Korisec_Backup_Jobs {
    const OPTION_JOB = 'korisec_backup_job';
    const OPTION_UNDO = 'korisec_backup_undo';
    const OPTION_CANCEL = 'korisec_backup_cancel';
    const OPTION_CORRUPT_SEEN = 'korisec_backup_corrupt_seen';
    const CORRUPT_GRACE = 7 * DAY_IN_SECONDS;
    const LOCK = '_korisec_backup_tick_lock';
    const HOOK_TICK = 'korisec_backup_tick';
    const HOOK_SCHEDULED = 'korisec_backup_scheduled';
    const HOOK_MAINT = 'korisec_backup_maint';
    const BUDGET = 20;
    const LOCK_TTL = 300;
    const MAX_RETRIES = 6;
    const SAFETY_KEEP = 3;
    const UNDO_DAYS = 7;

    public static function init() {
        add_action(self::HOOK_TICK, array(__CLASS__, 'cron_tick'));
        add_action(self::HOOK_SCHEDULED, array(__CLASS__, 'scheduled_backup'));
        add_action(self::HOOK_MAINT, array(__CLASS__, 'maintenance'));
        add_action('wp_ajax_nopriv_korisec_backup_tick', array(__CLASS__, 'loopback_tick'));
        add_action('wp_ajax_korisec_backup_tick', array(__CLASS__, 'loopback_tick'));
        if (!wp_next_scheduled(self::HOOK_MAINT)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::HOOK_MAINT);
        }
    }

    public static function deactivate() {
        wp_clear_scheduled_hook(self::HOOK_TICK);
        wp_clear_scheduled_hook(self::HOOK_SCHEDULED);
        wp_clear_scheduled_hook(self::HOOK_MAINT);
    }

    public static function provider() {
        static $provider = null;
        if ($provider === null) {
            $custom = apply_filters('korisec_backup_provider', null);
            $provider = $custom instanceof Korisec_Storage_Provider ? $custom : new Korisec_GDrive();
        }
        return $provider;
    }

    /* ------------------------------------------------------------ schedule */

    public static function reschedule() {
        wp_clear_scheduled_hook(self::HOOK_SCHEDULED);
        $s = Korisec_Backup_Store::settings();
        if ($s['schedule'] === 'off' || !self::provider()->is_connected()) {
            return;
        }
        $tz = wp_timezone();
        $now = new DateTimeImmutable('now', $tz);
        $next = $now->setTime($s['hour'], 0, 0);
        if ($next <= $now) {
            $next = $next->modify('+1 day');
        }
        wp_schedule_event($next->getTimestamp(), $s['schedule'] === 'weekly' ? 'weekly' : 'daily', self::HOOK_SCHEDULED);
    }

    public static function next_scheduled() {
        $ts = wp_next_scheduled(self::HOOK_SCHEDULED);
        return $ts ? (int) $ts : 0;
    }

    public static function scheduled_backup() {
        if (self::current() && self::current()['status'] === 'running') {
            return;
        }
        $r = self::start_backup('scheduled');
        if (is_wp_error($r)) {
            self::notify_failure(__('Scheduled backup could not start', 'korisec'), $r->get_error_message());
        }
    }

    /* ------------------------------------------------------------- job I/O */

    public static function current() {
        $job = get_option(self::OPTION_JOB, null);
        return is_array($job) ? $job : null;
    }

    private static function save(array $job) {
        $job['updated'] = time();
        update_option(self::OPTION_JOB, $job, false);
    }

    public static function is_running() {
        $job = self::current();
        return $job && $job['status'] === 'running';
    }

    public static function undo_info() {
        $u = get_option(self::OPTION_UNDO, null);
        return is_array($u) ? $u : null;
    }

    /* ---------------------------------------------------------------- lock */

    private static function lock() {
        global $wpdb;
        $until = time() + self::LOCK_TTL;
        $ok = $wpdb->query($wpdb->prepare("INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", self::LOCK, (string) $until)); // phpcs:ignore WordPress.DB
        if ($ok !== 1) {
            $ok = $wpdb->query($wpdb->prepare("UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND CAST(option_value AS UNSIGNED) < %d", (string) $until, self::LOCK, time())); // phpcs:ignore WordPress.DB
        }
        if ($ok !== 1) {
            return false;
        }
        self::forget_cached_state();
        return true;
    }

    /**
     * Another request may have advanced the job while this one waited for the lock, so drop
     * this request's cached copies; otherwise it would replay steps from a stale cursor.
     */
    private static function forget_cached_state() {
        $names = array(self::OPTION_JOB, self::OPTION_UNDO, self::OPTION_CANCEL);
        $all = wp_cache_get('alloptions', 'options');
        $all_changed = false;
        foreach ($names as $name) {
            wp_cache_delete($name, 'options');
            if (is_array($all) && array_key_exists($name, $all)) {
                unset($all[$name]);
                $all_changed = true;
            }
        }
        if ($all_changed) {
            wp_cache_set('alloptions', $all, 'options');
        }
        wp_cache_delete('notoptions', 'options');
    }

    private static function unlock() {
        global $wpdb;
        $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->options} WHERE option_name = %s", self::LOCK)); // phpcs:ignore WordPress.DB
    }

    /* --------------------------------------------------------------- start */

    /** @return true|WP_Error */
    private static function preflight() {
        if (is_multisite()) {
            return new WP_Error('backup_multisite', __('Backups are not yet available on WordPress multisite.', 'korisec'));
        }
        if (!Korisec_Backup_Crypto::available()) {
            return new WP_Error('backup_env', __('This server is missing PHP sodium or zlib, which Korisec needs to encrypt backups.', 'korisec'));
        }
        if (!self::provider()->is_connected()) {
            return new WP_Error('backup_no_drive', __('Connect Google Drive first.', 'korisec'));
        }
        if (self::is_running()) {
            return new WP_Error('backup_busy', __('A backup or restore is already running.', 'korisec'));
        }
        return true;
    }

    private static function new_backup_ctx($type, $scope = null) {
        $s = Korisec_Backup_Store::settings();
        $stamp = gmdate('Y-m-d\THis\Z');
        $uuid = Korisec_Backup_Store::uuid();
        return array(
            'uuid' => $uuid,
            'type' => $type,
            'scope' => $scope ? $scope : $s['scope'],
            'include_uploads' => $s['include_uploads'],
            'all_tables' => $s['all_tables'],
            'stamp' => $stamp,
            'base' => 'korisec-' . $type . '-' . $stamp . '-' . substr(str_replace('-', '', $uuid), 0, 8),
            'step' => 'init',
            'parts' => array(),
        );
    }

    private static function new_job($kind, $trigger) {
        return array(
            'id' => bin2hex(random_bytes(4)),
            'kind' => $kind,
            'trigger' => $trigger,
            'status' => 'running',
            'token' => bin2hex(random_bytes(16)),
            'label' => __('Starting…', 'korisec'),
            'pct' => 0,
            'started' => time(),
            'updated' => time(),
            'error' => '',
            'retries' => 0,
            'next_at' => 0,
            'user_id' => get_current_user_id(),
        );
    }

    /** @return array|WP_Error Job. */
    public static function start_backup($trigger = 'manual') {
        $ok = self::preflight();
        if (is_wp_error($ok)) {
            return $ok;
        }
        $job = self::new_job('backup', $trigger);
        $job['backup'] = self::new_backup_ctx($trigger === 'scheduled' ? 'scheduled' : 'manual');
        delete_option(self::OPTION_CANCEL);
        self::save($job);
        self::kick($job);
        return $job;
    }

    /** @return array|WP_Error Job. */
    public static function start_restore($uuid, $include_files) {
        $ok = self::preflight();
        if (is_wp_error($ok)) {
            return $ok;
        }
        $row = Korisec_Backup_Store::get_backup($uuid);
        if (!$row || $row['status'] !== Korisec_Backup_Store::STATUS_VERIFIED || empty($row['remote_manifest_id'])) {
            return new WP_Error('restore_source', __('Only verified backups can be restored.', 'korisec'));
        }
        $key = Korisec_Backup_Crypto::key_for($row['key_id']);
        if (is_wp_error($key)) {
            return $key;
        }
        if (self::undo_info()) {
            self::keep_restore();
        }
        $job = self::new_job('restore', 'manual');
        $include_files = $include_files && $row['scope'] === 'full';
        $job['restore'] = array(
            'rid' => bin2hex(random_bytes(4)),
            'source' => $uuid,
            'include_files' => $include_files,
            'phase' => 'manifest',
            'safety' => self::new_backup_ctx('safety', $include_files ? 'full' : 'database'),
        );
        delete_option(self::OPTION_CANCEL);
        Korisec_Backup_Store::log('RESTORE_STARTED', $uuid, $include_files ? 'Database and files' : 'Database only');
        self::save($job);
        self::kick($job);
        return $job;
    }

    /** @return true|WP_Error */
    public static function cancel() {
        $job = self::current();
        if (!$job || $job['status'] !== 'running') {
            return true;
        }
        if ($job['kind'] === 'restore' && isset($job['restore']['phase']) && $job['restore']['phase'] === 'swap') {
            return new WP_Error('restore_swap', __('The restore is swapping files right now and cannot be cancelled.', 'korisec'));
        }
        update_option(self::OPTION_CANCEL, $job['id'], false);
        if (self::lock()) {
            $job = self::current();
            self::fail($job, new WP_Error('cancelled', __('Cancelled by an administrator.', 'korisec')));
            delete_option(self::OPTION_CANCEL);
            self::unlock();
        }
        return true;
    }

    /* ---------------------------------------------------------------- ticks */

    public static function kick(array $job) {
        if (!wp_next_scheduled(self::HOOK_TICK)) {
            wp_schedule_single_event(time() + 60, self::HOOK_TICK);
        }
        wp_remote_post(
            admin_url('admin-ajax.php'),
            array(
                'timeout' => 0.01,
                'blocking' => false,
                'sslverify' => apply_filters('https_local_ssl_verify', false), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals -- core filter
                'body' => array('action' => 'korisec_backup_tick', 'token' => $job['token']),
            )
        );
    }

    public static function loopback_tick() {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- authenticated by the per-job random token
        $token = isset($_POST['token']) ? sanitize_text_field(wp_unslash($_POST['token'])) : '';
        $job = self::current();
        if (!$job || $token === '' || !hash_equals((string) $job['token'], $token)) {
            wp_die('', '', array('response' => 403));
        }
        self::tick();
        wp_die();
    }

    public static function cron_tick() {
        self::tick();
    }

    /**
     * Run one time slice.
     *
     * @return string 'idle' | 'busy' | 'ran'
     */
    public static function tick() {
        $job = self::current();
        if (!$job || $job['status'] !== 'running') {
            return 'idle';
        }
        if (!self::lock()) {
            return 'busy';
        }
        ignore_user_abort(true);
        if (function_exists('set_time_limit')) {
            @set_time_limit(self::BUDGET + 100); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
        }
        $job = self::current();
        if (!$job || $job['status'] !== 'running') {
            self::unlock();
            return 'idle';
        }
        if (!empty($job['next_at']) && $job['next_at'] > time()) {
            self::unlock();
            if (!wp_next_scheduled(self::HOOK_TICK)) {
                wp_schedule_single_event($job['next_at'], self::HOOK_TICK);
            }
            return 'busy';
        }
        $budget = (float) apply_filters('korisec_backup_tick_budget', self::BUDGET);
        $deadline = microtime(true) + max(0.05, min((float) self::BUDGET, $budget));
        try {
            $result = $job['kind'] === 'restore' ? self::run_restore($job, $deadline) : self::run_backup_job($job, $deadline);
            if (is_wp_error($result)) {
                self::handle_error($job, $result);
            } elseif ($result === true) {
                $job['status'] = 'done';
                $job['pct'] = 100;
                self::save($job);
            } else {
                $job['retries'] = 0;
                self::save($job);
            }
        } catch (Throwable $e) {
            self::handle_error($job, new WP_Error('exception', $e->getMessage()));
        }
        self::unlock();
        $job = self::current();
        if ($job && $job['status'] === 'running') {
            self::kick($job);
        }
        return 'ran';
    }

    private static function handle_error(array &$job, WP_Error $err) {
        $code = $err->get_error_code();
        $transient = in_array($code, array('gd_transient', 'gd_session_expired'), true);
        if ($transient && $job['retries'] < self::MAX_RETRIES) {
            $job['retries']++;
            $job['next_at'] = time() + min(300, 15 * (1 << $job['retries']));
            /* translators: %s: error message */
            $job['label'] = sprintf(__('Waiting to retry: %s', 'korisec'), $err->get_error_message());
            self::save($job);
            return;
        }
        self::fail($job, $err);
    }

    private static function cancelled(array $job) {
        return get_option(self::OPTION_CANCEL, '') === $job['id'];
    }

    private static function fail(array $job, WP_Error $err) {
        $msg = $err->get_error_message();
        if ($job['kind'] === 'backup') {
            self::cleanup_backup_ctx($job['backup'], true);
            Korisec_Backup_Store::update_backup($job['backup']['uuid'], array('status' => Korisec_Backup_Store::STATUS_FAILED, 'error_message' => $msg, 'completed_at' => gmdate('Y-m-d H:i:s')));
            Korisec_Backup_Store::log('BACKUP_FAILED', $job['backup']['uuid'], $msg);
            if ($job['trigger'] === 'scheduled' && $err->get_error_code() !== 'cancelled') {
                self::notify_failure(__('Scheduled backup failed', 'korisec'), $msg);
            }
        } else {
            $r = $job['restore'];
            if (!empty($r['safety']['uuid']) && $r['safety']['step'] !== 'done') {
                self::cleanup_backup_ctx($r['safety'], true);
                Korisec_Backup_Store::update_backup($r['safety']['uuid'], array('status' => Korisec_Backup_Store::STATUS_FAILED, 'error_message' => $msg));
            }
            Korisec_Backup_DB::drop_temp_tables($r['rid']);
            self::cleanup_restore_files($r);
            Korisec_Backup_Store::log('RESTORE_FAILED', $r['source'], $msg . ' — the live site was not changed.');
        }
        $job['status'] = $err->get_error_code() === 'cancelled' ? 'cancelled' : 'failed';
        $job['error'] = $msg;
        $job['label'] = $msg;
        self::save($job);
    }

    private static function notify_failure($subject, $message) {
        $s = Korisec_Backup_Store::settings();
        if (empty($s['notify_failures'])) {
            return;
        }
        wp_mail(
            get_option('admin_email'),
            '[' . wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES) . '] ' . $subject,
            $message . "\n\n" . __('Open Korisec → Backups in wp-admin to retry.', 'korisec') . "\n" . admin_url('admin.php?page=korisec&korisec_tab=backups')
        );
    }

    /* ------------------------------------------------------- backup engine */

    private static function run_backup_job(array &$job, $deadline) {
        $r = self::run_backup($job['backup'], $deadline, $job);
        if ($r === true) {
            $job['label'] = __('Backup verified and stored in Google Drive.', 'korisec');
        }
        return $r;
    }

    private static function part_path($dir, array $b, $part) {
        return $dir . '/' . $b['base'] . '-' . $part . '.kbackup';
    }

    /**
     * Advance a backup context. Shared by normal backups and pre-restore safety backups.
     *
     * @return bool|WP_Error true when the backup is verified and registered.
     */
    private static function run_backup(array &$b, $deadline, array &$job, $pct_from = 0, $pct_to = 100) {
        $dir = Korisec_Backup_Store::workdir();
        if (is_wp_error($dir)) {
            return $dir;
        }
        $span = $pct_to - $pct_from;
        $progress = function ($label, $frac) use (&$job, $pct_from, $span) {
            $job['label'] = $label;
            $job['pct'] = (int) round($pct_from + $span * max(0, min(1, $frac)));
        };

        while (microtime(true) < $deadline) {
            if (self::cancelled($job)) {
                return new WP_Error('cancelled', __('Cancelled by an administrator.', 'korisec'));
            }
            switch ($b['step']) {
                case 'init':
                    Korisec_Backup_Crypto::ensure_key();
                    $need = self::estimate_bytes($b);
                    $free = function_exists('disk_free_space') ? @disk_free_space($dir) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
                    if ($free !== false && $free < $need * 1.2 + 52428800) {
                        /* translators: 1: needed size, 2: free size */
                        return new WP_Error('backup_disk', sprintf(__('Not enough free disk space for a backup (needs about %1$s, %2$s free).', 'korisec'), size_format($need * 1.2), size_format($free)));
                    }
                    Korisec_Backup_Store::insert_backup(
                        array(
                            'backup_uuid' => $b['uuid'],
                            'backup_type' => $b['type'],
                            'scope' => $b['scope'],
                            'provider' => 'gdrive',
                            'key_id' => Korisec_Backup_Crypto::active_key_id(),
                            'created_by' => (int) $job['user_id'],
                        )
                    );
                    Korisec_Backup_Store::log('BACKUP_STARTED', $b['uuid'], ucfirst($b['type']) . ' backup (' . $b['scope'] . ')');
                    $b['step'] = 'db';
                    break;

                case 'db':
                    if (empty($b['db_cur'])) {
                        $b['db_cur'] = Korisec_Backup_DB::dump_init($b['all_tables']);
                        $w = Korisec_Backup_Crypto::writer_open(self::part_path($dir, $b, 'db'));
                        if (is_wp_error($w)) {
                            return $w;
                        }
                        $b['db_writer'] = $w;
                    }
                    $total = max(1, count($b['db_cur']['tables']));
                    /* translators: 1: table index, 2: table count */
                    $progress(sprintf(__('Backing up database (table %1$d of %2$d)…', 'korisec'), min($total, $b['db_cur']['table_index'] + 1), $total), 0.05 + 0.3 * ($b['db_cur']['table_index'] / $total));
                    $r = Korisec_Backup_DB::dump_step($b['db_cur'], $b['db_writer'], $deadline);
                    if (is_wp_error($r)) {
                        return $r;
                    }
                    if ($r === true) {
                        $b['parts']['db'] = array('local' => $b['db_writer']['path'], 'plain' => $b['db_writer']['plain_bytes']);
                        unset($b['db_writer']);
                        $b['step'] = $b['scope'] === 'full' ? 'scan' : 'verify_local';
                    }
                    break;

                case 'scan':
                    $progress(__('Listing files…', 'korisec'), 0.36);
                    $list = $dir . '/' . $b['base'] . '-files.lst';
                    $scan = Korisec_Backup_Files::scan($list, $b['include_uploads']);
                    if (is_wp_error($scan)) {
                        return $scan;
                    }
                    $free = function_exists('disk_free_space') ? @disk_free_space($dir) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
                    if ($free !== false && $free < $scan['bytes'] * 1.05 + 52428800) {
                        wp_delete_file($list);
                        /* translators: 1: needed size, 2: free size */
                        return new WP_Error('backup_disk', sprintf(__('Not enough free disk space to back up files (needs about %1$s, %2$s free). Try excluding uploads or a database-only backup.', 'korisec'), size_format($scan['bytes'] * 1.05), size_format($free)));
                    }
                    $b['files_list'] = $list;
                    $b['files_total'] = $scan;
                    $b['step'] = 'files';
                    break;

                case 'files':
                    if (empty($b['files_cur'])) {
                        $b['files_cur'] = Korisec_Backup_Files::archive_init();
                        $w = Korisec_Backup_Crypto::writer_open(self::part_path($dir, $b, 'files'));
                        if (is_wp_error($w)) {
                            return $w;
                        }
                        $b['files_writer'] = $w;
                    }
                    $tb = max(1, (int) $b['files_total']['bytes']);
                    /* translators: 1: files done, 2: total files */
                    $progress(sprintf(__('Backing up files (%1$s of %2$s)…', 'korisec'), number_format_i18n($b['files_cur']['files']), number_format_i18n($b['files_total']['count'])), 0.38 + 0.3 * ($b['files_cur']['bytes'] / $tb));
                    $r = Korisec_Backup_Files::archive_step($b['files_list'], $b['files_cur'], $b['files_writer'], $deadline);
                    if (is_wp_error($r)) {
                        return $r;
                    }
                    if ($r === true) {
                        $b['parts']['files'] = array('local' => $b['files_writer']['path'], 'plain' => $b['files_writer']['plain_bytes']);
                        unset($b['files_writer']);
                        $b['step'] = 'verify_local';
                    }
                    break;

                case 'verify_local':
                    $progress(__('Verifying the encrypted backup can be read…', 'korisec'), 0.7);
                    $r = self::verify_local_step($b, $deadline);
                    if (is_wp_error($r)) {
                        return $r;
                    }
                    if ($r === true) {
                        $b['step'] = 'seal';
                    }
                    break;

                case 'seal':
                    foreach ($b['parts'] as $name => $p) {
                        $b['parts'][$name]['size'] = (int) filesize($p['local']);
                        $b['parts'][$name]['sha256'] = hash_file('sha256', $p['local']);
                        $b['parts'][$name]['md5'] = md5_file($p['local']);
                    }
                    Korisec_Backup_Store::update_backup(
                        $b['uuid'],
                        array(
                            'status' => Korisec_Backup_Store::STATUS_UPLOADING,
                            'table_count' => count($b['db_cur']['tables']),
                            'row_count' => (int) $b['db_cur']['rows'],
                            'file_count' => isset($b['files_cur']['files']) ? (int) $b['files_cur']['files'] : 0,
                            'db_size' => (int) $b['parts']['db']['plain'],
                            'files_size' => isset($b['parts']['files']) ? (int) $b['parts']['files']['plain'] : 0,
                        )
                    );
                    Korisec_Backup_Store::log('BACKUP_CREATED', $b['uuid'], 'Encrypted and verified locally');
                    $b['upload_queue'] = array_merge(array_keys($b['parts']), array('manifest'));
                    $b['upload_index'] = 0;
                    $b['upload_session'] = array();
                    $b['step'] = 'upload';
                    break;

                case 'upload':
                    $r = self::upload_step($b, $deadline, $dir, $progress);
                    if (is_wp_error($r)) {
                        return $r;
                    }
                    if ($r === true) {
                        $b['step'] = 'verify_remote';
                    }
                    break;

                case 'verify_remote':
                    $progress(__('Confirming the backup in Google Drive…', 'korisec'), 0.95);
                    Korisec_Backup_Store::update_backup($b['uuid'], array('status' => Korisec_Backup_Store::STATUS_REMOTE_VERIFYING));
                    foreach ($b['parts'] as $name => $p) {
                        $meta = self::provider()->get_metadata($p['remote_id']);
                        if (is_wp_error($meta)) {
                            return $meta;
                        }
                        if ($meta['trashed'] || $meta['size'] !== (int) $p['size'] || ($meta['md5'] !== '' && $meta['md5'] !== $p['md5'])) {
                            Korisec_Backup_Store::update_backup($b['uuid'], array('status' => Korisec_Backup_Store::STATUS_CORRUPTED));
                            /* translators: %s: part name */
                            return new WP_Error('backup_remote_mismatch', sprintf(__('The %s file in Google Drive does not match what was uploaded.', 'korisec'), $name));
                        }
                    }
                    $b['step'] = 'register';
                    break;

                case 'register':
                    $parts = array();
                    $stored = 0;
                    foreach ($b['parts'] as $name => $p) {
                        $parts[$name] = array('name' => $p['remote_name'], 'remote_id' => $p['remote_id'], 'size' => $p['size'], 'sha256' => $p['sha256'], 'md5' => $p['md5']);
                        $stored += (int) $p['size'];
                    }
                    Korisec_Backup_Store::update_backup(
                        $b['uuid'],
                        array(
                            'status' => Korisec_Backup_Store::STATUS_VERIFIED,
                            'completed_at' => gmdate('Y-m-d H:i:s'),
                            'stored_size' => $stored,
                            'parts' => $parts,
                            'remote_manifest_id' => $parts['manifest']['remote_id'],
                        )
                    );
                    Korisec_Backup_Store::log('BACKUP_UPLOADED', $b['uuid'], size_format($stored) . ' to Google Drive');
                    Korisec_Backup_Store::log('BACKUP_VERIFIED', $b['uuid'], 'Remote size and checksum confirmed');
                    $b['step'] = 'retention';
                    break;

                case 'retention':
                    $progress(__('Applying retention…', 'korisec'), 0.98);
                    self::apply_retention();
                    $b['step'] = 'cleanup';
                    break;

                case 'cleanup':
                    self::cleanup_backup_ctx($b, false);
                    $b['step'] = 'done';
                    break;

                case 'done':
                    return true;

                default:
                    return new WP_Error('backup_state', 'Unknown backup step.');
            }
        }
        return $b['step'] === 'done' ? true : false;
    }

    private static function estimate_bytes(array $b) {
        global $wpdb;
        $db = (int) $wpdb->get_var($wpdb->prepare('SELECT SUM(data_length + index_length) FROM information_schema.TABLES WHERE table_schema = %s', DB_NAME)); // phpcs:ignore WordPress.DB
        return max(1048576, (int) ($db * 0.6));
    }

    private static function verify_local_step(array &$b, $deadline) {
        $names = array_keys($b['parts']);
        if (!isset($b['verify'])) {
            $b['verify'] = array('index' => 0, 'reader' => null);
        }
        while ($b['verify']['index'] < count($names) && microtime(true) < $deadline) {
            $part = $b['parts'][$names[$b['verify']['index']]];
            if ($b['verify']['reader'] === null) {
                $rd = Korisec_Backup_Crypto::reader_open($part['local']);
                if (is_wp_error($rd)) {
                    return $rd;
                }
                $b['verify']['reader'] = $rd;
                $b['verify']['bytes'] = 0;
            }
            while (microtime(true) < $deadline) {
                $blk = Korisec_Backup_Crypto::reader_next($b['verify']['reader']);
                if (is_wp_error($blk)) {
                    return new WP_Error('backup_corrupt', __('The new backup failed its own integrity check and was discarded.', 'korisec'));
                }
                if ($blk === null) {
                    if ($b['verify']['bytes'] !== (int) $part['plain']) {
                        return new WP_Error('backup_corrupt', __('The new backup failed its own integrity check and was discarded.', 'korisec'));
                    }
                    $b['verify']['index']++;
                    $b['verify']['reader'] = null;
                    break;
                }
                $b['verify']['bytes'] += strlen($blk);
            }
        }
        return $b['verify']['index'] >= count($names);
    }

    private static function build_manifest(array $b) {
        global $wpdb;
        $info = Korisec_Backup_DB::server_info();
        $parts = array();
        foreach ($b['parts'] as $name => $p) {
            if ($name === 'manifest') {
                continue;
            }
            $parts[$name] = array('name' => $p['remote_name'], 'remote_id' => $p['remote_id'], 'size' => $p['size'], 'sha256' => $p['sha256'], 'md5' => $p['md5'], 'plain_bytes' => $p['plain']);
        }
        return array(
            'format' => 'korisec-backup',
            'format_version' => 1,
            'backup_id' => $b['uuid'],
            'type' => $b['type'],
            'scope' => $b['scope'],
            'created_at' => gmdate('c'),
            'site_host' => Korisec_Backup_Store::site_host(),
            'home_url' => home_url(),
            'wp_version' => get_bloginfo('version'),
            'plugin_version' => KORISEC_VERSION,
            'php_version' => PHP_VERSION,
            'encryption' => array('scheme' => 'xchacha20poly1305-secretstream+deflate', 'key_id' => Korisec_Backup_Crypto::active_key_id()),
            'database' => array(
                'server' => $info['server'],
                'version' => $info['version'],
                'charset' => $info['charset'],
                'name_hash' => substr(hash('sha256', DB_NAME . '|' . wp_salt('auth')), 0, 16),
                'table_prefix' => $wpdb->prefix,
                'tables' => $b['db_cur']['tables'],
                'table_count' => count($b['db_cur']['tables']),
                'row_count' => (int) $b['db_cur']['rows'],
                'sql_bytes' => (int) $b['db_cur']['sql_bytes'],
                'views_skipped' => (int) $b['db_cur']['views_skipped'],
                'other_prefix_skipped' => (int) $b['db_cur']['other_prefix_skipped'],
            ),
            'files' => isset($b['files_cur']) ? array(
                'count' => (int) $b['files_cur']['files'],
                'bytes' => (int) $b['files_cur']['bytes'],
                'include_uploads' => (bool) $b['include_uploads'],
            ) : null,
            'parts' => $parts,
        );
    }

    private static function upload_step(array &$b, $deadline, $dir, $progress) {
        $provider = self::provider();
        while ($b['upload_index'] < count($b['upload_queue']) && microtime(true) < $deadline) {
            $part = $b['upload_queue'][$b['upload_index']];
            if ($part === 'manifest' && !isset($b['parts']['manifest'])) {
                $path = self::part_path($dir, $b, 'manifest');
                $w = Korisec_Backup_Crypto::writer_open($path);
                if (is_wp_error($w)) {
                    return $w;
                }
                $json = wp_json_encode(self::build_manifest($b));
                $r = Korisec_Backup_Crypto::writer_push($w, $json, true);
                if (is_wp_error($r)) {
                    return $r;
                }
                $b['parts']['manifest'] = array('local' => $path, 'plain' => strlen($json), 'size' => (int) filesize($path), 'sha256' => hash_file('sha256', $path), 'md5' => md5_file($path));
            }
            $p = $b['parts'][$part];
            $remote_name = $b['base'] . '-' . $part . '.kbackup';
            $done_bytes = isset($b['upload_session']['offset']) ? (int) $b['upload_session']['offset'] : 0;
            /* translators: 1: part name, 2: uploaded size, 3: total size */
            $progress(sprintf(__('Uploading %1$s to Google Drive (%2$s of %3$s)…', 'korisec'), $part, size_format($done_bytes), size_format($p['size'])), 0.72 + 0.22 * (($b['upload_index'] + ($p['size'] ? $done_bytes / $p['size'] : 1)) / count($b['upload_queue'])));
            $props = array(
                'korisec_backup' => $b['uuid'],
                'korisec_part' => $part,
                'korisec_host' => substr(Korisec_Backup_Store::site_host(), 0, 100),
                'korisec_sha256' => $p['sha256'],
            );
            $session = $provider->upload_step($p['local'], $remote_name, $props, $b['upload_session'], $deadline);
            if (is_wp_error($session)) {
                if ($session->get_error_code() === 'gd_session_expired') {
                    $b['upload_session'] = array();
                }
                return $session;
            }
            $b['upload_session'] = $session;
            if (!empty($session['done'])) {
                if ((int) $session['size'] !== (int) $p['size'] || ($session['md5'] !== '' && $session['md5'] !== $p['md5'])) {
                    $provider->delete($session['remote_id']);
                    $b['upload_session'] = array();
                    return new WP_Error('gd_transient', __('Google Drive stored a different file size or checksum. Re-uploading.', 'korisec'));
                }
                $b['parts'][$part]['remote_id'] = $session['remote_id'];
                $b['parts'][$part]['remote_name'] = $remote_name;
                $b['upload_index']++;
                $b['upload_session'] = array();
            }
        }
        return $b['upload_index'] >= count($b['upload_queue']);
    }

    private static function cleanup_backup_ctx(array $b, $failed) {
        foreach (isset($b['parts']) ? $b['parts'] : array() as $name => $p) {
            if (!empty($p['local']) && file_exists($p['local'])) {
                wp_delete_file($p['local']);
            }
            if ($failed && !empty($p['remote_id'])) {
                self::provider()->delete($p['remote_id']);
            }
        }
        foreach (array('db_writer', 'files_writer') as $w) {
            if (!empty($b[$w]['path']) && file_exists($b[$w]['path'])) {
                wp_delete_file($b[$w]['path']);
            }
        }
        if (!empty($b['files_list']) && file_exists($b['files_list'])) {
            wp_delete_file($b['files_list']);
        }
    }

    /**
     * Delete old restore points. Never removes the only verified backup.
     *
     * @param float $deadline Stop early at this microtime (0 = no limit).
     * @return array{deleted:int, done:bool}
     */
    public static function apply_retention($deadline = 0) {
        $s = Korisec_Backup_Store::settings();
        $provider = self::provider();
        $groups = array(
            array('types' => array('manual', 'scheduled'), 'keep' => $s['retention']),
            array('types' => array('safety'), 'keep' => self::SAFETY_KEEP),
        );
        $deleted = 0;
        $all_verified = count(Korisec_Backup_Store::verified_backups());
        foreach ($groups as $g) {
            $rows = Korisec_Backup_Store::verified_backups($g['types']);
            foreach (array_slice($rows, $g['keep']) as $old) {
                if ($all_verified <= 1) {
                    return array('deleted' => $deleted, 'done' => true);
                }
                if ($deadline && microtime(true) > $deadline) {
                    return array('deleted' => $deleted, 'done' => false);
                }
                $ok = true;
                foreach ($old['parts'] as $p) {
                    if (!empty($p['remote_id']) && is_wp_error($provider->delete($p['remote_id']))) {
                        $ok = false;
                    }
                }
                if ($ok) {
                    Korisec_Backup_Store::update_backup($old['backup_uuid'], array('status' => Korisec_Backup_Store::STATUS_DELETED));
                    Korisec_Backup_Store::log('BACKUP_DELETED', $old['backup_uuid'], 'Removed by retention policy');
                    $all_verified--;
                    $deleted++;
                }
            }
        }
        return array('deleted' => $deleted, 'done' => true);
    }

    /**
     * Re-check corrupted backups against Google Drive. A backup whose stored files still match
     * what was uploaded (the damage happened during download) becomes restorable again; one that
     * is really damaged is removed from Drive after a grace period so it stops using space.
     *
     * @return array{recovered:int, deleted:int}
     */
    public static function prune_corrupted() {
        $out = array('recovered' => 0, 'deleted' => 0);
        $rows = Korisec_Backup_Store::backups_with_status(Korisec_Backup_Store::STATUS_CORRUPTED);
        $seen = get_option(self::OPTION_CORRUPT_SEEN, array());
        $seen = is_array($seen) ? $seen : array();
        $live = array();
        $provider = self::provider();
        foreach ($rows as $row) {
            $uuid = $row['backup_uuid'];
            $first = isset($seen[$uuid]) ? (int) $seen[$uuid] : time();
            $live[$uuid] = $first;

            $intact = !empty($row['parts']);
            $missing = 0;
            $check_failed = false;
            foreach ($row['parts'] as $p) {
                if (empty($p['remote_id'])) {
                    $intact = false;
                    continue;
                }
                $meta = $provider->get_metadata($p['remote_id']);
                if (is_wp_error($meta)) {
                    if ($meta->get_error_code() === 'gd_missing') {
                        $missing++;
                        $intact = false;
                    } else {
                        $check_failed = true;
                    }
                    continue;
                }
                if ($meta['trashed'] || empty($p['md5']) || $meta['md5'] !== $p['md5'] || $meta['size'] !== (int) $p['size']) {
                    $intact = false;
                }
            }
            if ($check_failed) {
                continue;
            }
            if ($intact) {
                Korisec_Backup_Store::update_backup($uuid, array('status' => Korisec_Backup_Store::STATUS_VERIFIED, 'error_message' => ''));
                Korisec_Backup_Store::log('BACKUP_VERIFIED', $uuid, 'Re-checked in Google Drive: the stored files are intact, so the earlier damage happened during download');
                unset($live[$uuid]);
                $out['recovered']++;
                continue;
            }
            if ($missing === count($row['parts']) || $first < time() - self::CORRUPT_GRACE) {
                $ok = true;
                foreach ($row['parts'] as $p) {
                    if (!empty($p['remote_id']) && is_wp_error($provider->delete($p['remote_id']))) {
                        $ok = false;
                    }
                }
                if ($ok) {
                    Korisec_Backup_Store::update_backup($uuid, array('status' => Korisec_Backup_Store::STATUS_DELETED));
                    Korisec_Backup_Store::log('BACKUP_DELETED', $uuid, 'Corrupted backup removed from Google Drive');
                    unset($live[$uuid]);
                    $out['deleted']++;
                }
            }
        }
        update_option(self::OPTION_CORRUPT_SEEN, $live, false);
        return $out;
    }

    /** @return true|WP_Error */
    public static function delete_backup($uuid) {
        $row = Korisec_Backup_Store::get_backup($uuid);
        if (!$row) {
            return new WP_Error('not_found', __('Backup not found.', 'korisec'));
        }
        if ($row['status'] === Korisec_Backup_Store::STATUS_VERIFIED && count(Korisec_Backup_Store::verified_backups()) <= 1) {
            return new WP_Error('last_backup', __('This is your only verified backup, so it cannot be deleted.', 'korisec'));
        }
        foreach ($row['parts'] as $p) {
            if (!empty($p['remote_id'])) {
                $r = self::provider()->delete($p['remote_id']);
                if (is_wp_error($r)) {
                    return $r;
                }
            }
        }
        Korisec_Backup_Store::update_backup($uuid, array('status' => Korisec_Backup_Store::STATUS_DELETED));
        Korisec_Backup_Store::log('BACKUP_DELETED', $uuid, 'Deleted by an administrator');
        return true;
    }

    /* ------------------------------------------------------ restore engine */

    private static function restore_dir($rid) {
        $dir = Korisec_Backup_Store::workdir();
        return is_wp_error($dir) ? $dir : $dir . '/restore-' . $rid;
    }

    private static function cleanup_restore_files(array $r) {
        $dir = self::restore_dir($r['rid']);
        if (!is_wp_error($dir)) {
            Korisec_Backup_Store::rrmdir($dir);
        }
    }

    private static function run_restore(array &$job, $deadline) {
        $r = &$job['restore'];
        $provider = self::provider();
        $dir = self::restore_dir($r['rid']);
        if (is_wp_error($dir)) {
            return $dir;
        }
        wp_mkdir_p($dir);

        while (microtime(true) < $deadline) {
            if ($r['phase'] !== 'swap' && self::cancelled($job)) {
                return new WP_Error('cancelled', __('Cancelled by an administrator.', 'korisec'));
            }
            switch ($r['phase']) {
                case 'manifest':
                    $job['label'] = __('Reading the backup manifest…', 'korisec');
                    $job['pct'] = 2;
                    $row = Korisec_Backup_Store::get_backup($r['source']);
                    if (!$row || empty($row['remote_manifest_id'])) {
                        return new WP_Error('restore_source', __('That backup is no longer available.', 'korisec'));
                    }
                    $local = $dir . '/manifest.kbackup';
                    $s = $provider->download_step($row['remote_manifest_id'], $local, array(), $deadline + 30);
                    if (is_wp_error($s)) {
                        return $s;
                    }
                    $json = Korisec_Backup_Crypto::decrypt_small_file($local);
                    if (is_wp_error($json)) {
                        return $json;
                    }
                    $m = json_decode($json, true);
                    global $wpdb;
                    if (!is_array($m) || empty($m['database']['tables']) || empty($m['parts']['db'])) {
                        return new WP_Error('restore_manifest', __('The backup manifest is invalid.', 'korisec'));
                    }
                    if ($m['database']['table_prefix'] !== $wpdb->prefix) {
                        /* translators: 1: backup prefix, 2: site prefix */
                        return new WP_Error('restore_prefix', sprintf(__('This backup uses table prefix %1$s but this site uses %2$s. Cross-prefix restores are not supported yet.', 'korisec'), $m['database']['table_prefix'], $wpdb->prefix));
                    }
                    if ($r['include_files'] && empty($m['parts']['files'])) {
                        $r['include_files'] = false;
                    }
                    $r['manifest'] = $m;
                    $r['phase'] = 'safety';
                    break;

                case 'safety':
                    $res = self::run_backup($r['safety'], $deadline, $job, 3, 45);
                    if (is_wp_error($res)) {
                        return $res;
                    }
                    $job['label'] = __('Creating a safety backup of the current site…', 'korisec') . ' ' . $job['label'];
                    if ($res === true) {
                        Korisec_Backup_Store::log('SAFETY_BACKUP_CREATED', $r['safety']['uuid'], 'Verified before restoring ' . $r['source']);
                        $r['dl_queue'] = $r['include_files'] ? array('db', 'files') : array('db');
                        $r['dl_index'] = 0;
                        $r['dl_session'] = array();
                        $r['phase'] = 'download';
                    }
                    break;

                case 'download':
                    while ($r['dl_index'] < count($r['dl_queue']) && microtime(true) < $deadline) {
                        $part = $r['dl_queue'][$r['dl_index']];
                        $info = $r['manifest']['parts'][$part];
                        $local = $dir . '/' . $part . '.kbackup';
                        $done = isset($r['dl_session']['offset']) ? (int) $r['dl_session']['offset'] : 0;
                        /* translators: 1: part, 2: downloaded, 3: total */
                        $job['label'] = sprintf(__('Downloading %1$s from Google Drive (%2$s of %3$s)…', 'korisec'), $part, size_format($done), size_format($info['size']));
                        $job['pct'] = 46 + (int) (14 * (($r['dl_index'] + ($info['size'] ? $done / $info['size'] : 1)) / count($r['dl_queue'])));
                        $s = $provider->download_step($info['remote_id'], $local, $r['dl_session'], $deadline);
                        if (is_wp_error($s)) {
                            return $s;
                        }
                        $r['dl_session'] = $s;
                        if (!empty($s['done'])) {
                            $r['dl_index']++;
                            $r['dl_session'] = array();
                        }
                    }
                    if ($r['dl_index'] >= count($r['dl_queue'])) {
                        $r['phase'] = 'verify_download';
                    }
                    break;

                case 'verify_download':
                    $job['label'] = __('Checking the downloaded backup checksum…', 'korisec');
                    foreach ($r['dl_queue'] as $part) {
                        $local = $dir . '/' . $part . '.kbackup';
                        if (!hash_equals((string) $r['manifest']['parts'][$part]['sha256'], (string) hash_file('sha256', $local))) {
                            Korisec_Backup_Store::update_backup($r['source'], array('status' => Korisec_Backup_Store::STATUS_CORRUPTED, 'error_message' => 'Checksum mismatch on download'));
                            return new WP_Error('backup_corrupt', __('The downloaded backup does not match its checksum. It was marked corrupted.', 'korisec'));
                        }
                    }
                    Korisec_Backup_DB::drop_temp_tables($r['rid']);
                    $r['db_cur'] = Korisec_Backup_DB::restore_init($r['rid'], $r['manifest']['database']['tables']);
                    $rd = Korisec_Backup_Crypto::reader_open($dir . '/db.kbackup');
                    if (is_wp_error($rd)) {
                        return $rd;
                    }
                    $r['db_reader'] = $rd;
                    $r['phase'] = 'db_import';
                    break;

                case 'db_import':
                    $size = max(1, (int) $r['manifest']['parts']['db']['size']);
                    $job['label'] = __('Loading the backup into temporary tables (your site stays live)…', 'korisec');
                    $job['pct'] = 60 + (int) (20 * ($r['db_reader']['offset'] / $size));
                    $res = Korisec_Backup_DB::restore_step($r['db_cur'], $r['db_reader'], $deadline);
                    if (is_wp_error($res)) {
                        return $res;
                    }
                    if ($res === true) {
                        if (empty($r['db_reader']['done'])) {
                            return new WP_Error('backup_corrupt', __('The database backup is truncated.', 'korisec'));
                        }
                        $r['phase'] = 'db_validate';
                    }
                    break;

                case 'db_validate':
                    global $wpdb;
                    $v = Korisec_Backup_DB::validate_temp($r['db_cur'], $wpdb->prefix);
                    if (is_wp_error($v)) {
                        return $v;
                    }
                    $r['validated'] = $v;
                    if ($r['include_files']) {
                        $rd = Korisec_Backup_Crypto::reader_open($dir . '/files.kbackup');
                        if (is_wp_error($rd)) {
                            return $rd;
                        }
                        $r['files_reader'] = $rd;
                        $r['files_cur'] = Korisec_Backup_Files::extract_init($dir . '/staging');
                        $r['phase'] = 'files_extract';
                    } else {
                        $r['phase'] = 'swap';
                    }
                    break;

                case 'files_extract':
                    $size = max(1, (int) $r['manifest']['parts']['files']['size']);
                    /* translators: %s: number of files */
                    $job['label'] = sprintf(__('Unpacking files into a staging folder (%s files)…', 'korisec'), number_format_i18n($r['files_cur']['files']));
                    $job['pct'] = 80 + (int) (15 * ($r['files_reader']['offset'] / $size));
                    $res = Korisec_Backup_Files::extract_step($r['files_cur'], $r['files_reader'], $deadline);
                    if (is_wp_error($res)) {
                        return $res;
                    }
                    if ($res === true) {
                        if (empty($r['files_reader']['done'])) {
                            return new WP_Error('backup_corrupt', __('The files backup is truncated.', 'korisec'));
                        }
                        $r['phase'] = 'swap';
                    }
                    break;

                case 'swap':
                    $job['label'] = __('Switching the site to the restored version…', 'korisec');
                    $job['pct'] = 96;
                    self::save($job);
                    return self::do_swap($job, $dir);

                default:
                    return new WP_Error('restore_state', 'Unknown restore phase.');
            }
        }
        return false;
    }

    /**
     * Atomic switch-over. On any failure the previous database and files are put back.
     *
     * @return true|WP_Error
     */
    private static function do_swap(array &$job, $dir) {
        global $wpdb;
        $r = &$job['restore'];
        $old_siteurl = (string) get_option('siteurl');
        $kept = Korisec_Backup_DB::capture_preserved();
        $db_rec = Korisec_Backup_DB::swap_in($r['rid'], $r['db_cur']);
        if (is_wp_error($db_rec)) {
            return $db_rec;
        }
        Korisec_Backup_DB::apply_preserved($kept);
        // The lock row lived in the options table that was just swapped out.
        self::lock();

        $siteurl = $wpdb->get_var("SELECT option_value FROM {$wpdb->options} WHERE option_name = 'siteurl'"); // phpcs:ignore WordPress.DB
        $users = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->users}"); // phpcs:ignore WordPress.DB
        if (!$siteurl || $users < 1) {
            Korisec_Backup_Store::log('ROLLBACK_STARTED', $r['source'], 'Post-restore validation failed');
            Korisec_Backup_DB::swap_back($db_rec);
            Korisec_Backup_DB::apply_preserved($kept);
            Korisec_Backup_Store::log('ROLLBACK_COMPLETED', $r['source'], 'Original database put back');
            return new WP_Error('restore_validate', __('The restored database failed validation, so the original was put back.', 'korisec'));
        }

        $files_rec = null;
        if ($r['include_files']) {
            $files_rec = Korisec_Backup_Files::swap_in($dir . '/staging', Korisec_Backup_Store::workdir() . '/rollback-' . $r['rid']);
            if (is_wp_error($files_rec)) {
                Korisec_Backup_Store::log('ROLLBACK_STARTED', $r['source'], $files_rec->get_error_message());
                Korisec_Backup_DB::swap_back($db_rec);
                Korisec_Backup_DB::apply_preserved($kept);
                Korisec_Backup_Store::log('ROLLBACK_COMPLETED', $r['source'], 'Original database put back after a file swap error');
                return $files_rec;
            }
            if (function_exists('opcache_reset')) {
                @opcache_reset(); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
            }
        }

        update_option(
            self::OPTION_UNDO,
            array(
                'rid' => $r['rid'],
                'source' => $r['source'],
                'safety' => $r['safety']['uuid'],
                'db' => $db_rec,
                'files' => $files_rec,
                'restored_at' => time(),
                'expires' => time() + self::UNDO_DAYS * DAY_IN_SECONDS,
                'siteurl_changed' => untrailingslashit((string) $siteurl) !== untrailingslashit($old_siteurl),
            ),
            false
        );
        wp_delete_file($dir . '/db.kbackup');
        wp_delete_file($dir . '/files.kbackup');
        wp_delete_file($dir . '/manifest.kbackup');
        Korisec_Backup_Store::rrmdir($dir);
        Korisec_Backup_Store::log('RESTORE_COMPLETED', $r['source'], ($r['include_files'] ? 'Database and files' : 'Database') . ' restored; undo available for ' . self::UNDO_DAYS . ' days');
        $job['label'] = __('Restore complete. You can undo it from this screen.', 'korisec');
        $r['phase'] = 'done';
        return true;
    }

    /** Put the pre-restore database and files back. @return true|WP_Error */
    public static function undo_restore() {
        $u = self::undo_info();
        if (!$u) {
            return new WP_Error('no_undo', __('There is no restore to undo.', 'korisec'));
        }
        if (self::is_running() || !self::lock()) {
            return new WP_Error('backup_busy', __('Wait for the running job to finish first.', 'korisec'));
        }
        $u = self::undo_info();
        if (!$u) {
            self::unlock();
            return new WP_Error('no_undo', __('There is no restore to undo.', 'korisec'));
        }
        Korisec_Backup_Store::log('ROLLBACK_STARTED', $u['source'], 'Undo restore requested');
        $kept = Korisec_Backup_DB::capture_preserved();
        $r = Korisec_Backup_DB::swap_back($u['db']);
        if (is_wp_error($r)) {
            self::unlock();
            return $r;
        }
        Korisec_Backup_DB::apply_preserved($kept);
        if (!empty($u['files'])) {
            Korisec_Backup_Files::swap_back($u['files']);
            Korisec_Backup_Store::rrmdir($u['files']['rollback']);
            if (function_exists('opcache_reset')) {
                @opcache_reset(); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
            }
        }
        delete_option(self::OPTION_UNDO);
        Korisec_Backup_Store::log('ROLLBACK_COMPLETED', $u['source'], 'Site returned to its pre-restore state');
        self::unlock();
        return true;
    }

    /** Accept the restore and free the space held for undo. */
    /** @return true|WP_Error */
    public static function keep_restore() {
        if (!self::undo_info()) {
            return true;
        }
        if (!self::lock()) {
            return new WP_Error('backup_busy', __('Wait for the running job to finish first.', 'korisec'));
        }
        $u = self::undo_info();
        if ($u) {
            Korisec_Backup_DB::drop_old($u['db']);
            if (!empty($u['files']['rollback'])) {
                Korisec_Backup_Store::rrmdir($u['files']['rollback']);
            }
            delete_option(self::OPTION_UNDO);
            Korisec_Backup_Store::log('RESTORE_FINALIZED', $u['source'], 'Undo data removed');
        }
        self::unlock();
        return true;
    }

    public static function schedule_maintenance_soon() {
        wp_schedule_single_event(time() + MINUTE_IN_SECONDS, self::HOOK_MAINT, array('soon'));
    }

    public static function maintenance() {
        $u = self::undo_info();
        if ($u && !empty($u['expires']) && $u['expires'] < time()) {
            self::keep_restore();
        }
        if (!self::is_running() && self::provider()->is_connected()) {
            self::prune_corrupted();
            self::apply_retention(microtime(true) + self::BUDGET);
        }
        if (!self::is_running() && !self::undo_info()) {
            $left = Korisec_Backup_DB::leftover_tables();
            if ($left) {
                Korisec_Backup_DB::drop_tables($left);
            }
            $dir = Korisec_Backup_Store::workdir();
            if (!is_wp_error($dir)) {
                foreach ((array) glob($dir . '/*') as $f) {
                    if (in_array(basename($f), array('index.php', '.htaccess', 'web.config'), true)) {
                        continue;
                    }
                    if (filemtime($f) < time() - DAY_IN_SECONDS) {
                        Korisec_Backup_Store::rrmdir($f);
                    }
                }
            }
        }
    }

    /**
     * Register backups found in Drive (e.g. after reinstalling WordPress).
     *
     * @return array|WP_Error added / locked counts.
     */
    public static function sync_remote() {
        $provider = self::provider();
        $list = $provider->list_manifests();
        if (is_wp_error($list)) {
            return $list;
        }
        $dir = Korisec_Backup_Store::workdir();
        if (is_wp_error($dir)) {
            return $dir;
        }
        $added = 0;
        $locked = 0;
        foreach ($list as $f) {
            $uuid = isset($f['appProperties']['korisec_backup']) ? sanitize_text_field($f['appProperties']['korisec_backup']) : '';
            if ($uuid === '' || !preg_match('/^[a-f0-9-]{36}$/', $uuid) || Korisec_Backup_Store::get_backup($uuid)) {
                continue;
            }
            $tmp = $dir . '/sync-' . md5($f['id']) . '.kbackup';
            $s = $provider->download_step($f['id'], $tmp, array(), microtime(true) + 30);
            if (is_wp_error($s)) {
                continue;
            }
            $json = Korisec_Backup_Crypto::decrypt_small_file($tmp);
            wp_delete_file($tmp);
            if (is_wp_error($json)) {
                $locked++;
                continue;
            }
            $m = json_decode($json, true);
            if (!is_array($m) || ($m['backup_id'] ?? '') !== $uuid || empty($m['parts']['db'])) {
                continue;
            }
            $parts = $m['parts'];
            $parts['manifest'] = array('name' => $f['name'], 'remote_id' => $f['id'], 'size' => (int) $f['size'], 'sha256' => '', 'md5' => '');
            $stored = 0;
            foreach ($parts as $p) {
                $stored += (int) ($p['size'] ?? 0);
            }
            Korisec_Backup_Store::insert_backup(
                array(
                    'backup_uuid' => $uuid,
                    'status' => Korisec_Backup_Store::STATUS_VERIFIED,
                    'backup_type' => in_array($m['type'] ?? '', array('manual', 'scheduled', 'safety'), true) ? $m['type'] : 'manual',
                    'scope' => ($m['scope'] ?? '') === 'full' ? 'full' : 'database',
                    'created_at' => gmdate('Y-m-d H:i:s', strtotime($m['created_at'] ?? 'now')),
                    'completed_at' => gmdate('Y-m-d H:i:s', strtotime($m['created_at'] ?? 'now')),
                    'site_host' => sanitize_text_field($m['site_host'] ?? ''),
                    'table_prefix' => sanitize_text_field($m['database']['table_prefix'] ?? ''),
                    'table_count' => (int) ($m['database']['table_count'] ?? 0),
                    'row_count' => (int) ($m['database']['row_count'] ?? 0),
                    'file_count' => (int) ($m['files']['count'] ?? 0),
                    'db_size' => (int) ($parts['db']['plain_bytes'] ?? 0),
                    'files_size' => (int) ($parts['files']['plain_bytes'] ?? 0),
                    'stored_size' => $stored,
                    'key_id' => sanitize_text_field($m['encryption']['key_id'] ?? ''),
                    'provider' => 'gdrive',
                    'remote_manifest_id' => $f['id'],
                    'parts' => $parts,
                    'created_by' => 0,
                )
            );
            Korisec_Backup_Store::log('BACKUP_IMPORTED', $uuid, 'Found in Google Drive');
            $added++;
        }
        return array('added' => $added, 'locked' => $locked);
    }
}
