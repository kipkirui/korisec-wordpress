<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Backup metadata (own tables, not wp_options), audit events, settings, and the
 * protected local working folder.
 */
class Korisec_Backup_Store {
    const DB_VERSION = '1';
    const OPTION_DB_VERSION = 'korisec_backup_db_version';
    const OPTION_SETTINGS = 'korisec_backup_settings';
    const OPTION_WORKDIR = 'korisec_backup_workdir';

    const STATUS_CREATING = 'CREATING';
    const STATUS_UPLOADING = 'UPLOADING';
    const STATUS_REMOTE_VERIFYING = 'REMOTE_VERIFYING';
    const STATUS_VERIFIED = 'VERIFIED';
    const STATUS_FAILED = 'FAILED';
    const STATUS_CORRUPTED = 'CORRUPTED';
    const STATUS_DELETED = 'DELETED';

    public static function backups_table() {
        global $wpdb;
        return $wpdb->prefix . 'korisec_backups';
    }

    public static function events_table() {
        global $wpdb;
        return $wpdb->prefix . 'korisec_backup_events';
    }

    /** Tables that must never be dumped or replaced by a restore. */
    public static function own_tables() {
        return array(self::backups_table(), self::events_table());
    }

    public static function maybe_install() {
        if (get_option(self::OPTION_DB_VERSION) === self::DB_VERSION) {
            return;
        }
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();
        $backups = self::backups_table();
        $events = self::events_table();
        dbDelta(
            "CREATE TABLE {$backups} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  backup_uuid varchar(36) NOT NULL,
  status varchar(20) NOT NULL,
  backup_type varchar(20) NOT NULL,
  scope varchar(20) NOT NULL,
  created_at datetime NOT NULL,
  completed_at datetime NULL,
  site_host varchar(253) NOT NULL DEFAULT '',
  table_prefix varchar(64) NOT NULL DEFAULT '',
  table_count int(10) unsigned NOT NULL DEFAULT 0,
  row_count bigint(20) unsigned NOT NULL DEFAULT 0,
  file_count int(10) unsigned NOT NULL DEFAULT 0,
  db_size bigint(20) unsigned NOT NULL DEFAULT 0,
  files_size bigint(20) unsigned NOT NULL DEFAULT 0,
  stored_size bigint(20) unsigned NOT NULL DEFAULT 0,
  key_id varchar(16) NOT NULL DEFAULT '',
  format_version smallint(5) unsigned NOT NULL DEFAULT 1,
  provider varchar(20) NOT NULL DEFAULT '',
  remote_manifest_id varchar(128) NOT NULL DEFAULT '',
  parts longtext NULL,
  error_message text NULL,
  created_by bigint(20) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY  (id),
  UNIQUE KEY backup_uuid (backup_uuid),
  KEY status (status),
  KEY created_at (created_at)
) {$charset};"
        );
        dbDelta(
            "CREATE TABLE {$events} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  created_at datetime NOT NULL,
  event varchar(40) NOT NULL,
  backup_uuid varchar(36) NOT NULL DEFAULT '',
  user_id bigint(20) unsigned NOT NULL DEFAULT 0,
  message text NULL,
  PRIMARY KEY  (id),
  KEY created_at (created_at)
) {$charset};"
        );
        update_option(self::OPTION_DB_VERSION, self::DB_VERSION, false);
    }

    /* ----------------------------- settings ----------------------------- */

    public static function settings() {
        $defaults = array(
            'schedule' => 'daily',
            'hour' => 2,
            'scope' => 'full',
            'include_uploads' => true,
            'retention' => 14,
            'all_tables' => false,
            'notify_failures' => true,
        );
        $stored = get_option(self::OPTION_SETTINGS, array());
        $out = array_merge($defaults, is_array($stored) ? $stored : array());
        $out['schedule'] = in_array($out['schedule'], array('off', 'daily', 'weekly'), true) ? $out['schedule'] : 'daily';
        $out['hour'] = max(0, min(23, (int) $out['hour']));
        $out['scope'] = in_array($out['scope'], array('full', 'database'), true) ? $out['scope'] : 'full';
        $out['include_uploads'] = !empty($out['include_uploads']);
        $out['retention'] = max(1, min(90, (int) $out['retention']));
        $out['all_tables'] = !empty($out['all_tables']);
        $out['notify_failures'] = !empty($out['notify_failures']);
        return $out;
    }

    public static function save_settings($input) {
        $current = self::settings();
        $merged = array_merge($current, is_array($input) ? $input : array());
        update_option(self::OPTION_SETTINGS, $merged, false);
        return self::settings();
    }

    /* ----------------------------- work dir ----------------------------- */

    /**
     * Protected scratch folder inside wp-content with an unguessable name.
     * Everything written here is encrypted, except restore staging (site files).
     *
     * @return string|WP_Error
     */
    public static function workdir() {
        $name = get_option(self::OPTION_WORKDIR, '');
        if (!is_string($name) || !preg_match('/^korisec-backups-[a-f0-9]{16}$/', $name)) {
            $name = 'korisec-backups-' . bin2hex(random_bytes(8));
            update_option(self::OPTION_WORKDIR, $name, false);
        }
        $dir = trailingslashit(WP_CONTENT_DIR) . $name;
        if (!is_dir($dir) && !wp_mkdir_p($dir)) {
            return new WP_Error('backup_workdir', __('Could not create the backup working folder in wp-content. Check folder permissions.', 'korisec'));
        }
        $guards = array(
            'index.php' => "<?php\n// Silence is golden.\n",
            '.htaccess' => "Require all denied\nDeny from all\n",
            'web.config' => "<?xml version=\"1.0\"?>\n<configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n",
        );
        foreach ($guards as $file => $contents) {
            if (!file_exists($dir . '/' . $file)) {
                file_put_contents($dir . '/' . $file, $contents);
            }
        }
        return $dir;
    }

    public static function workdir_name() {
        $name = get_option(self::OPTION_WORKDIR, '');
        return is_string($name) ? $name : '';
    }

    public static function rrmdir($dir) {
        if (!is_dir($dir) || is_link($dir)) {
            if (is_file($dir) || is_link($dir)) {
                wp_delete_file($dir);
            }
            return;
        }
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $item) {
            $path = $item->getPathname();
            if ($item->isDir() && !$item->isLink()) {
                rmdir($path); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
            } else {
                unlink($path); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
            }
        }
        rmdir($dir); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
    }

    /* ----------------------------- backups ------------------------------ */

    public static function uuid() {
        return wp_generate_uuid4();
    }

    public static function insert_backup(array $row) {
        global $wpdb;
        $row = array_merge(
            array(
                'status' => self::STATUS_CREATING,
                'created_at' => gmdate('Y-m-d H:i:s'),
                'site_host' => self::site_host(),
                'table_prefix' => $wpdb->prefix,
                'created_by' => get_current_user_id(),
            ),
            $row
        );
        if (isset($row['parts']) && is_array($row['parts'])) {
            $row['parts'] = wp_json_encode($row['parts']);
        }
        $wpdb->insert(self::backups_table(), $row); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        return (int) $wpdb->insert_id;
    }

    public static function update_backup($uuid, array $fields) {
        global $wpdb;
        if (isset($fields['parts']) && is_array($fields['parts'])) {
            $fields['parts'] = wp_json_encode($fields['parts']);
        }
        $wpdb->update(self::backups_table(), $fields, array('backup_uuid' => $uuid)); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
    }

    public static function get_backup($uuid) {
        global $wpdb;
        $table = self::backups_table();
        $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE backup_uuid = %s", $uuid), ARRAY_A); // phpcs:ignore WordPress.DB
        return $row ? self::hydrate($row) : null;
    }

    public static function list_backups($limit = 50) {
        global $wpdb;
        $table = self::backups_table();
        $rows = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$table} WHERE status <> %s ORDER BY created_at DESC, id DESC LIMIT %d", self::STATUS_DELETED, (int) $limit), ARRAY_A); // phpcs:ignore WordPress.DB
        return array_map(array(__CLASS__, 'hydrate'), $rows ? $rows : array());
    }

    public static function verified_backups($types = null) {
        global $wpdb;
        $table = self::backups_table();
        $rows = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$table} WHERE status = %s ORDER BY created_at DESC, id DESC", self::STATUS_VERIFIED), ARRAY_A); // phpcs:ignore WordPress.DB
        $rows = array_map(array(__CLASS__, 'hydrate'), $rows ? $rows : array());
        if ($types !== null) {
            $rows = array_values(array_filter($rows, function ($r) use ($types) {
                return in_array($r['backup_type'], (array) $types, true);
            }));
        }
        return $rows;
    }

    public static function backups_with_status($status) {
        global $wpdb;
        $table = self::backups_table();
        $rows = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$table} WHERE status = %s ORDER BY created_at ASC, id ASC", $status), ARRAY_A); // phpcs:ignore WordPress.DB
        return array_map(array(__CLASS__, 'hydrate'), $rows ? $rows : array());
    }

    public static function last_failed_since($ts) {
        global $wpdb;
        $table = self::backups_table();
        $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE status = %s AND created_at >= %s ORDER BY created_at DESC LIMIT 1", self::STATUS_FAILED, gmdate('Y-m-d H:i:s', $ts)), ARRAY_A); // phpcs:ignore WordPress.DB
        return $row ? self::hydrate($row) : null;
    }

    private static function hydrate($row) {
        $row['parts'] = !empty($row['parts']) ? json_decode($row['parts'], true) : array();
        if (!is_array($row['parts'])) {
            $row['parts'] = array();
        }
        foreach (array('id', 'table_count', 'row_count', 'file_count', 'db_size', 'files_size', 'stored_size', 'created_by') as $int) {
            $row[$int] = isset($row[$int]) ? (int) $row[$int] : 0;
        }
        return $row;
    }

    public static function site_host() {
        $host = wp_parse_url(home_url(), PHP_URL_HOST);
        return $host ? strtolower($host) : 'wordpress';
    }

    /* ------------------------------ audit ------------------------------- */

    /** Audit log. Never pass secrets in $message. */
    public static function log($event, $uuid = '', $message = '') {
        global $wpdb;
        $wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
            self::events_table(),
            array(
                'created_at' => gmdate('Y-m-d H:i:s'),
                'event' => substr((string) $event, 0, 40),
                'backup_uuid' => (string) $uuid,
                'user_id' => get_current_user_id(),
                'message' => substr((string) $message, 0, 1000),
            )
        );
    }

    public static function recent_events($limit = 30) {
        global $wpdb;
        $table = self::events_table();
        $rows = $wpdb->get_results($wpdb->prepare("SELECT created_at, event, backup_uuid, message FROM {$table} ORDER BY id DESC LIMIT %d", (int) $limit), ARRAY_A); // phpcs:ignore WordPress.DB
        return $rows ? $rows : array();
    }
}
