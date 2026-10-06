<?php
/**
 * Remove stored plugin key and state when the plugin is deleted.
 *
 * The backup key ring (korisec_backup_keyring) is intentionally kept: it is
 * encrypted with this site's salts and is the only way to read the backups that
 * remain in Google Drive if the plugin is reinstalled without the recovery key.
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

delete_option('korisec_license_key');
delete_option('korisec_state');
delete_option('korisec_pin_origin');
delete_option('korisec_login_protection');
delete_option('korisec_hardening');

delete_option('korisec_gdrive');
delete_option('korisec_backup_settings');
delete_option('korisec_backup_job');
delete_option('korisec_backup_undo');
delete_option('korisec_backup_cancel');
delete_option('korisec_backup_corrupt_seen');
delete_option('korisec_cron_health');
delete_option('korisec_cron_seen');
delete_transient('korisec_cron_activation_notice');
delete_option('korisec_backup_db_version');
delete_transient('korisec_gd_access');
wp_clear_scheduled_hook('korisec_backup_tick');
wp_clear_scheduled_hook('korisec_backup_scheduled');
wp_clear_scheduled_hook('korisec_backup_maint');
wp_clear_scheduled_hook('korisec_cron_ping');
wp_unschedule_hook('korisec_cron_probe');

global $wpdb;
$korisec_tables = array($wpdb->prefix . 'korisec_backups', $wpdb->prefix . 'korisec_backup_events');
foreach ($korisec_tables as $korisec_table) {
    $wpdb->query('DROP TABLE IF EXISTS `' . str_replace('`', '', $korisec_table) . '`'); // phpcs:ignore WordPress.DB
}

$korisec_workdir = get_option('korisec_backup_workdir', '');
if (is_string($korisec_workdir) && preg_match('/^korisec-backups-[a-f0-9]{16}$/', $korisec_workdir)) {
    $korisec_path = trailingslashit(WP_CONTENT_DIR) . $korisec_workdir;
    if (is_dir($korisec_path)) {
        $korisec_it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($korisec_path, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($korisec_it as $korisec_item) {
            if ($korisec_item->isDir() && !$korisec_item->isLink()) {
                rmdir($korisec_item->getPathname()); // phpcs:ignore WordPress.WP.AlternativeFunctions
            } else {
                unlink($korisec_item->getPathname()); // phpcs:ignore WordPress.WP.AlternativeFunctions
            }
        }
        rmdir($korisec_path); // phpcs:ignore WordPress.WP.AlternativeFunctions
    }
}
delete_option('korisec_backup_workdir');
