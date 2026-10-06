<?php
/**
 * Plugin Name: Korisec Security – Vulnerability Scanner, Login Protection and Backup
 * Plugin URI: https://korisec.com/wordpress/
 * Description: Hosted WordPress security checks with plain-English fixes, CVE-aware findings, local login attempt limiting, and free encrypted Google Drive backups with one-click rollback.
 * Version: 1.1.1
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: Korisec
 * Author URI: https://korisec.com
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: korisec
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) {
    exit;
}

define('KORISEC_VERSION', '1.1.1');
define('KORISEC_PLUGIN_FILE', __FILE__);
define('KORISEC_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('KORISEC_PLUGIN_URL', plugin_dir_url(__FILE__));

require_once KORISEC_PLUGIN_DIR . 'includes/class-korisec-api.php';
require_once KORISEC_PLUGIN_DIR . 'includes/class-korisec-inventory.php';
require_once KORISEC_PLUGIN_DIR . 'includes/class-korisec-cron.php';
require_once KORISEC_PLUGIN_DIR . 'includes/class-korisec-cron-health.php';
require_once KORISEC_PLUGIN_DIR . 'includes/class-korisec-admin.php';
require_once KORISEC_PLUGIN_DIR . 'includes/class-korisec-privacy.php';
require_once KORISEC_PLUGIN_DIR . 'includes/class-korisec-login.php';
require_once KORISEC_PLUGIN_DIR . 'includes/class-korisec-hardening.php';
require_once KORISEC_PLUGIN_DIR . 'includes/backup/interface-korisec-storage-provider.php';
require_once KORISEC_PLUGIN_DIR . 'includes/backup/class-korisec-backup-crypto.php';
require_once KORISEC_PLUGIN_DIR . 'includes/backup/class-korisec-backup-store.php';
require_once KORISEC_PLUGIN_DIR . 'includes/backup/class-korisec-gdrive.php';
require_once KORISEC_PLUGIN_DIR . 'includes/backup/class-korisec-backup-db.php';
require_once KORISEC_PLUGIN_DIR . 'includes/backup/class-korisec-backup-files.php';
require_once KORISEC_PLUGIN_DIR . 'includes/backup/class-korisec-backup-jobs.php';
require_once KORISEC_PLUGIN_DIR . 'includes/backup/class-korisec-backup-admin.php';

register_activation_hook(
    __FILE__,
    function () {
        Korisec_Cron::activate();
        Korisec_Backup_Store::maybe_install();
        Korisec_Cron_Health::activate();
    }
);
register_deactivation_hook(
    __FILE__,
    function () {
        Korisec_Cron::deactivate();
        Korisec_Backup_Jobs::deactivate();
        Korisec_Cron_Health::deactivate();
    }
);

add_action(
    'plugins_loaded',
    function () {
        Korisec_API::init();
        Korisec_Admin::init();
        Korisec_Cron::init();
        Korisec_Cron_Health::init();
        Korisec_Privacy::init();
        Korisec_Login::init();
        Korisec_Hardening::init();
        Korisec_Backup_Jobs::init();
        if (is_admin()) {
            Korisec_Backup_Admin::init();
        }
    }
);
