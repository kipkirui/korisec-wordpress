<?php
/**
 * Plugin Name: Korisec Security – Vulnerability Scanner and Login Protection
 * Plugin URI: https://korisec.com/wordpress/
 * Description: Hosted WordPress security checks with plain-English fixes, CVE-aware findings, and local login attempt limiting. Scans run in Korisec’s cloud.
 * Version: 1.0.12
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

define('KORISEC_VERSION', '1.0.12');
define('KORISEC_PLUGIN_FILE', __FILE__);
define('KORISEC_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('KORISEC_PLUGIN_URL', plugin_dir_url(__FILE__));

require_once KORISEC_PLUGIN_DIR . 'includes/class-korisec-api.php';
require_once KORISEC_PLUGIN_DIR . 'includes/class-korisec-inventory.php';
require_once KORISEC_PLUGIN_DIR . 'includes/class-korisec-cron.php';
require_once KORISEC_PLUGIN_DIR . 'includes/class-korisec-admin.php';
require_once KORISEC_PLUGIN_DIR . 'includes/class-korisec-privacy.php';
require_once KORISEC_PLUGIN_DIR . 'includes/class-korisec-login.php';
require_once KORISEC_PLUGIN_DIR . 'includes/class-korisec-hardening.php';

register_activation_hook(__FILE__, array('Korisec_Cron', 'activate'));
register_deactivation_hook(__FILE__, array('Korisec_Cron', 'deactivate'));

add_action(
    'plugins_loaded',
    function () {
        Korisec_API::init();
        Korisec_Admin::init();
        Korisec_Cron::init();
        Korisec_Privacy::init();
        Korisec_Login::init();
        Korisec_Hardening::init();
    }
);
