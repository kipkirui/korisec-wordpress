<?php
/**
 * Remove stored plugin key and state when the plugin is deleted.
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

delete_option('korisec_license_key');
delete_option('korisec_state');
delete_option('korisec_pin_origin');
delete_option('korisec_login_protection');
delete_option('korisec_hardening');
