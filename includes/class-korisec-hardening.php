<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Local hardening remedies applied from the Actions / Protection UI.
 * Nothing here is sent to Korisec — it only changes this WordPress site.
 */
class Korisec_Hardening {
    const OPTION = 'korisec_hardening';

    public static function init() {
        $settings = self::settings();
        if (!empty($settings['disable_xmlrpc'])) {
            add_filter('xmlrpc_enabled', '__return_false');
        }
        if (!empty($settings['block_user_enumeration'])) {
            add_filter('rest_endpoints', array(__CLASS__, 'filter_rest_endpoints'));
            add_action('init', array(__CLASS__, 'block_author_query'), 0);
            add_action('template_redirect', array(__CLASS__, 'block_author_archive'));
        }
        if (!empty($settings['block_install_php'])) {
            add_action('init', array(__CLASS__, 'block_install_php'), 0);
        }
    }

    /**
     * @return array{disable_xmlrpc:bool,block_user_enumeration:bool,block_install_php:bool}
     */
    public static function settings() {
        $defaults = array(
            'disable_xmlrpc' => false,
            'block_user_enumeration' => false,
            'block_install_php' => false,
        );
        $stored = get_option(self::OPTION, array());
        if (!is_array($stored)) {
            $stored = array();
        }
        $out = array_merge($defaults, $stored);
        $out['disable_xmlrpc'] = !empty($out['disable_xmlrpc']);
        $out['block_user_enumeration'] = !empty($out['block_user_enumeration']);
        $out['block_install_php'] = !empty($out['block_install_php']);
        return $out;
    }

    /**
     * @param array $input Raw settings.
     * @return array{disable_xmlrpc:bool,block_user_enumeration:bool,block_install_php:bool}
     */
    public static function save_settings($input) {
        if (!is_array($input)) {
            $input = array();
        }
        $settings = array(
            'disable_xmlrpc' => !empty($input['disable_xmlrpc']),
            'block_user_enumeration' => !empty($input['block_user_enumeration']),
            'block_install_php' => !empty($input['block_install_php']),
        );
        update_option(self::OPTION, $settings, false);
        return $settings;
    }

    /**
     * Enable a single remedy key from the Actions tab.
     *
     * @param string $remedy Remedy id.
     * @return array|WP_Error
     */
    public static function apply_remedy($remedy) {
        $map = array(
            'disable_xmlrpc' => 'disable_xmlrpc',
            'block_user_enumeration' => 'block_user_enumeration',
            'block_install_php' => 'block_install_php',
        );
        if (!isset($map[$remedy])) {
            return new WP_Error('invalid_remedy', __('Unknown remedy.', 'korisec'));
        }
        $settings = self::settings();
        $settings[$map[$remedy]] = true;
        return self::save_settings($settings);
    }

    /**
     * @param array $endpoints REST endpoints.
     * @return array
     */
    public static function filter_rest_endpoints($endpoints) {
        if (!is_array($endpoints)) {
            return $endpoints;
        }
        unset($endpoints['/wp/v2/users']);
        unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        return $endpoints;
    }

    public static function block_author_query() {
        if (is_admin()) {
            return;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- public request hardening
        if (!isset($_GET['author'])) {
            return;
        }
        if (is_user_logged_in() && current_user_can('list_users')) {
            return;
        }
        wp_safe_redirect(home_url('/'), 301);
        exit;
    }

    public static function block_author_archive() {
        if (!is_author()) {
            return;
        }
        if (is_user_logged_in() && current_user_can('list_users')) {
            return;
        }
        wp_safe_redirect(home_url('/'), 301);
        exit;
    }

    public static function block_install_php() {
        if (defined('WP_INSTALLING') && WP_INSTALLING) {
            return;
        }
        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        if ($uri === '' || stripos($uri, 'wp-admin/install.php') === false) {
            return;
        }
        status_header(403);
        nocache_headers();
        wp_die(
            esc_html__('Access to the WordPress installer is blocked by Korisec.', 'korisec'),
            esc_html__('Forbidden', 'korisec'),
            array('response' => 403)
        );
    }

    /**
     * Catalog of remedies for the Actions UI.
     *
     * @return array<string,array{id:string,title:string,description:string,enabled:bool}>
     */
    public static function remedy_catalog() {
        $settings = self::settings();
        return array(
            'disable_xmlrpc' => array(
                'id' => 'disable_xmlrpc',
                'title' => __('Disable XML-RPC', 'korisec'),
                'description' => __('Turns off xmlrpc.php. Keep this off if Jetpack or the WordPress mobile app needs XML-RPC.', 'korisec'),
                'enabled' => !empty($settings['disable_xmlrpc']),
            ),
            'block_user_enumeration' => array(
                'id' => 'block_user_enumeration',
                'title' => __('Hide public usernames', 'korisec'),
                'description' => __('Blocks anonymous REST /wp/v2/users and ?author= redirects that leak login names.', 'korisec'),
                'enabled' => !empty($settings['block_user_enumeration']),
            ),
            'block_install_php' => array(
                'id' => 'block_install_php',
                'title' => __('Block wp-admin/install.php', 'korisec'),
                'description' => __('Returns 403 for the installer script once WordPress is already set up.', 'korisec'),
                'enabled' => !empty($settings['block_install_php']),
            ),
        );
    }
}
