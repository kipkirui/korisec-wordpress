<?php

if (!defined('ABSPATH')) {
    exit;
}

class Korisec_Inventory {
    public static function collect() {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $plugin_updates = get_site_transient('update_plugins');
        $theme_updates = get_site_transient('update_themes');

        $plugins = array();
        foreach (get_plugins() as $file => $data) {
            $slug = dirname($file);
            if ('.' === $slug) {
                $slug = basename($file, '.php');
            }
            $new_version = '';
            if (is_object($plugin_updates) && !empty($plugin_updates->response[$file]->new_version)) {
                $new_version = (string) $plugin_updates->response[$file]->new_version;
            }
            $plugins[] = array(
                'slug' => $slug,
                'name' => isset($data['Name']) ? $data['Name'] : $slug,
                'version' => isset($data['Version']) ? $data['Version'] : '',
                'active' => is_plugin_active($file),
                'network' => is_multisite() && is_plugin_active_for_network($file),
                'file' => $file,
                'update_available' => $new_version !== '',
                'new_version' => $new_version !== '' ? $new_version : null,
            );
        }

        $themes = array();
        $active = get_stylesheet();
        foreach (wp_get_themes() as $stylesheet => $theme) {
            $new_version = '';
            if (is_object($theme_updates) && !empty($theme_updates->response[$stylesheet]['new_version'])) {
                $new_version = (string) $theme_updates->response[$stylesheet]['new_version'];
            } elseif (is_object($theme_updates) && !empty($theme_updates->response[$stylesheet]) && is_object($theme_updates->response[$stylesheet]) && !empty($theme_updates->response[$stylesheet]->new_version)) {
                $new_version = (string) $theme_updates->response[$stylesheet]->new_version;
            }
            $themes[] = array(
                'slug' => $stylesheet,
                'name' => $theme->get('Name'),
                'version' => $theme->get('Version'),
                'active' => ($stylesheet === $active),
                'stylesheet' => $stylesheet,
                'update_available' => $new_version !== '',
                'new_version' => $new_version !== '' ? $new_version : null,
            );
        }

        $must_use = array();
        if (function_exists('get_mu_plugins')) {
            foreach (get_mu_plugins() as $file => $data) {
                $must_use[] = array(
                    'slug' => basename($file, '.php'),
                    'name' => isset($data['Name']) ? $data['Name'] : basename($file),
                    'version' => isset($data['Version']) ? $data['Version'] : '',
                    'active' => true,
                    'file' => $file,
                );
            }
        }

        $dropins = array();
        if (function_exists('get_dropins')) {
            foreach (get_dropins() as $file => $data) {
                $dropins[] = array(
                    'slug' => basename($file, '.php'),
                    'name' => isset($data['Name']) ? $data['Name'] : $file,
                    'version' => isset($data['Version']) ? $data['Version'] : '',
                    'active' => true,
                    'file' => $file,
                );
            }
        }

        return array(
            'core' => array(
                'version' => get_bloginfo('version'),
                'locale' => get_locale(),
            ),
            'php_version' => PHP_VERSION,
            'plugins' => $plugins,
            'themes' => $themes,
            'must_use' => $must_use,
            'dropins' => $dropins,
        );
    }

    /**
     * Local update actions for the Actions tab (URLs include nonces).
     *
     * @return array{plugins:array<int,array>,themes:array<int,array>,core:array|null}
     */
    public static function local_update_actions() {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        if (!current_user_can('update_plugins') && !current_user_can('update_themes') && !current_user_can('update_core')) {
            return array(
                'plugins' => array(),
                'themes' => array(),
                'core' => null,
            );
        }

        $plugin_updates = get_site_transient('update_plugins');
        $theme_updates = get_site_transient('update_themes');
        $core_updates = get_site_transient('update_core');
        $all_plugins = get_plugins();

        $plugins = array();
        if (current_user_can('update_plugins') && is_object($plugin_updates) && !empty($plugin_updates->response) && is_array($plugin_updates->response)) {
            foreach ($plugin_updates->response as $file => $info) {
                if (!isset($all_plugins[$file])) {
                    continue;
                }
                $slug = dirname($file);
                if ('.' === $slug) {
                    $slug = basename($file, '.php');
                }
                $new_version = !empty($info->new_version) ? (string) $info->new_version : '';
                $plugins[] = array(
                    'type' => 'plugin',
                    'slug' => $slug,
                    'file' => $file,
                    'name' => isset($all_plugins[$file]['Name']) ? $all_plugins[$file]['Name'] : $slug,
                    'version' => isset($all_plugins[$file]['Version']) ? $all_plugins[$file]['Version'] : '',
                    'new_version' => $new_version,
                    // Raw URL for JS (do not use wp_nonce_url — it esc_html()'s &amp;).
                    'update_url' => self::plugin_upgrade_url($file),
                    'list_url' => self_admin_url('plugins.php?plugin_status=upgrade'),
                );
            }
        }

        $themes = array();
        if (current_user_can('update_themes') && is_object($theme_updates) && !empty($theme_updates->response) && is_array($theme_updates->response)) {
            foreach ($theme_updates->response as $stylesheet => $info) {
                $theme = wp_get_theme($stylesheet);
                if (!$theme->exists()) {
                    continue;
                }
                $new_version = '';
                if (is_array($info) && !empty($info['new_version'])) {
                    $new_version = (string) $info['new_version'];
                } elseif (is_object($info) && !empty($info->new_version)) {
                    $new_version = (string) $info->new_version;
                }
                $themes[] = array(
                    'type' => 'theme',
                    'slug' => $stylesheet,
                    'stylesheet' => $stylesheet,
                    'name' => $theme->get('Name'),
                    'version' => $theme->get('Version'),
                    'new_version' => $new_version,
                    'update_url' => self::theme_upgrade_url($stylesheet),
                    'list_url' => self_admin_url('themes.php'),
                );
            }
        }

        $core = null;
        if (current_user_can('update_core') && !empty($core_updates->updates) && is_array($core_updates->updates)) {
            foreach ($core_updates->updates as $update) {
                if (!is_object($update) || empty($update->response) || $update->response === 'latest') {
                    continue;
                }
                $core = array(
                    'type' => 'core',
                    'name' => 'WordPress',
                    'version' => get_bloginfo('version'),
                    'new_version' => !empty($update->version) ? (string) $update->version : '',
                    'update_url' => self_admin_url('update-core.php'),
                    'list_url' => self_admin_url('update-core.php'),
                );
                break;
            }
        }

        return array(
            'plugins' => $plugins,
            'themes' => $themes,
            'core' => $core,
        );
    }

    /**
     * Map slug/file → upgrade URL for finding action buttons.
     *
     * @return array{plugins:array<string,string>,themes:array<string,string>,core:string}
     */
    public static function update_url_map() {
        $actions = self::local_update_actions();
        $plugins = array();
        foreach ($actions['plugins'] as $row) {
            if (!empty($row['slug']) && !empty($row['update_url'])) {
                $plugins[$row['slug']] = $row['update_url'];
            }
            if (!empty($row['file']) && !empty($row['update_url'])) {
                $plugins[$row['file']] = $row['update_url'];
            }
        }
        $themes = array();
        foreach ($actions['themes'] as $row) {
            if (!empty($row['slug']) && !empty($row['update_url'])) {
                $themes[$row['slug']] = $row['update_url'];
            }
        }
        return array(
            'plugins' => $plugins,
            'themes' => $themes,
            'core' => self_admin_url('update-core.php'),
        );
    }

    /**
     * One-click plugin upgrade URL for JS (unescaped — wp_nonce_url HTML-encodes &).
     *
     * @param string $file Plugin basename (e.g. akismet/akismet.php).
     * @return string
     */
    public static function plugin_upgrade_url($file) {
        return add_query_arg(
            array(
                'action' => 'upgrade-plugin',
                'plugin' => $file,
                '_wpnonce' => wp_create_nonce('upgrade-plugin_' . $file),
            ),
            self_admin_url('update.php')
        );
    }

    /**
     * One-click theme upgrade URL for JS (unescaped).
     *
     * @param string $stylesheet Theme stylesheet slug.
     * @return string
     */
    public static function theme_upgrade_url($stylesheet) {
        return add_query_arg(
            array(
                'action' => 'upgrade-theme',
                'theme' => $stylesheet,
                '_wpnonce' => wp_create_nonce('upgrade-theme_' . $stylesheet),
            ),
            self_admin_url('update.php')
        );
    }

    public static function post() {
        $payload = self::collect();
        $result = Korisec_API::request('POST', '/api/v1/plugin/inventory', $payload, 15);
        return Korisec_API::apply_auth_failure($result);
    }
}
