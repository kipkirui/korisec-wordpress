<?php

if (!defined('ABSPATH')) {
    exit;
}

class Korisec_Admin {
    public static function init() {
        add_action('admin_menu', array(__CLASS__, 'menu'));
        add_action('admin_enqueue_scripts', array(__CLASS__, 'assets'));
        add_action('wp_ajax_korisec_connect', array(__CLASS__, 'ajax_connect'));
        add_action('wp_ajax_korisec_disconnect', array(__CLASS__, 'ajax_disconnect'));
        add_action('wp_ajax_korisec_run_check', array(__CLASS__, 'ajax_run_check'));
        add_action('wp_ajax_korisec_scan_status', array(__CLASS__, 'ajax_scan_status'));
        add_action('wp_ajax_korisec_dashboard', array(__CLASS__, 'ajax_dashboard'));
        add_action('wp_ajax_korisec_account', array(__CLASS__, 'ajax_account'));
        add_action('wp_ajax_korisec_save_login', array(__CLASS__, 'ajax_save_login'));
        add_action('wp_ajax_korisec_save_hardening', array(__CLASS__, 'ajax_save_hardening'));
        add_action('wp_ajax_korisec_apply_remedy', array(__CLASS__, 'ajax_apply_remedy'));
        add_action('admin_post_korisec_pdf', array(__CLASS__, 'download_pdf'));
    }

    public static function menu() {
        add_menu_page(
            __('Korisec', 'korisec'),
            __('Korisec', 'korisec'),
            'manage_options',
            'korisec',
            array(__CLASS__, 'render'),
            'dashicons-shield',
            80
        );
    }

    public static function assets($hook) {
        if ($hook !== 'toplevel_page_korisec') {
            return;
        }
        wp_enqueue_style(
            'korisec-admin',
            KORISEC_PLUGIN_URL . 'assets/admin.css',
            array(),
            KORISEC_VERSION
        );
        wp_enqueue_script(
            'korisec-admin',
            KORISEC_PLUGIN_URL . 'assets/admin.js',
            array(),
            KORISEC_VERSION,
            true
        );
        $state = Korisec_API::get_state();
        wp_localize_script(
            'korisec-admin',
            'korisecAdmin',
            array(
                'ajaxUrl' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('korisec_admin'),
                'dashboardUrl' => 'https://app.korisec.com/dashboard',
                'pluginsUrl' => admin_url('plugins.php'),
                'themesUrl' => admin_url('themes.php'),
                'updatesUrl' => admin_url('update-core.php'),
                'pluginsUpgradeUrl' => admin_url('plugins.php?plugin_status=upgrade'),
                'loginSettings' => Korisec_Login::settings(),
                'localUpdates' => Korisec_Inventory::local_update_actions(),
                'updateUrls' => Korisec_Inventory::update_url_map(),
                'hardening' => Korisec_Hardening::settings(),
                'remedies' => array_values(Korisec_Hardening::remedy_catalog()),
                'connected' => !empty($state['connected']) && Korisec_API::get_key() ? 1 : 0,
                'scanId' => isset($state['last_scan_id']) ? (int) $state['last_scan_id'] : 0,
                'scanStatus' => isset($state['last_scan_status']) ? $state['last_scan_status'] : '',
                'plan' => isset($state['plan']) ? $state['plan'] : '',
                'host' => isset($state['bound_host']) ? $state['bound_host'] : '',
                'pdfUrl' => admin_url('admin-post.php'),
                'i18n' => self::js_i18n(),
            )
        );
    }

    public static function render() {
        if (!current_user_can('manage_options')) {
            return;
        }
        $key = Korisec_API::get_key();
        $state = Korisec_API::get_state();
        $connected = !empty($state['connected']) && $key;
        $prefix = isset($state['key_prefix']) ? $state['key_prefix'] : ($key ? substr($key, 0, 12) : '');
        $error = isset($state['last_error']) ? $state['last_error'] : '';
        $error_code = isset($state['last_error_code']) ? $state['last_error_code'] : '';
        ?>
        <div class="wrap korisec-wrap">
            <div class="korisec-top">
                <div>
                    <h1><?php echo esc_html__('Korisec', 'korisec'); ?></h1>
                    <p class="korisec-lede"><?php echo esc_html__('Cloud checks for this WordPress site. Scans run on Korisec; results stay here.', 'korisec'); ?></p>
                </div>
            </div>
            <?php if ($error) : ?>
                <div class="notice notice-error"><p><?php echo esc_html($error); ?></p>
                    <?php if ($error_code === 'plan_lapsed') : ?>
                        <p><a href="https://app.korisec.com/dashboard" target="_blank" rel="noopener noreferrer"><?php echo esc_html__('Renew the Korisec service account', 'korisec'); ?></a></p>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

            <?php if (!$connected) : ?>
                <div class="korisec-card">
                    <h2><?php echo esc_html__('Connect this site', 'korisec'); ?></h2>
                    <p><?php echo esc_html__('Paste the plugin key from your Korisec account (Account → API keys). Connecting sends this site’s URL and installed plugin list to Korisec so cloud checks can include hidden plugins. Scans run on Korisec, not on this server.', 'korisec'); ?></p>
                    <form id="korisec-connect-form">
                        <p>
                            <label for="korisec-key"><?php echo esc_html__('Plugin key', 'korisec'); ?></label><br>
                            <input class="regular-text" type="password" id="korisec-key" name="key" autocomplete="off" placeholder="kr_live_…">
                        </p>
                        <p>
                            <button type="submit" class="button button-primary" id="korisec-connect"><?php echo esc_html__('Connect', 'korisec'); ?></button>
                        </p>
                    </form>
                    <p class="description">
                        <?php
                        echo wp_kses(
                            sprintf(
                                /* translators: 1: terms of use URL, 2: privacy policy URL */
                                __('By connecting you agree to Korisec’s <a href="%1$s" target="_blank" rel="noopener noreferrer">Terms of Use</a> and <a href="%2$s" target="_blank" rel="noopener noreferrer">Privacy Policy</a>.', 'korisec'),
                                'https://korisec.com/terms.html',
                                'https://korisec.com/privacy.html'
                            ),
                            array(
                                'a' => array(
                                    'href' => array(),
                                    'target' => array(),
                                    'rel' => array(),
                                ),
                            )
                        );
                        ?>
                    </p>
                </div>
                <?php self::render_protection_card(); ?>
            <?php else : ?>
                <div id="korisec-app" class="korisec-app">
                    <nav class="korisec-tabs" role="tablist">
                        <button type="button" class="korisec-tab is-active" data-tab="checks"><?php echo esc_html__('Checks', 'korisec'); ?></button>
                        <button type="button" class="korisec-tab" data-tab="actions"><?php echo esc_html__('Actions', 'korisec'); ?></button>
                        <button type="button" class="korisec-tab" data-tab="protection"><?php echo esc_html__('Protection', 'korisec'); ?></button>
                        <button type="button" class="korisec-tab" data-tab="billing"><?php echo esc_html__('Billing', 'korisec'); ?></button>
                        <button type="button" class="korisec-tab" data-tab="team"><?php echo esc_html__('Team', 'korisec'); ?></button>
                        <button type="button" class="korisec-tab" data-tab="reports"><?php echo esc_html__('Reports', 'korisec'); ?></button>
                        <button type="button" class="korisec-tab" data-tab="alerts"><?php echo esc_html__('Alerts', 'korisec'); ?></button>
                        <button type="button" class="korisec-tab" data-tab="connection"><?php echo esc_html__('Connection', 'korisec'); ?></button>
                    </nav>
                    <p class="korisec-status" id="korisec-status"></p>
                    <div id="korisec-panel-checks" class="korisec-panel is-active">
                        <div id="korisec-hero"></div>
                        <div id="korisec-progress" class="korisec-progress is-hidden"></div>
                        <div id="korisec-findings"></div>
                        <div id="korisec-history"></div>
                    </div>
                    <div id="korisec-panel-actions" class="korisec-panel">
                        <div id="korisec-actions"></div>
                    </div>
                    <div id="korisec-panel-protection" class="korisec-panel">
                        <?php self::render_protection_card(); ?>
                    </div>
                    <div id="korisec-panel-billing" class="korisec-panel" data-loaded="0"></div>
                    <div id="korisec-panel-team" class="korisec-panel" data-loaded="0"></div>
                    <div id="korisec-panel-reports" class="korisec-panel" data-loaded="0"></div>
                    <div id="korisec-panel-alerts" class="korisec-panel" data-loaded="0"></div>
                    <div id="korisec-panel-connection" class="korisec-panel">
                        <div class="korisec-card korisec-settings">
                            <h2><?php echo esc_html__('Connection', 'korisec'); ?></h2>
                            <ul class="korisec-meta">
                                <li><strong><?php echo esc_html__('Key:', 'korisec'); ?></strong> <code><?php echo esc_html($prefix); ?>…</code></li>
                                <li><strong><?php echo esc_html__('Site:', 'korisec'); ?></strong> <?php echo esc_html(isset($state['bound_host']) ? $state['bound_host'] : '—'); ?></li>
                                <li><strong><?php echo esc_html__('Plan:', 'korisec'); ?></strong> <?php echo esc_html(isset($state['plan']) ? $state['plan'] : '—'); ?></li>
                            </ul>
                            <p class="korisec-actions">
                                <button type="button" class="button" id="korisec-disconnect"><?php echo esc_html__('Disconnect', 'korisec'); ?></button>
                            </p>
                            <p class="description"><?php echo esc_html__('This key only acts on the Korisec billing account that issued it. Disconnecting here does not revoke the key. Deleting the plugin removes the stored key from WordPress.', 'korisec'); ?></p>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
        </div>
        <?php
    }

    private static function render_protection_card() {
        $settings = Korisec_Login::settings();
        $hardening = Korisec_Hardening::settings();
        ?>
        <div class="korisec-card korisec-settings" id="korisec-protection-card">
            <h2><?php echo esc_html__('Login protection', 'korisec'); ?></h2>
            <p><?php echo esc_html__('Limits failed wp-login attempts from the same IP. Runs locally in WordPress — nothing is sent to Korisec for this feature.', 'korisec'); ?></p>
            <form id="korisec-login-form">
                <p>
                    <label>
                        <input type="checkbox" name="enabled" id="korisec-login-enabled" value="1" <?php checked(!empty($settings['enabled'])); ?>>
                        <?php echo esc_html__('Enable login attempt limiting', 'korisec'); ?>
                    </label>
                </p>
                <p>
                    <label for="korisec-login-max"><?php echo esc_html__('Failed attempts before lockout', 'korisec'); ?></label><br>
                    <input class="small-text" type="number" min="3" max="20" id="korisec-login-max" name="max_attempts" value="<?php echo esc_attr((string) $settings['max_attempts']); ?>">
                </p>
                <p>
                    <label for="korisec-login-mins"><?php echo esc_html__('Lockout length (minutes)', 'korisec'); ?></label><br>
                    <input class="small-text" type="number" min="5" max="1440" id="korisec-login-mins" name="lockout_minutes" value="<?php echo esc_attr((string) $settings['lockout_minutes']); ?>">
                </p>
                <p class="korisec-actions">
                    <button type="submit" class="button button-primary" id="korisec-login-save"><?php echo esc_html__('Save login settings', 'korisec'); ?></button>
                    <span class="korisec-inline-status" id="korisec-login-status" aria-live="polite"></span>
                </p>
            </form>
        </div>
        <div class="korisec-card korisec-settings" id="korisec-hardening-card">
            <h2><?php echo esc_html__('Exposure remedies', 'korisec'); ?></h2>
            <p><?php echo esc_html__('One-click fixes for common WordPress exposures Korisec finds. Applied only on this site.', 'korisec'); ?></p>
            <form id="korisec-hardening-form">
                <p>
                    <label>
                        <input type="checkbox" name="disable_xmlrpc" id="korisec-disable-xmlrpc" value="1" <?php checked(!empty($hardening['disable_xmlrpc'])); ?>>
                        <?php echo esc_html__('Disable XML-RPC', 'korisec'); ?>
                    </label>
                </p>
                <p class="description"><?php echo esc_html__('Turn this off if Jetpack or the WordPress mobile app needs XML-RPC.', 'korisec'); ?></p>
                <p>
                    <label>
                        <input type="checkbox" name="block_user_enumeration" id="korisec-block-users" value="1" <?php checked(!empty($hardening['block_user_enumeration'])); ?>>
                        <?php echo esc_html__('Hide public usernames', 'korisec'); ?>
                    </label>
                </p>
                <p class="description"><?php echo esc_html__('Blocks anonymous REST user listing and ?author= redirects.', 'korisec'); ?></p>
                <p>
                    <label>
                        <input type="checkbox" name="block_install_php" id="korisec-block-install" value="1" <?php checked(!empty($hardening['block_install_php'])); ?>>
                        <?php echo esc_html__('Block wp-admin/install.php', 'korisec'); ?>
                    </label>
                </p>
                <p class="korisec-actions">
                    <button type="submit" class="button button-primary" id="korisec-hardening-save"><?php echo esc_html__('Save exposure remedies', 'korisec'); ?></button>
                    <span class="korisec-inline-status" id="korisec-hardening-status" aria-live="polite"></span>
                </p>
            </form>
        </div>
        <?php
    }

    public static function ajax_save_login() {
        self::require_ajax();
        check_ajax_referer('korisec_admin', 'nonce');
        $settings = Korisec_Login::save_settings(
            array(
                'enabled' => !empty($_POST['enabled']),
                'max_attempts' => isset($_POST['max_attempts']) ? (int) $_POST['max_attempts'] : 5,
                'lockout_minutes' => isset($_POST['lockout_minutes']) ? (int) $_POST['lockout_minutes'] : 15,
            )
        );
        wp_send_json_success(
            array(
                'message' => __('Login protection settings saved.', 'korisec'),
                'settings' => $settings,
            )
        );
    }

    public static function ajax_save_hardening() {
        self::require_ajax();
        check_ajax_referer('korisec_admin', 'nonce');
        $settings = Korisec_Hardening::save_settings(
            array(
                'disable_xmlrpc' => !empty($_POST['disable_xmlrpc']),
                'block_user_enumeration' => !empty($_POST['block_user_enumeration']),
                'block_install_php' => !empty($_POST['block_install_php']),
            )
        );
        wp_send_json_success(
            array(
                'message' => __('Exposure remedies saved.', 'korisec'),
                'settings' => $settings,
                'remedies' => array_values(Korisec_Hardening::remedy_catalog()),
            )
        );
    }

    public static function ajax_apply_remedy() {
        self::require_ajax();
        check_ajax_referer('korisec_admin', 'nonce');
        $remedy = isset($_POST['remedy']) ? sanitize_key(wp_unslash($_POST['remedy'])) : '';
        $result = Korisec_Hardening::apply_remedy($remedy);
        if (is_wp_error($result)) {
            wp_send_json_error(array('message' => $result->get_error_message()));
        }
        $catalog = Korisec_Hardening::remedy_catalog();
        $title = isset($catalog[$remedy]['title']) ? $catalog[$remedy]['title'] : $remedy;
        wp_send_json_success(
            array(
                /* translators: %s: remedy title */
                'message' => sprintf(__('Applied: %s. Re-run a check to confirm.', 'korisec'), $title),
                'settings' => $result,
                'remedies' => array_values($catalog),
            )
        );
    }

    private static function require_ajax() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('You cannot manage this plugin.', 'korisec')));
        }
    }

    private static function merge_scan_state($state, $scan, $findings = null) {
        if (!is_array($state)) {
            $state = array();
        }
        if (!empty($scan['id'])) {
            $state['last_scan_id'] = (int) $scan['id'];
        }
        if (!empty($scan['status'])) {
            $state['last_scan_status'] = $scan['status'];
        }
        if (!empty($scan['grade'])) {
            $state['last_grade'] = $scan['grade'];
        }
        if (isset($scan['score'])) {
            $state['last_score'] = $scan['score'];
        }
        if ($findings === null && !empty($scan['findings']) && is_array($scan['findings'])) {
            $findings = $scan['findings'];
        }
        if (is_array($findings)) {
            $state['last_findings'] = $findings;
        }
        $state['last_error'] = '';
        return $state;
    }

    public static function ajax_connect() {
        self::require_ajax();
        check_ajax_referer('korisec_admin', 'nonce');
        $key = isset($_POST['korisec_license']) ? sanitize_text_field(wp_unslash($_POST['korisec_license'])) : '';
        if ($key === '' && isset($_POST['key'])) {
            $key = sanitize_text_field(wp_unslash($_POST['key']));
        }
        if (strpos($key, 'kr_live_') !== 0) {
            wp_send_json_error(array('message' => __('Paste a Korisec plugin key that starts with kr_live_.', 'korisec')));
        }

        update_option(Korisec_API::OPTION_KEY, $key, false);

        $validate = Korisec_API::request('POST', '/api/v1/plugin/validate', Korisec_API::site_payload(), 15);
        if (!$validate['ok']) {
            delete_option(Korisec_API::OPTION_KEY);
            wp_send_json_error(
                array(
                    'message' => Korisec_API::human_error($validate),
                    'code' => $validate['code'],
                )
            );
        }

        $data = $validate['data'] ? $validate['data'] : array();
        $state = array(
            'connected' => true,
            'plan' => isset($data['plan']) ? $data['plan'] : '',
            'bound_host' => isset($data['bound_host']) ? $data['bound_host'] : '',
            'key_prefix' => substr($key, 0, 12),
            'last_error' => '',
            'last_error_code' => '',
            'plan_lapsed' => false,
        );
        Korisec_API::save_state($state);

        Korisec_Inventory::post();

        wp_send_json_success(array('message' => __('Connected. This site is verified in Korisec.', 'korisec')));
    }

    public static function ajax_disconnect() {
        self::require_ajax();
        check_ajax_referer('korisec_admin', 'nonce');
        delete_option(Korisec_API::OPTION_KEY);
        delete_option(Korisec_API::OPTION_STATE);
        wp_send_json_success(array('message' => __('Disconnected. The key was not revoked in Korisec.', 'korisec')));
    }

    public static function ajax_dashboard() {
        self::require_ajax();
        check_ajax_referer('korisec_admin', 'nonce');
        if (!Korisec_API::get_key()) {
            wp_send_json_error(array('message' => __('Connect a plugin key first.', 'korisec')));
        }
        $latest = Korisec_API::apply_auth_failure(
            Korisec_API::request('GET', '/api/v1/plugin/latest', null, 15)
        );
        if (!$latest['ok']) {
            wp_send_json_error(
                array(
                    'message' => Korisec_API::human_error($latest),
                    'code' => $latest['code'],
                )
            );
        }
        $data = $latest['data'] ? $latest['data'] : array();
        $scan = null;
        if (isset($data['scan']) && is_array($data['scan'])) {
            $scan = $data['scan'];
        } elseif (!empty($data['id'])) {
            $scan = $data;
        }
        $findings = array();
        if (isset($data['findings']) && is_array($data['findings'])) {
            $findings = $data['findings'];
        } elseif ($scan && isset($scan['findings']) && is_array($scan['findings'])) {
            $findings = $scan['findings'];
        }
        $counts = isset($data['severity_counts']) && is_array($data['severity_counts'])
            ? $data['severity_counts']
            : array();

        $history = Korisec_API::request('GET', '/api/v1/plugin/scans', null, 15);
        $scans = array();
        if ($history['ok'] && isset($history['data']['scans']) && is_array($history['data']['scans'])) {
            $scans = $history['data']['scans'];
        }

        $state = Korisec_API::get_state();
        if ($scan) {
            $state = self::merge_scan_state($state, $scan, $findings);
        }
        $state['history'] = $scans;
        Korisec_API::save_state($state);

        wp_send_json_success(
            array(
                'plan' => isset($state['plan']) ? $state['plan'] : '',
                'host' => isset($state['bound_host']) ? $state['bound_host'] : '',
                'scan' => $scan,
                'findings' => $findings,
                'severity_counts' => $counts,
                'history' => $scans,
            )
        );
    }

    public static function ajax_run_check() {
        self::require_ajax();
        check_ajax_referer('korisec_admin', 'nonce');
        if (!Korisec_API::get_key()) {
            wp_send_json_error(array('message' => __('Connect a plugin key first.', 'korisec')));
        }
        Korisec_Inventory::post();
        $result = Korisec_API::request('POST', '/api/v1/plugin/scans', new stdClass(), 20);
        $result = Korisec_API::apply_auth_failure($result);
        if (!$result['ok']) {
            $scan_id = null;
            if (isset($result['data']['detail']) && is_array($result['data']['detail']) && isset($result['data']['detail']['scan_id'])) {
                $scan_id = $result['data']['detail']['scan_id'];
            }
            wp_send_json_error(
                array(
                    'message' => Korisec_API::human_error($result),
                    'code' => $result['code'],
                    'scan_id' => $scan_id,
                )
            );
        }
        $scan = $result['data'] ? $result['data'] : array();
        $state = self::merge_scan_state(Korisec_API::get_state(), $scan);
        Korisec_API::save_state($state);
        wp_send_json_success(array('scan' => $scan));
    }

    public static function ajax_scan_status() {
        self::require_ajax();
        check_ajax_referer('korisec_admin', 'nonce');
        $scan_id = isset($_REQUEST['scan_id']) ? absint(wp_unslash($_REQUEST['scan_id'])) : 0;
        if (!$scan_id) {
            $state = Korisec_API::get_state();
            $scan_id = isset($state['last_scan_id']) ? (int) $state['last_scan_id'] : 0;
        }
        if (!$scan_id) {
            wp_send_json_error(array('message' => __('No check in progress.', 'korisec')));
        }
        $result = Korisec_API::request('GET', '/api/v1/plugin/scans/' . $scan_id, null, 15);
        $result = Korisec_API::apply_auth_failure($result);
        if (!$result['ok']) {
            wp_send_json_error(
                array(
                    'message' => Korisec_API::human_error($result),
                    'code' => $result['code'],
                )
            );
        }
        $scan = $result['data'] ? $result['data'] : array();
        $findings = isset($scan['findings']) && is_array($scan['findings']) ? $scan['findings'] : array();
        $state = self::merge_scan_state(Korisec_API::get_state(), $scan, $findings);
        Korisec_API::save_state($state);
        wp_send_json_success(
            array(
                'scan' => $scan,
                'findings' => $findings,
                'severity_counts' => isset($scan['severity_counts']) ? $scan['severity_counts'] : array(),
            )
        );
    }

    /**
     * @param mixed $value Payload from JSON.
     * @return mixed
     */
    private static function sanitize_account_payload($value) {
        if (is_array($value)) {
            $clean = array();
            foreach ($value as $key => $item) {
                $clean_key = is_string($key) ? sanitize_text_field($key) : $key;
                $clean[$clean_key] = self::sanitize_account_payload($item);
            }
            return $clean;
        }
        if (is_bool($value) || is_int($value) || is_float($value) || $value === null) {
            return $value;
        }
        return sanitize_text_field((string) $value);
    }

    private static function account_routes() {
        return array(
            'account' => array('GET', '/api/v1/plugin/account'),
            'billing' => array('GET', '/api/v1/plugin/account/billing'),
            'checkout' => array('POST', '/api/v1/plugin/account/billing/checkout'),
            'cancel' => array('POST', '/api/v1/plugin/account/billing/cancel'),
            'team' => array('GET', '/api/v1/plugin/account/team'),
            'team_invite' => array('POST', '/api/v1/plugin/account/team/invite'),
            'team_remove' => array('POST', '/api/v1/plugin/account/team/remove'),
            'reports' => array('GET', '/api/v1/plugin/account/reports'),
            'branding' => array('PATCH', '/api/v1/plugin/account/branding'),
            'alerts' => array('GET', '/api/v1/plugin/account/alerts'),
            'alerts_save' => array('PATCH', '/api/v1/plugin/account/alerts'),
            'telegram_link' => array('POST', '/api/v1/plugin/account/alerts/telegram/link'),
            'telegram_unlink' => array('POST', '/api/v1/plugin/account/alerts/telegram/unlink'),
            'telegram_test' => array('POST', '/api/v1/plugin/account/alerts/telegram/test'),
            'whatsapp_link' => array('POST', '/api/v1/plugin/account/alerts/whatsapp/link'),
            'whatsapp_unlink' => array('POST', '/api/v1/plugin/account/alerts/whatsapp/unlink'),
            'whatsapp_test' => array('POST', '/api/v1/plugin/account/alerts/whatsapp/test'),
            'slack_connect' => array('POST', '/api/v1/plugin/account/alerts/slack/connect'),
            'slack_unlink' => array('POST', '/api/v1/plugin/account/alerts/slack/unlink'),
            'slack_test' => array('POST', '/api/v1/plugin/account/alerts/slack/test'),
            'webhook_connect' => array('POST', '/api/v1/plugin/account/alerts/webhook/connect'),
            'webhook_unlink' => array('POST', '/api/v1/plugin/account/alerts/webhook/unlink'),
            'webhook_test' => array('POST', '/api/v1/plugin/account/alerts/webhook/test'),
        );
    }

    public static function ajax_account() {
        self::require_ajax();
        check_ajax_referer('korisec_admin', 'nonce');
        if (!Korisec_API::get_key()) {
            wp_send_json_error(array('message' => __('Connect a plugin key first.', 'korisec')));
        }
        $op = isset($_POST['op']) ? sanitize_key(wp_unslash($_POST['op'])) : '';
        $routes = self::account_routes();
        if (!isset($routes[$op])) {
            wp_send_json_error(array('message' => __('Unknown account action.', 'korisec')));
        }
        list($method, $path) = $routes[$op];
        $payload = null;
        if (strtoupper($method) !== 'GET') {
            $payload = new stdClass();
            if (isset($_POST['payload'])) {
                // JSON cannot be run through sanitize_text_field first; values are sanitized after decode.
                $raw_payload = wp_unslash($_POST['payload']); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
                if (is_string($raw_payload) && $raw_payload !== '') {
                    $decoded = json_decode($raw_payload, true);
                    if (is_array($decoded)) {
                        $payload = self::sanitize_account_payload($decoded);
                    }
                }
            }
        }
        $result = Korisec_API::apply_auth_failure(
            Korisec_API::request($method, $path, $payload, 25)
        );
        if (!$result['ok']) {
            wp_send_json_error(
                array(
                    'message' => Korisec_API::human_error($result),
                    'code' => $result['code'],
                )
            );
        }
        wp_send_json_success($result['data'] ? $result['data'] : array());
    }

    public static function download_pdf() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You cannot download this report.', 'korisec'));
        }
        check_admin_referer('korisec_admin');
        if (!Korisec_API::get_key()) {
            wp_die(esc_html__('Connect a plugin key first.', 'korisec'));
        }
        $kind = isset($_GET['kind']) ? sanitize_key(wp_unslash($_GET['kind'])) : '';
        if ($kind === 'portfolio') {
            $path = '/api/v1/plugin/account/reports/portfolio.pdf';
        } elseif ($kind === 'scan') {
            $scan_id = isset($_GET['scan_id']) ? (int) $_GET['scan_id'] : 0;
            if (!$scan_id) {
                wp_die(esc_html__('Missing scan.', 'korisec'));
            }
            $path = '/api/v1/plugin/scans/' . $scan_id . '/report.pdf';
        } else {
            wp_die(esc_html__('Unknown report.', 'korisec'));
        }
        $result = Korisec_API::apply_auth_failure(Korisec_API::request_binary($path, 90));
        if (empty($result['ok'])) {
            wp_die(esc_html(!empty($result['message']) ? $result['message'] : __('Could not download the PDF.', 'korisec')));
        }
        nocache_headers();
        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="' . sanitize_file_name($result['filename']) . '"');
        echo $result['body']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        exit;
    }

    private static function js_i18n() {
        return array(
            'genericError' => __('Something went wrong. Try again.', 'korisec'),
            'score' => __('Score', 'korisec'),
            'lastCheck' => __('Last check', 'korisec'),
            'noCheckYet' => __('No check yet', 'korisec'),
            'runCheck' => __('Run check', 'korisec'),
            'downloadPdf' => __('Download PDF', 'korisec'),
            'waitingQueue' => __('Waiting in queue', 'korisec'),
            'checkRunning' => __('Check running…', 'korisec'),
            'findings' => __('Findings', 'korisec'),
            'noFindings' => __('No issues on the latest check. Run a check to refresh.', 'korisec'),
            'finding' => __('Finding', 'korisec'),
            'whatWeFound' => __('What we found:', 'korisec'),
            'whyItMatters' => __('Why it matters:', 'korisec'),
            'whatToDo' => __('What to do:', 'korisec'),
            /* translators: %s: version number */
            'updateTo' => __('Update to %s', 'korisec'),
            'viewCve' => __('View CVE', 'korisec'),
            'openPluginUpdates' => __('Open Plugins', 'korisec'),
            'openThemeUpdates' => __('Open Themes', 'korisec'),
            'openCoreUpdates' => __('Open Updates', 'korisec'),
            /* translators: %s: plugin or theme name */
            'updateNamed' => __('Update %s', 'korisec'),
            'actionsTitle' => __('Actions', 'korisec'),
            'actionsIntro' => __('Plugin/theme updates and one-click remedies for XML-RPC, public usernames, and install.php. Changes apply on this site only.', 'korisec'),
            'actionsEmpty' => __('No updates waiting. Run a check or refresh WordPress updates if you expect something here.', 'korisec'),
            'actionsFromWp' => __('Available on this site', 'korisec'),
            'actionsFromScan' => __('From latest Korisec check', 'korisec'),
            'actionsRemedies' => __('Recommended remedies', 'korisec'),
            'applyRemedy' => __('Apply fix', 'korisec'),
            'remedyApplied' => __('Fix applied. Re-run a check to confirm.', 'korisec'),
            'remedyFailed' => __('Could not apply that fix.', 'korisec'),
            'remedyAlreadyOn' => __('Already applied', 'korisec'),
            'hardeningSaved' => __('Exposure remedies saved.', 'korisec'),
            'hardeningSaveFailed' => __('Could not save exposure remedies.', 'korisec'),
            'installedVersion' => __('Installed', 'korisec'),
            'availableVersion' => __('Available', 'korisec'),
            'recommendedFix' => __('Recommended', 'korisec'),
            'kevBadge' => __('Known exploited', 'korisec'),
            'loginSaved' => __('Login protection settings saved.', 'korisec'),
            'loginSaveFailed' => __('Could not save protection settings.', 'korisec'),
            'recentChecks' => __('Recent checks', 'korisec'),
            'when' => __('When', 'korisec'),
            'grade' => __('Grade', 'korisec'),
            'status' => __('Status', 'korisec'),
            'report' => __('Report', 'korisec'),
            'pdf' => __('PDF', 'korisec'),
            'couldNotLoadCheck' => __('Could not load the latest check.', 'korisec'),
            'couldNotRefresh' => __('Could not refresh check status.', 'korisec'),
            'startingCheck' => __('Starting check…', 'korisec'),
            'couldNotStart' => __('Could not start a check.', 'korisec'),
            'loading' => __('Loading…', 'korisec'),
            'couldNotLoadTab' => __('Could not load this tab.', 'korisec'),
            'billingTitle' => __('Billing & plan', 'korisec'),
            /* translators: %s: account email, may include HTML */
            'billingIntro' => __('Changes apply to %s — the billing owner for this plugin key. This key cannot act on another workspace.', 'korisec'),
            'yourAccount' => __('your Korisec account', 'korisec'),
            'currentPlan' => __('Current plan:', 'korisec'),
            'monthly' => __('Monthly', 'korisec'),
            /* translators: %s: discount percent */
            'annuallyOff' => __('Annual (%s%% off)', 'korisec'),
            'current' => __('Current', 'korisec'),
            'perMonth' => __('/ mo', 'korisec'),
            /* translators: %s: plan name */
            'choosePlan' => __('Choose %s', 'korisec'),
            'cancelSub' => __('Cancel subscription', 'korisec'),
            'paystackNote' => __('Paystack opens in a new tab. After paying, come back and reopen Billing to see the new plan.', 'korisec'),
            'checkoutStarted' => __('Checkout started. Complete payment in the Paystack window.', 'korisec'),
            'couldNotCheckout' => __('Could not start checkout.', 'korisec'),
            'confirmCancel' => __('Cancel the Paystack subscription for this Korisec account?', 'korisec'),
            'teamTitle' => __('Team seats', 'korisec'),
            /* translators: %s: owner email, may include HTML */
            'teamIntro' => __('Seats on %s. Invites join this owner’s workspace, not another team.', 'korisec'),
            'thisBilling' => __('this billing account', 'korisec'),
            /* translators: 1: seats used, 2: seat limit, 3: plan name */
            'seatsUsed' => __('%1$s of %2$s seats used · plan %3$s', 'korisec'),
            'invite' => __('Invite', 'korisec'),
            'analyst' => __('Analyst', 'korisec'),
            'viewer' => __('Viewer', 'korisec'),
            'upgradeSeats' => __('Upgrade to Pro (3 seats) or Agency (10 seats) to invite teammates.', 'korisec'),
            'email' => __('Email', 'korisec'),
            'role' => __('Role', 'korisec'),
            'noInvites' => __('No invites yet. You are the owner.', 'korisec'),
            'remove' => __('Remove', 'korisec'),
            'confirmRemove' => __('Remove this seat from your billing account?', 'korisec'),
            'reportsTitle' => __('PDF / white-label reports', 'korisec'),
            /* translators: %s: site hostname, may include HTML */
            'reportsIntro' => __('PDFs use branding on this billing account. Scan PDFs are only for %s.', 'korisec'),
            'thisSite' => __('this connected site', 'korisec'),
            /* translators: %s: scan grade, may include HTML */
            'latestCheck' => __('Latest check: grade %s', 'korisec'),
            'downloadSitePdf' => __('Download site PDF', 'korisec'),
            'runCheckForPdf' => __('Run a check on the Checks tab to generate a PDF for this site.', 'korisec'),
            'downloadPortfolio' => __('Download agency portfolio PDF', 'korisec'),
            'agencyNote' => __('Portfolio and white-label branding need the Agency plan.', 'korisec'),
            'whiteLabel' => __('White-label', 'korisec'),
            'companyName' => __('Company name', 'korisec'),
            'accentColour' => __('Accent colour', 'korisec'),
            'saveBranding' => __('Save branding', 'korisec'),
            'logoNote' => __('Upload a logo from app.korisec.com → Account if you need a mark on the PDF cover.', 'korisec'),
            'upgradeAgency' => __('Upgrade to Agency to set company name and accent on client PDFs.', 'korisec'),
            'brandingSaved' => __('Branding saved for this billing account.', 'korisec'),
            'alertsTitle' => __('Alerts', 'korisec'),
            /* translators: %s: owner email, may include HTML */
            'alertsIntro' => __('Channels for %s. Findings on this site still send to the owner’s linked Telegram, Slack, and email — not another team.', 'korisec'),
            'emailLegend' => __('Email', 'korisec'),
            'telegram' => __('Telegram', 'korisec'),
            'whatsapp' => __('WhatsApp', 'korisec'),
            'slack' => __('Slack', 'korisec'),
            'webhook' => __('Webhook', 'korisec'),
            'critical' => __('Critical', 'korisec'),
            'high' => __('High', 'korisec'),
            'medium' => __('Medium', 'korisec'),
            'low' => __('Low', 'korisec'),
            'info' => __('Info', 'korisec'),
            'savePrefs' => __('Save preferences', 'korisec'),
            'linked' => __('Linked', 'korisec'),
            'notLinked' => __('Not linked', 'korisec'),
            'sendTest' => __('Send test', 'korisec'),
            'unlink' => __('Unlink', 'korisec'),
            'connectTelegram' => __('Connect Telegram', 'korisec'),
            'whatsappPaid' => __('WhatsApp is on paid plans.', 'korisec'),
            'whatsappCode' => __('Get WhatsApp link code', 'korisec'),
            'slackPro' => __('Slack is on Pro and Agency.', 'korisec'),
            'slackPaste' => __('Paste an incoming webhook URL.', 'korisec'),
            /* translators: %s: masked webhook URL */
            'slackConnected' => __('Webhook connected %s', 'korisec'),
            'saveSlack' => __('Save Slack webhook', 'korisec'),
            'webhookAgency' => __('Generic webhooks are on Agency.', 'korisec'),
            'webhookHttps' => __('HTTPS endpoint for JSON alerts.', 'korisec'),
            /* translators: %s: masked webhook URL */
            'webhookConnected' => __('Connected %s', 'korisec'),
            'saveWebhook' => __('Save webhook', 'korisec'),
            'prefsSaved' => __('Alert preferences saved.', 'korisec'),
            'openTelegram' => __('Open Telegram and tap Start.', 'korisec'),
            /* translators: %s: webhook secret */
            'webhookSecret' => __('Webhook saved. Secret (shown once): %s', 'korisec'),
            'couldNotWp' => __('Could not reach WordPress.', 'korisec'),
            'confirmDisconnect' => __('Disconnect this site? This does not revoke the key in Korisec.', 'korisec'),
            'thisSiteHost' => __('This site', 'korisec'),
        );
    }
}
