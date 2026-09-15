<?php

if (!defined('ABSPATH')) {
    exit;
}

class Korisec_Privacy {
    public static function init() {
        add_action('admin_init', array(__CLASS__, 'policy'));
    }

    public static function policy() {
        if (!function_exists('wp_add_privacy_policy_content')) {
            return;
        }

        $content = '<p class="privacy-policy-tutorial">'
            . esc_html__('Suggested text:', 'korisec')
            . '</p>';
        $content .= '<p>'
            . esc_html__('If you connect the Korisec plugin, this site sends data to Korisec (api.korisec.com) so Korisec can run hosted security checks. Nothing is sent until a site administrator pastes a Korisec plugin key and clicks Connect.', 'korisec')
            . '</p>';
        $content .= '<p>'
            . esc_html__('Data sent after connecting typically includes: this site’s URL and host name, WordPress and PHP versions, names and versions of installed plugins, themes, must-use plugins, and drop-ins (including whether they are active), and requests to start or fetch security checks. Daily heartbeat and inventory updates continue while the key remains connected.', 'korisec')
            . '</p>';
        $content .= '<p>'
            . esc_html__('Korisec processes that data on its servers to produce grades, findings, PDF reports, billing, team seats, and alerts for the Korisec account that issued the key. Scans run in Korisec’s cloud, not inside WordPress.', 'korisec')
            . '</p>';
        $content .= '<p>'
            . esc_html__('Separately, login protection (failed attempt limiting) and optional exposure remedies (XML-RPC, public username listing, install.php blocking) run only on this WordPress site. They store settings in WordPress options and short-lived login counters keyed by a hash of the visitor IP. Those are not sent to Korisec.', 'korisec')
            . '</p>';
        $policy_links = sprintf(
            /* translators: 1: privacy policy URL, 2: terms of use URL */
            __('Korisec’s privacy policy is at <a href="%1$s">%1$s</a>. Terms of use: <a href="%2$s">%2$s</a>. Disconnecting the plugin stops new data being sent; deleting the plugin removes the stored key from this WordPress site. Korisec account data is managed in the Korisec dashboard.', 'korisec'),
            'https://korisec.com/privacy.html',
            'https://korisec.com/terms.html'
        );
        $content .= '<p>' . wp_kses($policy_links, array('a' => array('href' => array()))) . '</p>';

        wp_add_privacy_policy_content('Korisec', wp_kses_post($content));
    }
}
