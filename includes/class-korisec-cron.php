<?php

if (!defined('ABSPATH')) {
    exit;
}

class Korisec_Cron {
    const HOOK_DAILY = 'korisec_daily';
    const HOOK_INVENTORY = 'korisec_inventory_soon';

    public static function init() {
        add_action(self::HOOK_DAILY, array(__CLASS__, 'run_daily'));
        add_action(self::HOOK_INVENTORY, array(__CLASS__, 'run_inventory'));
        add_action('upgrader_process_complete', array(__CLASS__, 'on_upgrade'), 10, 2);
    }

    public static function activate() {
        if (!wp_next_scheduled(self::HOOK_DAILY)) {
            wp_schedule_event(time() + 300, 'daily', self::HOOK_DAILY);
        }
    }

    public static function deactivate() {
        $ts = wp_next_scheduled(self::HOOK_DAILY);
        if ($ts) {
            wp_unschedule_event($ts, self::HOOK_DAILY);
        }
        wp_clear_scheduled_hook(self::HOOK_INVENTORY);
    }

    public static function on_upgrade($upgrader, $options) {
        unset($upgrader);
        if (empty($options['type']) || !in_array($options['type'], array('plugin', 'theme', 'core'), true)) {
            return;
        }
        if (!Korisec_API::get_key()) {
            return;
        }
        $next = wp_next_scheduled(self::HOOK_INVENTORY);
        if ($next) {
            return;
        }
        wp_schedule_single_event(time() + 60, self::HOOK_INVENTORY);
    }

    public static function run_daily() {
        if (!Korisec_API::get_key()) {
            return;
        }
        $hb = Korisec_API::request('POST', '/api/v1/plugin/heartbeat', Korisec_API::site_payload(), 15);
        Korisec_API::apply_auth_failure($hb);
        if (!$hb['ok']) {
            return;
        }
        self::run_inventory();
    }

    public static function run_inventory() {
        if (!Korisec_API::get_key()) {
            return;
        }
        Korisec_Inventory::post();
    }
}
