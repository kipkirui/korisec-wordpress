<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Pure-PHP database dump and restore (no exec/mysqldump needed).
 *
 * Dump: one SQL statement per line (values are escaped so they never contain raw
 * newlines), batched into ~1 MB encrypted records. Rows are paged by integer
 * primary key where possible, so work can stop and resume between requests.
 *
 * Restore: statements are replayed into temporary tables (kstmp_*), validated,
 * then swapped in with a single atomic RENAME TABLE. The previous tables are kept
 * as ksold_* so "Undo restore" is another instant RENAME.
 */
class Korisec_Backup_DB {
    const BATCH_ROWS = 500;
    const STATEMENT_BYTES = 524288;
    const RECORD_BYTES = 1048576;

    private static function dbh() {
        global $wpdb;
        return $wpdb->dbh;
    }

    private static function esc($value) {
        return mysqli_real_escape_string(self::dbh(), (string) $value);
    }

    private static function qi($name) {
        return '`' . str_replace('`', '``', $name) . '`';
    }

    /** Run raw SQL on the WordPress connection without wpdb rewriting. */
    private static function raw($sql) {
        $res = mysqli_query(self::dbh(), $sql);
        if ($res === false) {
            return new WP_Error('db_query', mysqli_error(self::dbh()));
        }
        return $res;
    }

    /* ---------------------------------------------------------------- dump */

    /**
     * @return array Base tables to back up (and a count of skipped ones).
     */
    public static function discover_tables($all_tables = false) {
        global $wpdb;
        $rows = $wpdb->get_results('SHOW FULL TABLES', ARRAY_N); // phpcs:ignore WordPress.DB
        $own = Korisec_Backup_Store::own_tables();
        $tables = array();
        $views = 0;
        $other_prefix = 0;
        foreach ($rows ? $rows : array() as $r) {
            $name = $r[0];
            $type = isset($r[1]) ? strtoupper($r[1]) : 'BASE TABLE';
            if (in_array($name, $own, true) || preg_match('/^ks(tmp|old)_[a-f0-9]{8}_\d+$/', $name)) {
                continue;
            }
            if ($type !== 'BASE TABLE') {
                $views++;
                continue;
            }
            if (!$all_tables && strpos($name, $wpdb->base_prefix) !== 0) {
                $other_prefix++;
                continue;
            }
            $tables[] = $name;
        }
        sort($tables);
        return array('tables' => $tables, 'views_skipped' => $views, 'other_prefix_skipped' => $other_prefix);
    }

    public static function server_info() {
        global $wpdb;
        return array(
            'server' => (string) $wpdb->db_server_info(),
            'version' => (string) $wpdb->db_version(),
            'charset' => (string) $wpdb->charset,
        );
    }

    /** Fresh dump cursor. */
    public static function dump_init($all_tables) {
        $found = self::discover_tables($all_tables);
        return array(
            'tables' => $found['tables'],
            'views_skipped' => $found['views_skipped'],
            'other_prefix_skipped' => $found['other_prefix_skipped'],
            'table_index' => 0,
            'phase' => 'header',
            'columns' => array(),
            'pk' => '',
            'last_pk' => null,
            'offset' => 0,
            'rows' => 0,
            'sql_bytes' => 0,
        );
    }

    private static function table_columns($table) {
        global $wpdb;
        $cols = $wpdb->get_results('SHOW COLUMNS FROM ' . self::qi($table), ARRAY_A); // phpcs:ignore WordPress.DB
        $insertable = array();
        $int_pk = array();
        foreach ($cols ? $cols : array() as $c) {
            $extra = strtoupper((string) $c['Extra']);
            if (strpos($extra, 'GENERATED') !== false || strpos($extra, 'VIRTUAL') !== false || strpos($extra, 'STORED') !== false) {
                continue;
            }
            $insertable[] = $c['Field'];
            if ($c['Key'] === 'PRI' && preg_match('/^(tiny|small|medium|big)?int/i', $c['Type'])) {
                $int_pk[] = $c['Field'];
            }
        }
        $pri_count = 0;
        foreach ($cols ? $cols : array() as $c) {
            if ($c['Key'] === 'PRI') {
                $pri_count++;
            }
        }
        return array('columns' => $insertable, 'pk' => ($pri_count === 1 && count($int_pk) === 1) ? $int_pk[0] : '');
    }

    /**
     * Dump until the deadline. Appends encrypted records via $writer.
     *
     * @return bool|WP_Error true when the dump is complete.
     */
    public static function dump_step(array &$cur, array &$writer, $deadline) {
        global $wpdb;
        $buffer = '';
        $flush = function ($force) use (&$buffer, &$writer, &$cur) {
            if ($buffer === '' || (!$force && strlen($buffer) < self::RECORD_BYTES)) {
                return true;
            }
            $cur['sql_bytes'] += strlen($buffer);
            $r = Korisec_Backup_Crypto::writer_push($writer, $buffer);
            $buffer = '';
            return $r;
        };

        if ($cur['phase'] === 'header') {
            $info = self::server_info();
            $buffer .= '-- Korisec database backup ' . gmdate('c') . "\n";
            $buffer .= 'SET NAMES ' . preg_replace('/[^a-z0-9_]/i', '', $info['charset'] ? $info['charset'] : 'utf8mb4') . ";\n";
            $buffer .= "SET FOREIGN_KEY_CHECKS=0;\n";
            $buffer .= "SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\n";
            $buffer .= "SET UNIQUE_CHECKS=0;\n";
            $cur['phase'] = 'schema';
        }

        while ($cur['table_index'] < count($cur['tables'])) {
            $table = $cur['tables'][$cur['table_index']];
            if ($cur['phase'] === 'schema') {
                $create = $wpdb->get_row('SHOW CREATE TABLE ' . self::qi($table), ARRAY_N); // phpcs:ignore WordPress.DB
                if (!$create || empty($create[1])) {
                    return new WP_Error('db_dump', sprintf('Could not read the structure of table %s.', $table));
                }
                $buffer .= 'DROP TABLE IF EXISTS ' . self::qi($table) . ";\n";
                $buffer .= str_replace(array("\r", "\n"), ' ', $create[1]) . ";\n";
                $meta = self::table_columns($table);
                $cur['columns'] = $meta['columns'];
                $cur['pk'] = $meta['pk'];
                $cur['last_pk'] = null;
                $cur['offset'] = 0;
                $cur['phase'] = 'rows';
            }

            if ($cur['phase'] === 'rows') {
                if (empty($cur['columns'])) {
                    $cur['phase'] = 'next';
                }
                while ($cur['phase'] === 'rows') {
                    $cols_sql = implode(',', array_map(array(__CLASS__, 'qi'), $cur['columns']));
                    if ($cur['pk'] !== '') {
                        $where = $cur['last_pk'] === null ? '' : ' WHERE ' . self::qi($cur['pk']) . " > '" . self::esc($cur['last_pk']) . "'";
                        $sql = 'SELECT ' . $cols_sql . ' FROM ' . self::qi($table) . $where . ' ORDER BY ' . self::qi($cur['pk']) . ' ASC LIMIT ' . self::BATCH_ROWS;
                    } else {
                        $sql = 'SELECT ' . $cols_sql . ' FROM ' . self::qi($table) . ' LIMIT ' . (int) $cur['offset'] . ',' . self::BATCH_ROWS;
                    }
                    $res = self::raw($sql);
                    if (is_wp_error($res)) {
                        return new WP_Error('db_dump', sprintf('Reading table %1$s failed: %2$s', $table, $res->get_error_message()));
                    }
                    $count = 0;
                    $stmt = '';
                    $pk_index = $cur['pk'] !== '' ? array_search($cur['pk'], $cur['columns'], true) : false;
                    $prefix = 'INSERT INTO ' . self::qi($table) . ' (' . $cols_sql . ') VALUES ';
                    while ($row = mysqli_fetch_row($res)) {
                        $vals = array();
                        foreach ($row as $v) {
                            $vals[] = $v === null ? 'NULL' : "'" . self::esc($v) . "'";
                        }
                        $tuple = '(' . implode(',', $vals) . ')';
                        if ($stmt !== '' && strlen($stmt) + strlen($tuple) > self::STATEMENT_BYTES) {
                            $buffer .= $stmt . ";\n";
                            $stmt = '';
                        }
                        $stmt .= ($stmt === '' ? $prefix : ',') . $tuple;
                        if ($pk_index !== false) {
                            $cur['last_pk'] = $row[$pk_index];
                        }
                        $count++;
                    }
                    mysqli_free_result($res);
                    if ($stmt !== '') {
                        $buffer .= $stmt . ";\n";
                    }
                    $cur['rows'] += $count;
                    $cur['offset'] += $count;
                    $r = $flush(false);
                    if (is_wp_error($r)) {
                        return $r;
                    }
                    if ($count < self::BATCH_ROWS) {
                        $cur['phase'] = 'next';
                        break;
                    }
                    if (microtime(true) >= $deadline) {
                        $r = $flush(true);
                        return is_wp_error($r) ? $r : false;
                    }
                }
            }

            $cur['table_index']++;
            $cur['phase'] = 'schema';
            $r = $flush(false);
            if (is_wp_error($r)) {
                return $r;
            }
            if (microtime(true) >= $deadline) {
                $r = $flush(true);
                return is_wp_error($r) ? $r : false;
            }
        }

        $buffer .= "SET FOREIGN_KEY_CHECKS=1;\nSET UNIQUE_CHECKS=1;\n-- end of Korisec backup\n";
        $r = $flush(true);
        if (is_wp_error($r)) {
            return $r;
        }
        $r = Korisec_Backup_Crypto::writer_close($writer);
        return is_wp_error($r) ? $r : true;
    }

    /* ------------------------------------------------------------- restore */

    public static function restore_init($restore_id, array $manifest_tables) {
        $map = array();
        foreach (array_values($manifest_tables) as $i => $name) {
            $map[$name] = 'kstmp_' . $restore_id . '_' . $i;
        }
        return array('rid' => $restore_id, 'map' => $map, 'statements' => 0, 'tables_created' => array());
    }

    /** Drop any leftover temp tables for this restore id. */
    public static function drop_temp_tables($restore_id) {
        global $wpdb;
        $like = $wpdb->esc_like('kstmp_' . $restore_id . '_') . '%';
        $names = $wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', $like)); // phpcs:ignore WordPress.DB
        foreach ($names ? $names : array() as $t) {
            self::raw('DROP TABLE IF EXISTS ' . self::qi($t));
        }
    }

    /**
     * Rewrite one dump statement so it targets the temp table.
     *
     * @return string|null|WP_Error Rewritten SQL, null to skip.
     */
    private static function rewrite_statement($line, array &$cur) {
        if ($line === '' || strpos($line, '--') === 0) {
            return null;
        }
        if (preg_match('/^SET (NAMES [A-Za-z0-9_]+|FOREIGN_KEY_CHECKS=[01]|UNIQUE_CHECKS=[01]|SQL_MODE=\'[A-Z_,]*\');$/', $line)) {
            return $line;
        }
        if (!preg_match('/^(DROP TABLE IF EXISTS|CREATE TABLE|INSERT INTO) `((?:[^`]|``)+)`/', $line, $m)) {
            return new WP_Error('restore_sql', __('The backup contains an unexpected SQL statement and was not restored.', 'korisec'));
        }
        $name = str_replace('``', '`', $m[2]);
        if (!isset($cur['map'][$name])) {
            return new WP_Error('restore_sql', __('The backup references a table that is not in its manifest.', 'korisec'));
        }
        $tmp = $cur['map'][$name];
        $rest = substr($line, strlen($m[0]));
        if ($m[1] === 'CREATE TABLE') {
            foreach ($cur['map'] as $orig => $t) {
                $rest = str_replace('REFERENCES ' . self::qi($orig) . ' ', 'REFERENCES ' . self::qi($t) . ' ', $rest);
            }
            // Foreign key names are unique per database, so the temp copy needs its own.
            $rid = $cur['rid'];
            $rest = preg_replace_callback(
                '/CONSTRAINT `((?:[^`]|``)+)`/',
                function ($c) use ($rid) {
                    $base = preg_replace('/_ks[a-f0-9]{8}$/', '', str_replace('``', '`', $c[1]));
                    return 'CONSTRAINT ' . self::qi(substr($base, 0, 50) . '_ks' . $rid);
                },
                $rest
            );
            $cur['tables_created'][$name] = true;
        }
        return $m[1] . ' ' . self::qi($tmp) . $rest;
    }

    /**
     * Replay statements from the decrypted dump into temp tables until the deadline.
     *
     * @return bool|WP_Error true when finished.
     */
    public static function restore_step(array &$cur, array &$reader, $deadline) {
        self::raw('SET FOREIGN_KEY_CHECKS=0');
        while (microtime(true) < $deadline) {
            $block = Korisec_Backup_Crypto::reader_next($reader);
            if (is_wp_error($block)) {
                return $block;
            }
            if ($block === null) {
                return true;
            }
            foreach (explode("\n", $block) as $line) {
                $sql = self::rewrite_statement(rtrim($line, "\r"), $cur);
                if ($sql === null) {
                    continue;
                }
                if (is_wp_error($sql)) {
                    return $sql;
                }
                $res = self::raw($sql);
                if (is_wp_error($res)) {
                    return new WP_Error('restore_sql', sprintf(__('A SQL statement failed during restore: %s', 'korisec'), $res->get_error_message()));
                }
                $cur['statements']++;
            }
            if (!empty($reader['done'])) {
                return true;
            }
        }
        return false;
    }

    /** Sanity checks on the temp tables before they go live. */
    public static function validate_temp(array $cur, $prefix) {
        global $wpdb;
        $expected = count($cur['map']);
        if (count($cur['tables_created']) !== $expected) {
            /* translators: 1: tables restored, 2: tables expected */
            return new WP_Error('restore_validate', sprintf(__('Only %1$d of %2$d tables were restored.', 'korisec'), count($cur['tables_created']), $expected));
        }
        foreach (array('options', 'users', 'posts') as $core) {
            $name = $prefix . $core;
            if (!isset($cur['map'][$name])) {
                /* translators: %s: table name */
                return new WP_Error('restore_validate', sprintf(__('The backup is missing the %s table.', 'korisec'), $name));
            }
        }
        $opts = $cur['map'][$prefix . 'options'];
        $siteurl = $wpdb->get_var("SELECT option_value FROM " . self::qi($opts) . " WHERE option_name = 'siteurl' LIMIT 1"); // phpcs:ignore WordPress.DB
        if (!$siteurl) {
            return new WP_Error('restore_validate', __('The restored options table has no site URL.', 'korisec'));
        }
        $users = (int) $wpdb->get_var('SELECT COUNT(*) FROM ' . self::qi($cur['map'][$prefix . 'users'])); // phpcs:ignore WordPress.DB
        if ($users < 1) {
            return new WP_Error('restore_validate', __('The restored users table is empty.', 'korisec'));
        }
        return array('siteurl' => $siteurl, 'users' => $users);
    }

    /**
     * Atomically swap temp tables in. Live tables move to ksold_<id>_<n>.
     *
     * @return array|WP_Error Swap record used for undo.
     */
    public static function swap_in($restore_id, array $cur) {
        global $wpdb;
        $live = array_flip((array) $wpdb->get_col('SHOW TABLES')); // phpcs:ignore WordPress.DB
        $pairs = array();
        $record = array('old' => array(), 'new_only' => array());
        $i = 0;
        foreach ($cur['map'] as $orig => $tmp) {
            if (isset($live[$orig])) {
                $old = 'ksold_' . $restore_id . '_' . $i;
                $pairs[] = self::qi($orig) . ' TO ' . self::qi($old);
                $record['old'][$orig] = $old;
            } else {
                $record['new_only'][] = $orig;
            }
            $pairs[] = self::qi($tmp) . ' TO ' . self::qi($orig);
            $i++;
        }
        $res = self::raw('RENAME TABLE ' . implode(', ', $pairs));
        if (is_wp_error($res)) {
            return new WP_Error('restore_swap', sprintf(__('Swapping in the restored tables failed: %s. The live site was not changed.', 'korisec'), $res->get_error_message()));
        }
        return $record;
    }

    /** Reverse swap_in(): put the ksold_* tables back. */
    public static function swap_back(array $record) {
        $pairs = array();
        $drop = array();
        $n = 0;
        foreach ($record['old'] as $orig => $old) {
            $trash = 'ksold_' . substr(md5($old), 0, 8) . '_' . (900000 + $n++);
            $pairs[] = self::qi($orig) . ' TO ' . self::qi($trash);
            $pairs[] = self::qi($old) . ' TO ' . self::qi($orig);
            $drop[] = $trash;
        }
        foreach ($record['new_only'] as $orig) {
            $trash = 'ksold_' . substr(md5($orig), 0, 8) . '_' . (900000 + $n++);
            $pairs[] = self::qi($orig) . ' TO ' . self::qi($trash);
            $drop[] = $trash;
        }
        if ($pairs) {
            $res = self::raw('RENAME TABLE ' . implode(', ', $pairs));
            if (is_wp_error($res)) {
                return $res;
            }
        }
        foreach ($drop as $t) {
            self::raw('DROP TABLE IF EXISTS ' . self::qi($t));
        }
        return true;
    }

    /** Drop the kept ksold_* tables once the restore is accepted. */
    public static function drop_old(array $record) {
        foreach ($record['old'] as $old) {
            self::raw('DROP TABLE IF EXISTS ' . self::qi($old));
        }
    }

    /**
     * Snapshot Korisec's own options and the current admin session so a restore does
     * not roll back the plugin's settings, Drive link, keys, or log the admin out.
     */
    public static function capture_preserved() {
        global $wpdb;
        $opts = $wpdb->get_results($wpdb->prepare("SELECT option_name, option_value, autoload FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s", $wpdb->esc_like('korisec_') . '%', $wpdb->esc_like('_transient_korisec_') . '%', $wpdb->esc_like('_transient_timeout_korisec_') . '%'), ARRAY_A); // phpcs:ignore WordPress.DB
        $user = wp_get_current_user();
        $session = array();
        if ($user && $user->ID) {
            $session = array(
                'login' => $user->user_login,
                'tokens' => get_user_meta($user->ID, 'session_tokens', true),
            );
        }
        $active = get_option('active_plugins', array());
        return array('options' => $opts ? $opts : array(), 'session' => $session, 'korisec_active' => is_array($active) && in_array(plugin_basename(KORISEC_PLUGIN_FILE), $active, true));
    }

    public static function apply_preserved(array $kept) {
        global $wpdb;
        foreach ($kept['options'] as $o) {
            $wpdb->query($wpdb->prepare("INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE option_value = VALUES(option_value), autoload = VALUES(autoload)", $o['option_name'], $o['option_value'], $o['autoload'])); // phpcs:ignore WordPress.DB
        }
        wp_cache_flush();
        if (!empty($kept['korisec_active'])) {
            $active = get_option('active_plugins', array());
            $base = plugin_basename(KORISEC_PLUGIN_FILE);
            if (is_array($active) && !in_array($base, $active, true)) {
                $active[] = $base;
                update_option('active_plugins', $active);
            }
        }
        if (!empty($kept['session']['login'])) {
            $uid = $wpdb->get_var($wpdb->prepare("SELECT ID FROM {$wpdb->users} WHERE user_login = %s", $kept['session']['login'])); // phpcs:ignore WordPress.DB
            if ($uid && is_array($kept['session']['tokens'])) {
                update_user_meta((int) $uid, 'session_tokens', $kept['session']['tokens']);
            }
        }
        wp_cache_flush();
    }

    /** List ksold_* tables left behind (for cleanup). */
    public static function leftover_tables() {
        global $wpdb;
        $rows = $wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s', 'ks%')); // phpcs:ignore WordPress.DB
        return array_values(array_filter($rows ? $rows : array(), function ($t) {
            return (bool) preg_match('/^ks(tmp|old)_[a-f0-9]{8}_\d+$/', $t);
        }));
    }

    public static function drop_tables(array $names) {
        foreach ($names as $t) {
            if (preg_match('/^ks(tmp|old)_[a-f0-9]{8}_\d+$/', $t)) {
                self::raw('DROP TABLE IF EXISTS ' . self::qi($t));
            }
        }
    }
}
