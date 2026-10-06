<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * wp-content (+ wp-config.php) archive as an encrypted, resumable tar stream.
 *
 * Restore extracts into a staging folder, then swaps top-level wp-content entries
 * with rename(); the previous folders are kept so "Undo restore" is instant.
 * Korisec's own plugin folder always stays live so a restore cannot downgrade the
 * code that is running it.
 */
class Korisec_Backup_Files {
    const RECORD_BYTES = 1048576;
    const READ_BYTES = 1048576;
    const MAX_FILE = 8589934591;

    private static function excluded_top() {
        $list = array(
            'cache', 'upgrade', 'upgrade-temp-backup', 'updraft', 'ai1wm-backups', 'backups-dup-lite',
            'backups-dup-pro', 'wpvividbackups', 'backup-db', 'backups', 'et-cache', 'litespeed',
            'debug.log', 'wflogs-temp',
        );
        $work = Korisec_Backup_Store::workdir_name();
        if ($work !== '') {
            $list[] = $work;
        }
        return $list;
    }

    private static function plugin_dirname() {
        return basename(dirname(KORISEC_PLUGIN_FILE));
    }

    public static function config_path() {
        if (file_exists(ABSPATH . 'wp-config.php')) {
            return ABSPATH . 'wp-config.php';
        }
        $up = dirname(ABSPATH) . '/wp-config.php';
        return (file_exists($up) && !file_exists(dirname(ABSPATH) . '/wp-settings.php')) ? $up : '';
    }

    /* ---------------------------------------------------------------- scan */

    /**
     * Write the list of files to back up (one archive path per line).
     *
     * @return array|WP_Error count and total bytes.
     */
    public static function scan($list_path, $include_uploads) {
        $fh = fopen($list_path, 'wb');
        if (!$fh) {
            return new WP_Error('files_scan', __('Could not create the file list in the backup folder.', 'korisec'));
        }
        $count = 0;
        $bytes = 0;
        $root = rtrim(str_replace('\\', '/', WP_CONTENT_DIR), '/');
        $skip = self::excluded_top();
        if (!$include_uploads) {
            $skip[] = 'uploads';
        }
        $top = scandir($root);
        foreach ($top ? $top : array() as $entry) {
            if ($entry === '.' || $entry === '..' || in_array($entry, $skip, true) || preg_match('/^korisec-backups-[a-f0-9]{16}$/', $entry)) {
                continue;
            }
            $path = $root . '/' . $entry;
            if (is_link($path)) {
                continue;
            }
            if (is_file($path)) {
                fwrite($fh, 'wp-content/' . $entry . "\n");
                $count++;
                $bytes += (int) filesize($path);
                continue;
            }
            if (!is_dir($path)) {
                continue;
            }
            fwrite($fh, 'wp-content/' . $entry . "/\n");
            try {
                $it = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS),
                    RecursiveIteratorIterator::SELF_FIRST,
                    RecursiveIteratorIterator::CATCH_GET_CHILD
                );
                foreach ($it as $file) {
                    if ($file->isLink()) {
                        continue;
                    }
                    $rel = 'wp-content/' . ltrim(substr(str_replace('\\', '/', $file->getPathname()), strlen($root)), '/');
                    if (strpos($rel, "\n") !== false) {
                        continue;
                    }
                    if ($file->isDir()) {
                        fwrite($fh, $rel . "/\n");
                    } elseif ($file->isFile() && $file->isReadable()) {
                        $size = (int) $file->getSize();
                        if ($size > self::MAX_FILE) {
                            continue;
                        }
                        fwrite($fh, $rel . "\n");
                        $count++;
                        $bytes += $size;
                    }
                }
            } catch (Exception $e) {
                fclose($fh);
                return new WP_Error('files_scan', sprintf(__('Could not read part of wp-content: %s', 'korisec'), $e->getMessage()));
            }
        }
        if (self::config_path() !== '') {
            fwrite($fh, "wp-config.php\n");
            $count++;
            $bytes += (int) filesize(self::config_path());
        }
        fclose($fh);
        return array('count' => $count, 'bytes' => $bytes);
    }

    private static function source_path($archive_path) {
        if ($archive_path === 'wp-config.php') {
            return self::config_path();
        }
        return rtrim(WP_CONTENT_DIR, '/\\') . '/' . substr(rtrim($archive_path, '/'), strlen('wp-content/'));
    }

    /* --------------------------------------------------------- tar writer */

    private static function octal($value, $len) {
        return str_pad(decoct($value), $len - 1, '0', STR_PAD_LEFT) . "\0";
    }

    private static function tar_header($name, $size, $mtime, $type, $mode) {
        $out = '';
        if (strlen($name) > 99) {
            $out .= self::tar_header('././@LongLink', strlen($name) + 1, 0, 'L', 0644);
            $data = $name . "\0";
            $out .= $data . str_repeat("\0", (512 - strlen($data) % 512) % 512);
            $name = substr($name, 0, 99);
        }
        $h = str_pad($name, 100, "\0")
            . self::octal($mode, 8)
            . self::octal(0, 8)
            . self::octal(0, 8)
            . self::octal($size, 12)
            . self::octal(max(0, (int) $mtime), 12)
            . '        '
            . $type
            . str_repeat("\0", 100)
            . "ustar\0" . '00'
            . str_repeat("\0", 32 + 32 + 8 + 8 + 155 + 12);
        $sum = 0;
        for ($i = 0; $i < 512; $i++) {
            $sum += ord($h[$i]);
        }
        $h = substr_replace($h, str_pad(decoct($sum), 6, '0', STR_PAD_LEFT) . "\0 ", 148, 8);
        return $out . $h;
    }

    public static function archive_init() {
        return array('list_offset' => 0, 'entry' => null, 'files' => 0, 'bytes' => 0);
    }

    /**
     * Stream files into the encrypted tar until the deadline.
     *
     * @return bool|WP_Error true when complete.
     */
    public static function archive_step($list_path, array &$cur, array &$writer, $deadline) {
        $buffer = '';
        $flush = function ($force) use (&$buffer, &$writer) {
            if ($buffer === '' || (!$force && strlen($buffer) < self::RECORD_BYTES)) {
                return true;
            }
            $r = Korisec_Backup_Crypto::writer_push($writer, $buffer);
            $buffer = '';
            return $r;
        };
        $list = fopen($list_path, 'rb');
        if (!$list) {
            return new WP_Error('files_archive', __('The file list for this backup is missing.', 'korisec'));
        }
        fseek($list, $cur['list_offset']);

        while (true) {
            if ($cur['entry'] === null) {
                $line = fgets($list);
                if ($line === false) {
                    break;
                }
                $cur['list_offset'] = ftell($list);
                $name = rtrim($line, "\n");
                if ($name === '') {
                    continue;
                }
                $is_dir = substr($name, -1) === '/';
                $src = self::source_path($name);
                if ($is_dir) {
                    $buffer .= self::tar_header($name, 0, @filemtime($src), '5', 0755);
                    continue;
                }
                clearstatcache(true, $src);
                if (!is_file($src) || !is_readable($src)) {
                    continue;
                }
                $size = (int) filesize($src);
                $buffer .= self::tar_header($name, $size, @filemtime($src), '0', 0644);
                $cur['entry'] = array('path' => $name, 'size' => $size, 'done' => 0);
            }

            $entry = &$cur['entry'];
            $src = self::source_path($entry['path']);
            $fh = @fopen($src, 'rb');
            if ($fh && $entry['done'] > 0) {
                fseek($fh, $entry['done']);
            }
            while ($entry['done'] < $entry['size']) {
                $want = min(self::READ_BYTES, $entry['size'] - $entry['done']);
                $chunk = $fh ? fread($fh, $want) : '';
                if ($chunk === false || $chunk === '') {
                    $chunk = str_repeat("\0", $want);
                }
                $buffer .= $chunk;
                $entry['done'] += strlen($chunk);
                $cur['bytes'] += strlen($chunk);
                $r = $flush(false);
                if (is_wp_error($r)) {
                    if ($fh) {
                        fclose($fh);
                    }
                    fclose($list);
                    return $r;
                }
                if (microtime(true) >= $deadline && $entry['done'] < $entry['size']) {
                    if ($fh) {
                        fclose($fh);
                    }
                    fclose($list);
                    unset($entry);
                    $r = $flush(true);
                    return is_wp_error($r) ? $r : false;
                }
            }
            if ($fh) {
                fclose($fh);
            }
            $pad = (512 - $entry['size'] % 512) % 512;
            $buffer .= str_repeat("\0", $pad);
            unset($entry);
            $cur['entry'] = null;
            $cur['files']++;
            $r = $flush(false);
            if (is_wp_error($r)) {
                fclose($list);
                return $r;
            }
            if (microtime(true) >= $deadline) {
                fclose($list);
                $r = $flush(true);
                return is_wp_error($r) ? $r : false;
            }
        }
        fclose($list);
        $buffer .= str_repeat("\0", 1024);
        $r = $flush(true);
        if (is_wp_error($r)) {
            return $r;
        }
        $r = Korisec_Backup_Crypto::writer_close($writer);
        return is_wp_error($r) ? $r : true;
    }

    /* ------------------------------------------------------ tar extractor */

    public static function extract_init($staging) {
        return array(
            'staging' => $staging,
            'mode' => 'header',
            'carry' => '',
            'remaining' => 0,
            'pad' => 0,
            'out' => '',
            'longname' => '',
            'pending_name' => '',
            'files' => 0,
            'ended' => false,
        );
    }

    /** Map an archive path to a safe staging path, or '' to skip. */
    private static function safe_target($staging, $name) {
        $name = str_replace('\\', '/', $name);
        if ($name === '' || strpos($name, "\0") !== false || $name[0] === '/' || preg_match('#(^|/)\.\.(/|$)#', $name) || preg_match('/^[a-zA-Z]:/', $name)) {
            return '';
        }
        if (strpos($name, 'wp-content/') !== 0) {
            return '';
        }
        $rel = trim(substr($name, strlen('wp-content/')), '/');
        if ($rel === '') {
            return '';
        }
        $first = explode('/', $rel)[0];
        if (preg_match('/^korisec-backups-[a-f0-9]{16}$/', $first)) {
            return '';
        }
        if (strpos($rel, 'plugins/' . self::plugin_dirname()) === 0 && ($rel === 'plugins/' . self::plugin_dirname() || strpos($rel, 'plugins/' . self::plugin_dirname() . '/') === 0)) {
            return '';
        }
        return rtrim($staging, '/') . '/wp-content/' . $rel;
    }

    private static function parse_octal($field) {
        $field = trim(str_replace("\0", ' ', $field));
        return $field === '' ? 0 : octdec($field);
    }

    /**
     * Extract decrypted tar records into the staging folder until the deadline.
     *
     * @return bool|WP_Error true when complete.
     */
    public static function extract_step(array &$cur, array &$reader, $deadline) {
        while (microtime(true) < $deadline) {
            $block = Korisec_Backup_Crypto::reader_next($reader);
            if (is_wp_error($block)) {
                return $block;
            }
            if ($block === null) {
                return true;
            }
            $data = base64_decode($cur['carry']) . $block;
            $cur['carry'] = '';
            $pos = 0;
            $len = strlen($data);
            while ($pos < $len && !$cur['ended']) {
                if ($cur['mode'] === 'header') {
                    if ($len - $pos < 512) {
                        break;
                    }
                    $h = substr($data, $pos, 512);
                    $pos += 512;
                    if (trim($h, "\0") === '') {
                        $cur['ended'] = true;
                        break;
                    }
                    $stored = self::parse_octal(substr($h, 148, 8));
                    $calc = 0;
                    for ($i = 0; $i < 512; $i++) {
                        $calc += ($i >= 148 && $i < 156) ? 32 : ord($h[$i]);
                    }
                    if ($stored !== $calc) {
                        return new WP_Error('backup_corrupt', __('The files archive is damaged (bad header checksum).', 'korisec'));
                    }
                    $name = rtrim(substr($h, 0, 100), "\0");
                    if ($cur['pending_name'] !== '') {
                        $name = $cur['pending_name'];
                        $cur['pending_name'] = '';
                    }
                    $type = $h[156];
                    $size = self::parse_octal(substr($h, 124, 12));
                    $cur['remaining'] = $size;
                    $cur['pad'] = (512 - $size % 512) % 512;
                    $cur['out'] = '';
                    if ($type === 'L') {
                        $cur['mode'] = 'longname';
                        $cur['longname'] = '';
                        continue;
                    }
                    $target = self::safe_target($cur['staging'], $name);
                    if ($type === '5') {
                        if ($target !== '') {
                            wp_mkdir_p($target);
                        }
                        $cur['mode'] = 'header';
                        continue;
                    }
                    if (($type === '0' || $type === "\0") && $target !== '') {
                        wp_mkdir_p(dirname($target));
                        file_put_contents($target, '');
                        $cur['out'] = $target;
                        $cur['files']++;
                    }
                    $cur['mode'] = 'data';
                    if ($size === 0) {
                        $cur['mode'] = $cur['pad'] ? 'pad' : 'header';
                    }
                    continue;
                }
                if ($cur['mode'] === 'longname') {
                    $take = min($cur['remaining'], $len - $pos);
                    $cur['longname'] .= substr($data, $pos, $take);
                    $pos += $take;
                    $cur['remaining'] -= $take;
                    if (strlen($cur['longname']) > 4096) {
                        return new WP_Error('backup_corrupt', __('The files archive has an invalid long file name.', 'korisec'));
                    }
                    if ($cur['remaining'] === 0) {
                        $cur['pending_name'] = rtrim($cur['longname'], "\0");
                        $cur['mode'] = $cur['pad'] ? 'pad' : 'header';
                    }
                    continue;
                }
                if ($cur['mode'] === 'data') {
                    $take = min($cur['remaining'], $len - $pos);
                    if ($cur['out'] !== '' && $take > 0) {
                        if (file_put_contents($cur['out'], substr($data, $pos, $take), FILE_APPEND) === false) {
                            return new WP_Error('files_extract', __('Could not write restored files (disk full or permissions).', 'korisec'));
                        }
                    }
                    $pos += $take;
                    $cur['remaining'] -= $take;
                    if ($cur['remaining'] === 0) {
                        $cur['mode'] = $cur['pad'] ? 'pad' : 'header';
                    }
                    continue;
                }
                if ($cur['mode'] === 'pad') {
                    $take = min($cur['pad'], $len - $pos);
                    $pos += $take;
                    $cur['pad'] -= $take;
                    if ($cur['pad'] === 0) {
                        $cur['mode'] = 'header';
                    }
                }
            }
            if ($pos < $len && !$cur['ended']) {
                $cur['carry'] = base64_encode(substr($data, $pos));
            }
            if (!empty($reader['done'])) {
                return true;
            }
        }
        return false;
    }

    /* ---------------------------------------------------------------- swap */

    /**
     * Swap staged top-level wp-content entries into place.
     *
     * @return array|WP_Error Record of moves for undo.
     */
    public static function swap_in($staging, $rollback) {
        $live_root = rtrim(WP_CONTENT_DIR, '/\\');
        $staged_root = rtrim($staging, '/') . '/wp-content';
        if (!is_dir($staged_root)) {
            return array('moves' => array(), 'rollback' => $rollback);
        }
        if (!wp_mkdir_p($rollback)) {
            return new WP_Error('files_swap', __('Could not create the rollback folder.', 'korisec'));
        }
        $entries = array_values(array_diff(scandir($staged_root), array('.', '..')));
        $moves = array();
        $own = self::plugin_dirname();
        foreach ($entries as $entry) {
            $live = $live_root . '/' . $entry;
            $staged = $staged_root . '/' . $entry;
            $back = rtrim($rollback, '/') . '/' . $entry;
            if ($entry === 'plugins' && is_dir($live . '/' . $own)) {
                wp_mkdir_p($staged);
                if (!@rename($live . '/' . $own, $staged . '/' . $own)) {
                    self::undo_moves($moves, $rollback);
                    return new WP_Error('files_swap', __('Could not carry the Korisec plugin into the restored plugins folder.', 'korisec'));
                }
                $moves[] = array('type' => 'own_plugin', 'entry' => $entry, 'from' => $live . '/' . $own, 'to' => $staged . '/' . $own);
            }
            $had_live = file_exists($live) || is_link($live);
            if ($had_live && !@rename($live, $back)) {
                self::undo_moves($moves, $rollback);
                /* translators: %s: folder name */
                return new WP_Error('files_swap', sprintf(__('Could not move wp-content/%s aside (it may be on a different disk). Nothing was changed.', 'korisec'), $entry));
            }
            if (!@rename($staged, $live)) {
                if ($had_live) {
                    @rename($back, $live);
                }
                self::undo_moves($moves, $rollback);
                /* translators: %s: folder name */
                return new WP_Error('files_swap', sprintf(__('Could not move restored wp-content/%s into place. Nothing was changed.', 'korisec'), $entry));
            }
            $moves[] = array('type' => 'swap', 'entry' => $entry, 'had_live' => $had_live);
        }
        return array('moves' => $moves, 'rollback' => $rollback);
    }

    private static function undo_moves(array $moves, $rollback) {
        $live_root = rtrim(WP_CONTENT_DIR, '/\\');
        $own = self::plugin_dirname();
        $trash = rtrim($rollback, '/') . '-undo';
        wp_mkdir_p($trash);
        foreach (array_reverse($moves) as $m) {
            $live = $live_root . '/' . $m['entry'];
            $back = rtrim($rollback, '/') . '/' . $m['entry'];
            if ($m['type'] === 'own_plugin') {
                if (!empty($m['to']) && !file_exists($m['from']) && file_exists($m['to'])) {
                    @rename($m['to'], $m['from']);
                }
                continue;
            }
            if ($m['entry'] === 'plugins' && is_dir($live . '/' . $own)) {
                wp_mkdir_p($back);
                @rename($live . '/' . $own, $back . '/' . $own);
            }
            if (file_exists($live)) {
                @rename($live, $trash . '/' . $m['entry']);
            }
            if (!empty($m['had_live']) && file_exists($back)) {
                @rename($back, $live);
            }
        }
        Korisec_Backup_Store::rrmdir($trash);
        return true;
    }

    /** Undo a completed swap_in(). */
    public static function swap_back(array $record) {
        return self::undo_moves($record['moves'], $record['rollback']);
    }
}
