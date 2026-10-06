<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Remote storage for backups. Upload and download are resumable: callers keep the
 * returned session array between requests and call again until 'done' is true.
 */
interface Korisec_Storage_Provider {
    public function id();

    public function is_connected();

    /**
     * @param array $session Empty to start; previously returned session to resume.
     * @return array|WP_Error Session with 'done' and, when done, 'remote_id', 'size', 'md5'.
     */
    public function upload_step($local_path, $remote_name, array $app_properties, array $session, $deadline);

    /** @return array|WP_Error Session with 'done'. */
    public function download_step($remote_id, $destination, array $session, $deadline);

    /** @return true|WP_Error */
    public function delete($remote_id);

    /** @return array|WP_Error id, size, md5, trashed, app_properties */
    public function get_metadata($remote_id);
}
