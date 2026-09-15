# Korisec WordPress plugin

Official WordPress client for [Korisec](https://korisec.com) hosted security checks.

- Product page: https://korisec.com/wordpress/
- Changelog: https://korisec.com/wordpress/#changelog
- WordPress.org: https://wordpress.org/plugins/korisec/
- License: GPLv2 or later

This repository is **only** the installable plugin (PHP, CSS, JS, `readme.txt`). It is a public source mirror. After WordPress.org lists the plugin, install and update from WordPress.org — not from a zip on this repo.

The Korisec scanning service, API, and dashboard are separate and are not in this repository.

## What it does

After you paste a `kr_live_…` plugin key from your Korisec account, the plugin:

1. Verifies the site and binds the key to this host
2. Sends WordPress core, plugin, and theme versions so cloud checks can include software that is not visible from the public internet
3. Lets you start a cloud check from wp-admin and show grade, findings, and history
4. Limits failed wp-login attempts locally (on by default; no Korisec API call)

Scans run on Korisec workers. This plugin does not run port scans or other scanners inside WordPress.

## Install

1. Create an account at https://app.korisec.com/signup and add a plugin key
2. Install the plugin from WordPress.org (or this source while the listing is in review)
3. Open **Korisec** in wp-admin, paste the key, and Connect

## Contributing

Please open issues on this repo for the WordPress plugin only. Account, billing, and scan-engine questions: hello@korisec.com.
