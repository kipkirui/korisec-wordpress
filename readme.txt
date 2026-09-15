=== Korisec Security – Vulnerability Scanner and Login Protection ===
Contributors: korisec
Tags: security, vulnerability scanner, login security, wordpress security, brute force
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.12
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Hosted vulnerability checks and login protection for WordPress. Scans run in Korisec’s cloud — not on your server.

== Description ==

Korisec is a **hosted** website security service. This plugin is the official WordPress client: it does not run port scans, Nuclei, or other scanners inside WordPress.

After you paste a plugin key from your Korisec account, the plugin:

1. Verifies this site with Korisec and binds the key to this host
2. Sends WordPress core, plugin, and theme versions so cloud checks can include software that is not visible from the public internet
3. Lets you start a cloud check from wp-admin and show grade, findings, and history
4. Lets the **billing owner** who issued the key manage plan, team seats, PDF reports, and alerts (Telegram, Slack, WhatsApp, webhook)

Without a key, login protection and optional exposure remedies (XML-RPC, public usernames, install.php) still run locally. Those features do not send data to Korisec.

Paid plans, daily scan limits, and white-label PDFs are features of the **Korisec service**, not locked code inside this plugin. The plugin’s PHP is fully available under GPLv2 or later.

= External service =

This plugin requires a Korisec account and talks only to `https://api.korisec.com` (unless you set `KORISEC_API_BASE` in wp-config.php).

* Terms of Use: https://korisec.com/terms.html
* Privacy Policy: https://korisec.com/privacy.html
* Plugin page: https://korisec.com/wordpress/
* Dashboard: https://app.korisec.com

Nothing is sent until a site administrator pastes a `kr_live_…` key and clicks Connect.

= Data sent after Connect =

Typical payloads include this site’s URL and host, WordPress and PHP versions, names and versions of installed plugins/themes (and whether they are active), heartbeat, scan start/status requests, and billing/team/alert settings for the Korisec account that issued the key.

== Installation ==

1. Create a Korisec account at https://app.korisec.com/signup and add a plugin key under Account → API keys
2. Install this plugin and activate it
3. Open **Korisec** in wp-admin, paste the key, and Connect (you agree to Korisec’s terms and privacy policy)
4. Run a check, or wait for Korisec’s scheduled scans

The plugin connects to Korisec automatically. You do not need to edit wp-config.php.

== Frequently Asked Questions ==

= Does this plugin scan my server? =

No. Checks run on Korisec workers. The plugin only reports inventory and displays results.

= Why do I need a key? =

The key authenticates this site to the Korisec API. It is not a license gate for local scanner code. Without a key the plugin does not contact Korisec.

= What if my Korisec plan ends? =

The hosted service pauses cloud checks until the account is renewed. The plugin itself remains installed and GPLv2 licensed.

= How do I stop sending data? =

Disconnect on the Connection tab, or delete the plugin. Deleting removes the stored key from WordPress. Korisec account history is managed in the Korisec dashboard.

= Can I point the plugin at my own API? =

Yes. In wp-config.php set `define( 'KORISEC_API_BASE', 'https://your-host.example' );`

== Changelog ==

= 1.0.12 =
* Fix Actions-tab Update links showing “The link you followed has expired” (nonce URLs were HTML-escaped twice)

= 1.0.11 =
* Actions tab: update outdated plugins/themes with deep links, plus one-click remedies for XML-RPC, public usernames, and wp-admin/install.php
* Richer inventory (plugin file paths and WordPress-known updates) posted before each check

= 1.0.10 =
* Directory display name: Korisec Security – Vulnerability Scanner and Login Protection
* SEO-focused short description and tags (vulnerability scanner, login security, brute force)

= 1.0.9 =
* Findings show CVE links, known-exploited badges, and one-click links to Plugins / Themes / Updates when a fix version is known
* Login protection: limit failed wp-login attempts by IP (local; on by default; configurable under Protection)

= 1.0.8 =
* WordPress Plugin Check (plugin-repo) fixes: nonce in AJAX handlers, JSON payload sanitization, no false Cloudflare offload string

= 1.0.7 =
* Reliable connection is on automatically so site owners do not edit wp-config.php

= 1.0.6 =
* WordPress.org packaging: privacy policy suggestion, uninstall cleanup, i18n, service documentation
* Origin IP pin is off unless KORISEC_PIN_ORIGIN is defined
* Plugin key is sanitized before storage

= 1.0.5 =
* Horizontal tabs for billing, team seats, PDF / white-label reports, and alerts
* Plugin key can only manage the Korisec billing account that issued it

= 1.0.4 =
* In-admin dashboard: grade, score, grouped findings, recent checks, live progress

= 1.0.3 =
* Optional origin pin for hosts that cannot reach api.korisec.com through Cloudflare

= 1.0.2 =
* Only treat Cloudflare challenge pages as Bot Fight blocks

= 1.0.1 =
* Clearer connect errors when the API is unreachable
* WordPress AJAX no longer returns HTTP 403 for Korisec API errors

= 1.0.0 =
* First release: connect, inventory, run check, grade

== Upgrade Notice ==

= 1.0.12 =
Fixes broken Update buttons on the Actions tab.

= 1.0.11 =
Actions tab with update links and one-click exposure remedies.

= 1.0.10 =
Clearer plugin title and directory tags for security search.

= 1.0.9 =
Actionable findings plus local login attempt limiting.

= 1.0.8 =
WordPress.org Plugin Check clean-up.

= 1.0.7 =
Connects more reliably without editing wp-config.php.

= 1.0.6 =
Privacy and uninstall cleanup.
