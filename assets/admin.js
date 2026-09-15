(function () {
  var cfg = window.korisecAdmin || {};
  var i18n = cfg.i18n || {};
  var statusEl = document.getElementById('korisec-status');
  var pollTimer = null;
  var loadedTabs = {};
  var severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  var severityLabel = {
    critical: i18n.critical || 'Critical',
    high: i18n.high || 'High',
    medium: i18n.medium || 'Medium',
    low: i18n.low || 'Low',
    info: i18n.info || 'Info',
  };

  function t(key) {
    return i18n[key] != null && i18n[key] !== '' ? i18n[key] : key;
  }

  function tf(key) {
    var str = t(key);
    var args = Array.prototype.slice.call(arguments, 1);
    var i = 0;
    str = String(str).replace(/%%/g, '\0');
    str = str.replace(/%(\d+)\$s/g, function (_, n) {
      var v = args[Number(n) - 1];
      return v == null ? '' : String(v);
    });
    str = str.replace(/%s/g, function () {
      var v = args[i];
      i += 1;
      return v == null ? '' : String(v);
    });
    return str.replace(/\0/g, '%');
  }

  function post(action, extra) {
    var body = new URLSearchParams();
    body.set('action', action);
    body.set('nonce', cfg.nonce || '');
    if (extra) {
      Object.keys(extra).forEach(function (key) {
        body.set(key, extra[key]);
      });
    }
    return fetch(cfg.ajaxUrl, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
      body: body.toString(),
    }).then(function (res) {
      return res.json().then(function (data) {
        data._http = res.status;
        return data;
      });
    });
  }

  function account(op, payload) {
    var extra = { op: op };
    if (payload !== undefined) extra.payload = JSON.stringify(payload);
    return post('korisec_account', extra);
  }

  function failMessage(data) {
    if (data && data.data && data.data.message) return data.data.message;
    if (data && data.message) return data.message;
    return t('genericError');
  }

  function setStatus(text) {
    if (statusEl) statusEl.textContent = text || '';
  }

  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function pdfHref(kind, scanId) {
    var url = (cfg.pdfUrl || '') + '?action=korisec_pdf&kind=' + encodeURIComponent(kind) + '&_wpnonce=' + encodeURIComponent(cfg.nonce || '');
    if (scanId) url += '&scan_id=' + encodeURIComponent(scanId);
    return url;
  }

  function countsFrom(findings, provided) {
    var counts = provided && typeof provided === 'object'
      ? {
          critical: provided.critical || 0,
          high: provided.high || 0,
          medium: provided.medium || 0,
          low: provided.low || 0,
          info: provided.info || 0,
        }
      : { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    if ((!provided || !Object.keys(provided).length) && findings && findings.length) {
      findings.forEach(function (item) {
        var sev = String(item.severity || 'info').toLowerCase();
        if (!counts[sev] && counts[sev] !== 0) sev = 'info';
        counts[sev] += 1;
      });
    }
    return counts;
  }

  function formatWhen(iso) {
    if (!iso) return '—';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleString();
  }

  function renderHero(payload) {
    var el = document.getElementById('korisec-hero');
    if (!el) return;
    var scan = payload.scan || {};
    var findings = payload.findings || [];
    var counts = countsFrom(findings, payload.severity_counts);
    var grade = scan.grade || '—';
    var score = scan.score == null || scan.score === '' ? '—' : String(scan.score);
    var host = payload.host || cfg.host || t('thisSiteHost');
    var when = scan.finished_at || scan.created_at;
    var chips = severityOrder.map(function (sev) {
      return '<span class="korisec-chip korisec-chip-' + sev + '">' + counts[sev] + ' ' + severityLabel[sev].toLowerCase() + '</span>';
    }).join('');
    var pdf = scan.id && scan.status === 'done'
      ? '<a class="button" href="' + esc(pdfHref('scan', scan.id)) + '">' + esc(t('downloadPdf')) + '</a>'
      : '';
    el.innerHTML =
      '<div class="korisec-hero">' +
        '<div class="korisec-grade korisec-grade-' + esc(grade) + '">' + esc(grade) + '</div>' +
        '<div>' +
          '<h2>' + esc(host) + '</h2>' +
          '<p>' + esc(t('score')) + ' ' + esc(score) + (when ? ' · ' + esc(t('lastCheck')) + ' ' + esc(formatWhen(when)) : ' · ' + esc(t('noCheckYet'))) + '</p>' +
          '<div class="korisec-chips">' + chips + '</div>' +
        '</div>' +
        '<div class="korisec-actions">' +
          '<button type="button" class="button button-primary" id="korisec-run">' + esc(t('runCheck')) + '</button>' +
          pdf +
        '</div>' +
      '</div>';
    bindRun();
  }

  function renderProgress(scan) {
    var el = document.getElementById('korisec-progress');
    if (!el) return;
    var status = scan && scan.status;
    if (status !== 'queued' && status !== 'running') {
      el.className = 'korisec-progress is-hidden';
      el.innerHTML = '';
      return;
    }
    var pct = typeof scan.progress_pct === 'number' ? scan.progress_pct : 8;
    var label = scan.progress_label || (status === 'queued' ? t('waitingQueue') : t('checkRunning'));
    el.className = 'korisec-progress';
    el.innerHTML =
      '<strong>' + esc(label) + '</strong>' +
      '<div class="korisec-progress-bar"><span style="width:' + Math.max(4, Math.min(100, pct)) + '%"></span></div>';
  }

  function findingMeta(item) {
    if (item && item.meta && typeof item.meta === 'object') return item.meta;
    return {};
  }

  function updateUrls() {
    return cfg.updateUrls || { plugins: {}, themes: {}, core: cfg.updatesUrl || '' };
  }

  function pluginUpdateUrl(meta) {
    var map = updateUrls().plugins || {};
    if (meta.file && map[meta.file]) return map[meta.file];
    if (meta.slug && map[meta.slug]) return map[meta.slug];
    return '';
  }

  function themeUpdateUrl(meta) {
    var map = updateUrls().themes || {};
    if (meta.stylesheet && map[meta.stylesheet]) return map[meta.stylesheet];
    if (meta.slug && map[meta.slug]) return map[meta.slug];
    return '';
  }

  function findingActionsHtml(item) {
    var meta = findingMeta(item);
    var parts = [];
    var cve = meta.cve ? String(meta.cve) : '';
    var tracker = meta.tracker_url
      ? String(meta.tracker_url)
      : (cve ? 'https://korisec.com/cve/' + cve.toLowerCase() + '/' : '');
    var type = String(meta.type || '').toLowerCase();
    var fixed = meta.fixed_in ? String(meta.fixed_in) : '';
    var name = meta.name ? String(meta.name) : (meta.slug ? String(meta.slug) : '');

    if (meta.is_kev) {
      parts.push('<span class="korisec-badge korisec-badge-kev">' + esc(t('kevBadge')) + '</span>');
    }
    if (cve && tracker) {
      parts.push(
        '<a class="button button-small" href="' + esc(tracker) + '" target="_blank" rel="noopener noreferrer">' +
          esc(t('viewCve')) + (cve ? ' · ' + esc(cve) : '') +
        '</a>'
      );
    }
    if (fixed && (type === 'plugin' || type === 'theme' || type === 'core')) {
      parts.push('<span class="korisec-badge">' + esc(tf('updateTo', fixed)) + '</span>');
    }

    if (type === 'plugin') {
      var pluginUrl = pluginUpdateUrl(meta);
      if (pluginUrl) {
        parts.push('<a class="button button-primary button-small" href="' + esc(pluginUrl) + '">' + esc(name ? tf('updateNamed', name) : t('openPluginUpdates')) + '</a>');
      } else if (cfg.pluginsUpgradeUrl || cfg.pluginsUrl) {
        parts.push('<a class="button button-primary button-small" href="' + esc(cfg.pluginsUpgradeUrl || cfg.pluginsUrl) + '">' + esc(t('openPluginUpdates')) + '</a>');
      }
    } else if (type === 'theme') {
      var themeUrl = themeUpdateUrl(meta);
      if (themeUrl) {
        parts.push('<a class="button button-primary button-small" href="' + esc(themeUrl) + '">' + esc(name ? tf('updateNamed', name) : t('openThemeUpdates')) + '</a>');
      } else if (cfg.themesUrl) {
        parts.push('<a class="button button-primary button-small" href="' + esc(cfg.themesUrl) + '">' + esc(t('openThemeUpdates')) + '</a>');
      }
    } else if (type === 'core' || item.category === 'wordpress' || item.category === 'wordpress_passive') {
      var coreUrl = updateUrls().core || cfg.updatesUrl;
      if (coreUrl && (type === 'core' || meta.fixed_in)) {
        parts.push('<a class="button button-primary button-small" href="' + esc(coreUrl) + '">' + esc(t('openCoreUpdates')) + '</a>');
      }
    }

    var remedy = meta.remedy ? String(meta.remedy) : '';
    if (remedy) {
      var catalog = remedyById(remedy);
      if (catalog && catalog.enabled) {
        parts.push('<span class="korisec-badge">' + esc(t('remedyAlreadyOn')) + '</span>');
      } else {
        parts.push(
          '<button type="button" class="button button-primary button-small korisec-apply-remedy" data-remedy="' + esc(remedy) + '">' +
            esc(t('applyRemedy')) +
          '</button>'
        );
      }
    }
    if (!parts.length) return '';
    return '<div class="korisec-finding-actions">' + parts.join(' ') + '</div>';
  }

  function remedyById(id) {
    var list = cfg.remedies || [];
    for (var i = 0; i < list.length; i++) {
      if (list[i] && list[i].id === id) return list[i];
    }
    return null;
  }

  function syncRemedyControls(remedies, settings) {
    if (settings) cfg.hardening = settings;
    if (remedies) cfg.remedies = remedies;
    var map = {};
    (cfg.remedies || []).forEach(function (r) { map[r.id] = r; });
    var xml = document.getElementById('korisec-disable-xmlrpc');
    var users = document.getElementById('korisec-block-users');
    var install = document.getElementById('korisec-block-install');
    if (xml && map.disable_xmlrpc) xml.checked = !!map.disable_xmlrpc.enabled;
    if (users && map.block_user_enumeration) users.checked = !!map.block_user_enumeration.enabled;
    if (install && map.block_install_php) install.checked = !!map.block_install_php.enabled;
  }

  function applyRemedy(remedy, btn) {
    if (btn) btn.disabled = true;
    return post('korisec_apply_remedy', { remedy: remedy }).then(function (data) {
      if (btn) btn.disabled = false;
      if (!data || !data.success) {
        window.alert(failMessage(data) || t('remedyFailed'));
        return;
      }
      syncRemedyControls((data.data && data.data.remedies) || null, (data.data && data.data.settings) || null);
      window.alert((data.data && data.data.message) || t('remedyApplied'));
      renderActions(cfg.lastFindings || []);
      renderFindings(cfg.lastFindings || []);
    }).catch(function () {
      if (btn) btn.disabled = false;
      window.alert(t('remedyFailed'));
    });
  }

  function actionRowHtml(row) {
    var title = row.name || row.slug || t('finding');
    var typeLabel = row.type === 'theme' ? t('openThemeUpdates') : (row.type === 'core' ? t('openCoreUpdates') : (row.type === 'remedy' ? t('actionsRemedies') : t('openPluginUpdates')));
    var bits = [];
    if (row.version) bits.push(esc(t('installedVersion')) + ' ' + esc(row.version));
    if (row.new_version) bits.push(esc(t('availableVersion')) + ' ' + esc(row.new_version));
    if (row.fixed_in && row.fixed_in !== row.new_version) bits.push(esc(t('recommendedFix')) + ' ' + esc(row.fixed_in));
    if (row.cve) bits.push(esc(row.cve));
    var cta = '';
    if (row.remedy) {
      var catalog = remedyById(row.remedy);
      if (catalog && catalog.enabled) {
        cta = '<span class="korisec-badge">' + esc(t('remedyAlreadyOn')) + '</span>';
      } else {
        cta = '<button type="button" class="button button-primary korisec-apply-remedy" data-remedy="' + esc(row.remedy) + '">' + esc(t('applyRemedy')) + '</button>';
      }
    } else {
      var btnUrl = row.update_url || row.list_url || '';
      var btnLabel = row.update_url
        ? tf('updateNamed', title)
        : (row.type === 'theme' ? t('openThemeUpdates') : (row.type === 'core' ? t('openCoreUpdates') : t('openPluginUpdates')));
      if (btnUrl) {
        cta = '<a class="button button-primary" href="' + esc(btnUrl) + '">' + esc(btnLabel) + '</a>';
      }
    }
    return (
      '<article class="korisec-action-row">' +
        '<div class="korisec-action-main">' +
          '<strong>' + esc(title) + '</strong>' +
          '<div class="korisec-meta-row">' +
            '<span class="korisec-cat">' + esc(row.type || typeLabel) + '</span>' +
            (bits.length ? '<span class="korisec-cat">' + bits.join(' · ') + '</span>' : '') +
          '</div>' +
          (row.title ? '<p class="description">' + esc(row.title) + '</p>' : '') +
          (row.description ? '<p class="description">' + esc(row.description) + '</p>' : '') +
        '</div>' +
        (cta ? '<div class="korisec-action-cta">' + cta + '</div>' : '') +
      '</article>'
    );
  }

  function mergeActions(findings) {
    var local = cfg.localUpdates || {};
    var rows = [];
    var seen = {};

    function keyOf(type, slug, file) {
      return String(type || '') + '|' + String(slug || '') + '|' + String(file || '');
    }

    function add(row) {
      var k = keyOf(row.type, row.slug || row.remedy, row.file || row.stylesheet);
      if (seen[k]) return;
      seen[k] = true;
      rows.push(row);
    }

    (local.plugins || []).forEach(function (row) {
      row.source = 'wp';
      add(row);
    });
    (local.themes || []).forEach(function (row) {
      row.source = 'wp';
      add(row);
    });
    if (local.core) {
      local.core.source = 'wp';
      add(local.core);
    }

    (findings || []).forEach(function (item) {
      var meta = findingMeta(item);
      if (meta.remedy) {
        var catalog = remedyById(String(meta.remedy));
        add({
          type: 'remedy',
          remedy: String(meta.remedy),
          slug: String(meta.remedy),
          name: (catalog && catalog.title) || String(meta.remedy),
          description: (catalog && catalog.description) || (item.fix || ''),
          title: item.title || '',
          source: 'scan',
        });
      }
      var type = String(meta.type || '').toLowerCase();
      if (type !== 'plugin' && type !== 'theme' && type !== 'core') return;
      if (!meta.fixed_in && !meta.slug && type !== 'core') return;
      var updateUrl = '';
      if (type === 'plugin') updateUrl = pluginUpdateUrl(meta);
      else if (type === 'theme') updateUrl = themeUpdateUrl(meta);
      else updateUrl = updateUrls().core || cfg.updatesUrl || '';
      add({
        type: type,
        slug: meta.slug || '',
        file: meta.file || '',
        stylesheet: meta.stylesheet || meta.slug || '',
        name: meta.name || meta.slug || (type === 'core' ? 'WordPress' : ''),
        version: meta.version || '',
        new_version: meta.new_version || '',
        fixed_in: meta.fixed_in || '',
        cve: meta.cve || '',
        title: item.title || '',
        update_url: updateUrl,
        list_url: type === 'plugin'
          ? (cfg.pluginsUpgradeUrl || cfg.pluginsUrl)
          : (type === 'theme' ? cfg.themesUrl : cfg.updatesUrl),
        source: 'scan',
      });
    });

    return rows;
  }

  function renderActions(findings) {
    var el = document.getElementById('korisec-actions');
    if (!el) return;
    cfg.lastFindings = findings || [];
    var rows = mergeActions(findings);
    var html = '<div class="korisec-card korisec-actions-panel">';
    html += '<h2>' + esc(t('actionsTitle')) + '</h2>';
    html += '<p class="description">' + esc(t('actionsIntro')) + '</p>';
    if (!rows.length) {
      html += '<p>' + esc(t('actionsEmpty')) + '</p></div>';
      el.innerHTML = html;
      return;
    }
    var remedyRows = rows.filter(function (r) { return r.type === 'remedy'; });
    var localRows = rows.filter(function (r) { return r.source === 'wp'; });
    var scanRows = rows.filter(function (r) { return r.source === 'scan' && r.type !== 'remedy'; });
    if (remedyRows.length) {
      html += '<h3 class="korisec-actions-sub">' + esc(t('actionsRemedies')) + '</h3>';
      remedyRows.forEach(function (row) { html += actionRowHtml(row); });
    }
    if (localRows.length) {
      html += '<h3 class="korisec-actions-sub">' + esc(t('actionsFromWp')) + '</h3>';
      localRows.forEach(function (row) { html += actionRowHtml(row); });
    }
    if (scanRows.length) {
      html += '<h3 class="korisec-actions-sub">' + esc(t('actionsFromScan')) + '</h3>';
      scanRows.forEach(function (row) { html += actionRowHtml(row); });
    }
    html += '</div>';
    el.innerHTML = html;
  }

  function renderFindings(findings) {
    cfg.lastFindings = findings || [];
    var el = document.getElementById('korisec-findings');
    if (!el) return;
    findings = findings || [];
    if (!findings.length) {
      el.innerHTML = '<div class="korisec-card"><h2>' + esc(t('findings')) + '</h2><p>' + esc(t('noFindings')) + '</p></div>';
      return;
    }
    var groups = {};
    findings.forEach(function (item) {
      var sev = String(item.severity || 'info').toLowerCase();
      if (severityOrder.indexOf(sev) === -1) sev = 'info';
      if (!groups[sev]) groups[sev] = [];
      groups[sev].push(item);
    });
    var html = '<div class="korisec-findings-block"><h2>' + esc(t('findings')) + '</h2>';
    severityOrder.forEach(function (sev) {
      var items = groups[sev];
      if (!items || !items.length) return;
      var open = sev === 'critical' || sev === 'high' ? ' open' : '';
      html += '<details class="korisec-finding-group"' + open + '>';
      html += '<summary>' + severityLabel[sev] + ' · ' + items.length + '</summary>';
      items.forEach(function (item) {
        html +=
          '<article class="korisec-finding">' +
            '<div class="korisec-meta-row">' +
              '<span class="korisec-sev korisec-sev-' + esc(sev) + '">' + esc(severityLabel[sev]) + '</span>' +
              '<span class="korisec-cat">' + esc(item.category_label || item.category || '') + '</span>' +
              (item.target_host ? '<span class="korisec-cat">' + esc(item.target_host) + '</span>' : '') +
            '</div>' +
            '<strong>' + esc(item.title || t('finding')) + '</strong>' +
            (item.problem ? '<p><strong>' + esc(t('whatWeFound')) + '</strong> ' + esc(item.problem) + '</p>' : '') +
            (item.risk ? '<p><strong>' + esc(t('whyItMatters')) + '</strong> ' + esc(item.risk) + '</p>' : '') +
            (item.fix ? '<p><strong>' + esc(t('whatToDo')) + '</strong> ' + esc(item.fix) + '</p>' : '') +
            findingActionsHtml(item) +
          '</article>';
      });
      html += '</details>';
    });
    html += '</div>';
    el.innerHTML = html;
  }

  function renderHistory(rows) {
    var el = document.getElementById('korisec-history');
    if (!el) return;
    rows = rows || [];
    if (!rows.length) {
      el.innerHTML = '';
      return;
    }
    var body = rows.map(function (row) {
      var pdf = row.id && row.status === 'done'
        ? '<a href="' + esc(pdfHref('scan', row.id)) + '">' + esc(t('pdf')) + '</a>'
        : '—';
      return '<tr>' +
        '<td>' + esc(formatWhen(row.finished_at || row.created_at)) + '</td>' +
        '<td><strong>' + esc(row.grade || '—') + '</strong> · ' + esc(row.score == null ? '—' : row.score) + '</td>' +
        '<td>' + esc(row.status || '') + '</td>' +
        '<td>' + esc(row.findings_count == null ? '—' : row.findings_count) + '</td>' +
        '<td>' + pdf + '</td>' +
      '</tr>';
    }).join('');
    el.innerHTML =
      '<div class="korisec-card korisec-history">' +
        '<h2>' + esc(t('recentChecks')) + '</h2>' +
        '<table><thead><tr><th>' + esc(t('when')) + '</th><th>' + esc(t('grade')) + '</th><th>' + esc(t('status')) + '</th><th>' + esc(t('findings')) + '</th><th>' + esc(t('report')) + '</th></tr></thead><tbody>' +
        body +
        '</tbody></table></div>';
  }

  function paint(payload) {
    renderHero(payload || {});
    renderProgress((payload && payload.scan) || null);
    renderFindings((payload && payload.findings) || []);
    renderActions((payload && payload.findings) || []);
    renderHistory((payload && payload.history) || []);
  }

  function loadDashboard() {
    return post('korisec_dashboard').then(function (data) {
      if (!data || !data.success) {
        setStatus(failMessage(data));
        return;
      }
      setStatus('');
      paint(data.data || {});
    }).catch(function () {
      setStatus(t('couldNotLoadCheck'));
    });
  }

  function pollScan(scanId) {
    if (!scanId) return;
    setStatus(t('checkRunning'));
    window.clearInterval(pollTimer);
    pollTimer = window.setInterval(function () {
      post('korisec_scan_status', { scan_id: String(scanId) }).then(function (data) {
        if (!data || !data.success) {
          window.clearInterval(pollTimer);
          setStatus(failMessage(data));
          return;
        }
        var payload = data.data || {};
        var scan = payload.scan || {};
        renderProgress(scan);
        setStatus(scan.progress_label || '');
        if (scan.status === 'queued' || scan.status === 'running') return;
        window.clearInterval(pollTimer);
        loadDashboard();
      }).catch(function () {
        window.clearInterval(pollTimer);
        setStatus(t('couldNotRefresh'));
      });
    }, 3000);
  }

  function bindRun() {
    var runBtn = document.getElementById('korisec-run');
    if (!runBtn || runBtn.dataset.bound) return;
    runBtn.dataset.bound = '1';
    runBtn.addEventListener('click', function () {
      runBtn.disabled = true;
      setStatus(t('startingCheck'));
      post('korisec_run_check').then(function (data) {
        if (!data.success) {
          var existing = data.data && data.data.scan_id;
          if (existing) {
            pollScan(existing);
            return;
          }
          window.alert(failMessage(data));
          runBtn.disabled = false;
          setStatus('');
          return;
        }
        var scan = (data.data && data.data.scan) || {};
        renderProgress(scan);
        pollScan(scan.id);
      }).catch(function () {
        runBtn.disabled = false;
        setStatus(t('couldNotStart'));
      });
    });
  }

  function panel(id) {
    return document.getElementById('korisec-panel-' + id);
  }

  function showTab(name) {
    document.querySelectorAll('.korisec-tab').forEach(function (btn) {
      btn.classList.toggle('is-active', btn.getAttribute('data-tab') === name);
    });
    document.querySelectorAll('.korisec-panel').forEach(function (el) {
      el.classList.toggle('is-active', el.id === 'korisec-panel-' + name);
    });
    if (name !== 'checks' && name !== 'protection' && name !== 'connection' && name !== 'actions' && !loadedTabs[name]) {
      loadTab(name);
    }
  }

  function loadTab(name) {
    var el = panel(name);
    if (!el) return;
    if (name === 'connection' || name === 'protection' || name === 'actions') {
      loadedTabs[name] = true;
      return;
    }
    el.innerHTML = '<div class="korisec-card"><p>' + esc(t('loading')) + '</p></div>';
    var loader = {
      billing: loadBilling,
      team: loadTeam,
      reports: loadReports,
      alerts: loadAlerts,
    }[name];
    if (!loader) return;
    loader().then(function () {
      loadedTabs[name] = true;
    }).catch(function () {
      el.innerHTML = '<div class="korisec-card"><p>' + esc(t('couldNotLoadTab')) + '</p></div>';
    });
  }

  function intervalValue() {
    var picked = document.querySelector('input[name="korisec-interval"]:checked');
    return picked ? picked.value : 'monthly';
  }

  function loadBilling() {
    return account('billing').then(function (data) {
      var el = panel('billing');
      if (!data.success) {
        el.innerHTML = '<div class="korisec-card"><p>' + esc(failMessage(data)) + '</p></div>';
        return;
      }
      var d = data.data || {};
      var plans = d.plans || [];
      var html = '<div class="korisec-card">';
      html += '<h2>' + esc(t('billingTitle')) + '</h2>';
      html += '<p class="description">' + tf('billingIntro', '<strong>' + esc(d.owner_email || t('yourAccount')) + '</strong>') + '</p>';
      html += '<p>' + esc(t('currentPlan')) + ' <strong>' + esc(d.plan || '—') + '</strong>';
      if (d.trial_ends_at && String(d.plan) === 'trial') html += ' · trial ends ' + esc(formatWhen(d.trial_ends_at));
      html += '</p>';
      html += '<div class="korisec-interval">';
      html += '<label><input type="radio" name="korisec-interval" value="monthly" checked> ' + esc(t('monthly')) + '</label>';
      html += '<label><input type="radio" name="korisec-interval" value="annually"> ' + esc(tf('annuallyOff', d.annual_discount_pct || 20)) + '</label>';
      html += '</div>';
      html += '<div class="korisec-plans">';
      plans.forEach(function (plan) {
        html += '<div class="korisec-plan' + (plan.current ? ' is-current' : '') + '">';
        html += '<h3>' + esc(plan.name) + (plan.current ? ' <span>' + esc(t('current')) + '</span>' : '') + '</h3>';
        html += '<p class="korisec-price">' + esc(plan.price_label) + ' ' + esc(t('perMonth')) + '</p>';
        html += '<p>' + esc(plan.tagline || '') + '</p>';
        html += '<ul>' + (plan.bullets || []).map(function (b) { return '<li>' + esc(b) + '</li>'; }).join('') + '</ul>';
        if (!plan.current) {
          html += '<button type="button" class="button button-primary korisec-checkout" data-plan="' + esc(plan.id) + '">' + esc(tf('choosePlan', plan.name)) + '</button>';
        }
        html += '</div>';
      });
      html += '</div>';
      if (d.paystack_subscription_code) {
        html += '<p><button type="button" class="button korisec-cancel-plan">' + esc(t('cancelSub')) + '</button></p>';
      }
      html += '<p class="description">' + esc(t('paystackNote')) + '</p>';
      html += '</div>';
      el.innerHTML = html;
      el.querySelectorAll('.korisec-checkout').forEach(function (btn) {
        btn.addEventListener('click', function () {
          btn.disabled = true;
          account('checkout', { plan: btn.getAttribute('data-plan'), interval: intervalValue() }).then(function (res) {
            btn.disabled = false;
            if (!res.success) {
              window.alert(failMessage(res));
              return;
            }
            var url = res.data && res.data.authorization_url;
            if (url) window.open(url, '_blank', 'noopener');
            else window.alert(t('checkoutStarted'));
          }).catch(function () {
            btn.disabled = false;
            window.alert(t('couldNotCheckout'));
          });
        });
      });
      var cancelBtn = el.querySelector('.korisec-cancel-plan');
      if (cancelBtn) {
        cancelBtn.addEventListener('click', function () {
          if (!window.confirm(t('confirmCancel'))) return;
          cancelBtn.disabled = true;
          account('cancel', {}).then(function (res) {
            if (!res.success) {
              cancelBtn.disabled = false;
              window.alert(failMessage(res));
              return;
            }
            loadedTabs.billing = false;
            loadTab('billing');
          }).catch(function () {
            cancelBtn.disabled = false;
          });
        });
      }
    });
  }

  function loadTeam() {
    return account('team').then(function (data) {
      var el = panel('team');
      if (!data.success) {
        el.innerHTML = '<div class="korisec-card"><p>' + esc(failMessage(data)) + '</p></div>';
        return;
      }
      var d = data.data || {};
      var members = d.members || [];
      var html = '<div class="korisec-card">';
      html += '<h2>' + esc(t('teamTitle')) + '</h2>';
      html += '<p class="description">' + tf('teamIntro', '<strong>' + esc(d.owner_email || t('thisBilling')) + '</strong>') + '</p>';
      html += '<p>' + esc(tf('seatsUsed', d.seats_used || 0, d.seat_limit || 1, d.plan || '')) + '</p>';
      if (d.can_invite) {
        html += '<form id="korisec-invite-form" class="korisec-inline-form">';
        html += '<input type="email" name="email" class="regular-text" required placeholder="teammate@example.com">';
        html += '<select name="role"><option value="analyst">' + esc(t('analyst')) + '</option><option value="viewer">' + esc(t('viewer')) + '</option></select>';
        html += '<button type="submit" class="button button-primary">' + esc(t('invite')) + '</button>';
        html += '</form>';
      } else {
        html += '<p>' + esc(t('upgradeSeats')) + '</p>';
      }
      html += '<table class="korisec-table"><thead><tr><th>' + esc(t('email')) + '</th><th>' + esc(t('role')) + '</th><th>' + esc(t('status')) + '</th><th></th></tr></thead><tbody>';
      if (!members.length) {
        html += '<tr><td colspan="4">' + esc(t('noInvites')) + '</td></tr>';
      }
      members.forEach(function (m) {
        html += '<tr><td>' + esc(m.email) + '</td><td>' + esc(m.role) + '</td><td>' + esc(m.status) + '</td>';
        html += '<td><button type="button" class="button-link-delete korisec-remove-member" data-id="' + esc(m.id) + '">' + esc(t('remove')) + '</button></td></tr>';
      });
      html += '</tbody></table></div>';
      el.innerHTML = html;
      var form = document.getElementById('korisec-invite-form');
      if (form) {
        form.addEventListener('submit', function (e) {
          e.preventDefault();
          var email = form.email.value;
          var role = form.role.value;
          account('team_invite', { email: email, role: role }).then(function (res) {
            if (!res.success) {
              window.alert(failMessage(res));
              return;
            }
            loadedTabs.team = false;
            loadTab('team');
          });
        });
      }
      el.querySelectorAll('.korisec-remove-member').forEach(function (btn) {
        btn.addEventListener('click', function () {
          if (!window.confirm(t('confirmRemove'))) return;
          account('team_remove', { member_id: Number(btn.getAttribute('data-id')) }).then(function (res) {
            if (!res.success) {
              window.alert(failMessage(res));
              return;
            }
            loadedTabs.team = false;
            loadTab('team');
          });
        });
      });
    });
  }

  function loadReports() {
    return account('reports').then(function (data) {
      var el = panel('reports');
      if (!data.success) {
        el.innerHTML = '<div class="korisec-card"><p>' + esc(failMessage(data)) + '</p></div>';
        return;
      }
      var d = data.data || {};
      var branding = d.branding || {};
      var latest = d.latest_scan;
      var html = '<div class="korisec-card">';
      html += '<h2>' + esc(t('reportsTitle')) + '</h2>';
      html += '<p class="description">' + tf('reportsIntro', '<strong>' + esc(d.bound_host || t('thisSite')) + '</strong>') + '</p>';
      if (latest) {
        html += '<p>' + tf('latestCheck', '<strong>' + esc(latest.grade || '—') + '</strong>') + ' · ' + esc(formatWhen(latest.finished_at)) + '</p>';
        html += '<p><a class="button button-primary" href="' + esc(pdfHref('scan', latest.id)) + '">' + esc(t('downloadSitePdf')) + '</a></p>';
      } else {
        html += '<p>' + esc(t('runCheckForPdf')) + '</p>';
      }
      if (d.portfolio_available) {
        html += '<p><a class="button" href="' + esc(pdfHref('portfolio')) + '">' + esc(t('downloadPortfolio')) + '</a></p>';
      } else {
        html += '<p class="description">' + esc(d.note || t('agencyNote')) + '</p>';
      }
      html += '<h3>' + esc(t('whiteLabel')) + '</h3>';
      if (d.can_edit) {
        html += '<form id="korisec-branding-form">';
        html += '<p><label>' + esc(t('companyName')) + '<br><input class="regular-text" name="company_name" value="' + esc(branding.company_name || '') + '"></label></p>';
        html += '<p><label>' + esc(t('accentColour')) + '<br><input class="regular-text" name="accent_color" placeholder="#c62828" value="' + esc(branding.accent_color || '') + '"></label></p>';
        html += '<p><button type="submit" class="button button-primary">' + esc(t('saveBranding')) + '</button></p>';
        html += '<p class="description">' + esc(t('logoNote')) + '</p>';
        html += '</form>';
      } else {
        html += '<p>' + esc(t('upgradeAgency')) + '</p>';
      }
      html += '</div>';
      el.innerHTML = html;
      var form = document.getElementById('korisec-branding-form');
      if (form) {
        form.addEventListener('submit', function (e) {
          e.preventDefault();
          account('branding', {
            company_name: form.company_name.value || null,
            accent_color: form.accent_color.value || null,
          }).then(function (res) {
            if (!res.success) {
              window.alert(failMessage(res));
              return;
            }
            window.alert(t('brandingSaved'));
          });
        });
      }
    });
  }

  function prefBox(name, label, checked) {
    return '<label class="korisec-check"><input type="checkbox" data-pref="' + esc(name) + '"' + (checked ? ' checked' : '') + '> ' + esc(label) + '</label>';
  }

  function readPrefs(root) {
    var out = {};
    root.querySelectorAll('[data-pref]').forEach(function (box) {
      var path = box.getAttribute('data-pref').split('.');
      var cur = out;
      for (var i = 0; i < path.length - 1; i++) {
        if (!cur[path[i]]) cur[path[i]] = {};
        cur = cur[path[i]];
      }
      cur[path[path.length - 1]] = box.checked;
    });
    return out;
  }

  function channelCard(title, body, actions) {
    return '<div class="korisec-channel"><h3>' + esc(title) + '</h3>' + body + (actions || '') + '</div>';
  }

  function loadAlerts() {
    return account('alerts').then(function (data) {
      var el = panel('alerts');
      if (!data.success) {
        el.innerHTML = '<div class="korisec-card"><p>' + esc(failMessage(data)) + '</p></div>';
        return;
      }
      var d = data.data || {};
      var p = d.preferences || {};
      var html = '<div class="korisec-card">';
      html += '<h2>' + esc(t('alertsTitle')) + '</h2>';
      html += '<p class="description">' + tf('alertsIntro', '<strong>' + esc(d.owner_email || t('thisBilling')) + '</strong>') + '</p>';
      html += '<div class="korisec-prefs">';
      html += '<fieldset><legend>' + esc(t('emailLegend')) + '</legend>';
      html += prefBox('email.critical', t('critical'), p.email && p.email.critical);
      html += prefBox('email.high', t('high'), p.email && p.email.high);
      html += prefBox('email.medium', t('medium'), p.email && p.email.medium);
      html += '</fieldset>';
      html += '<fieldset><legend>' + esc(t('telegram')) + '</legend>';
      html += prefBox('telegram.critical', t('critical'), p.telegram && p.telegram.critical);
      html += prefBox('telegram.high', t('high'), p.telegram && p.telegram.high);
      html += '</fieldset>';
      html += '<fieldset><legend>' + esc(t('whatsapp')) + '</legend>';
      html += prefBox('whatsapp.critical', t('critical'), p.whatsapp && p.whatsapp.critical);
      html += prefBox('whatsapp.high', t('high'), p.whatsapp && p.whatsapp.high);
      html += '</fieldset>';
      html += '<fieldset><legend>' + esc(t('slack')) + '</legend>';
      html += prefBox('slack.critical', t('critical'), p.slack && p.slack.critical);
      html += prefBox('slack.high', t('high'), p.slack && p.slack.high);
      html += '</fieldset>';
      html += '</div>';
      html += '<p><button type="button" class="button button-primary" id="korisec-save-alerts">' + esc(t('savePrefs')) + '</button></p>';

      var tg = d.telegram || {};
      html += channelCard(
        t('telegram'),
        '<p>' + (tg.linked ? esc(t('linked')) : esc(t('notLinked'))) + (tg.bot_username ? ' · @' + esc(tg.bot_username) : '') + '</p>',
        tg.linked
          ? '<p><button type="button" class="button" data-alert="telegram_test">' + esc(t('sendTest')) + '</button> <button type="button" class="button" data-alert="telegram_unlink">' + esc(t('unlink')) + '</button></p>'
          : '<p><button type="button" class="button button-primary" data-alert="telegram_link">' + esc(t('connectTelegram')) + '</button></p>'
      );

      var wa = d.whatsapp || {};
      var waBody = wa.upgrade_required
        ? '<p>' + esc(t('whatsappPaid')) + '</p>'
        : '<p>' + (wa.linked ? esc(t('linked')) + ' ' + esc(wa.phone_masked || '') : esc(t('notLinked'))) + '</p>';
      var waAct = wa.upgrade_required
        ? ''
        : (wa.linked
          ? '<p><button type="button" class="button" data-alert="whatsapp_test">' + esc(t('sendTest')) + '</button> <button type="button" class="button" data-alert="whatsapp_unlink">' + esc(t('unlink')) + '</button></p>'
          : '<p><button type="button" class="button" data-alert="whatsapp_link">' + esc(t('whatsappCode')) + '</button></p>');
      html += channelCard(t('whatsapp'), waBody, waAct);

      var slack = d.slack || {};
      var slackBody = slack.upgrade_required
        ? '<p>' + esc(t('slackPro')) + '</p>'
        : '<p>' + (slack.linked ? esc(tf('slackConnected', slack.url_masked || '')) : esc(t('slackPaste'))) + '</p>';
      if (!slack.upgrade_required && !slack.linked) {
        slackBody += '<p><input class="regular-text" id="korisec-slack-url" placeholder="https://hooks.slack.com/services/…"></p>';
      }
      var slackAct = slack.upgrade_required
        ? ''
        : (slack.linked
          ? '<p><button type="button" class="button" data-alert="slack_test">' + esc(t('sendTest')) + '</button> <button type="button" class="button" data-alert="slack_unlink">' + esc(t('unlink')) + '</button></p>'
          : '<p><button type="button" class="button" data-alert="slack_connect">' + esc(t('saveSlack')) + '</button></p>');
      html += channelCard(t('slack'), slackBody, slackAct);

      var hook = d.webhook || {};
      var hookBody = hook.upgrade_required
        ? '<p>' + esc(t('webhookAgency')) + '</p>'
        : '<p>' + (hook.linked ? esc(tf('webhookConnected', hook.url_masked || '')) : esc(t('webhookHttps'))) + '</p>';
      if (!hook.upgrade_required && !hook.linked) {
        hookBody += '<p><input class="regular-text" id="korisec-webhook-url" placeholder="https://example.com/hooks/korisec"></p>';
      }
      var hookAct = hook.upgrade_required
        ? ''
        : (hook.linked
          ? '<p><button type="button" class="button" data-alert="webhook_test">' + esc(t('sendTest')) + '</button> <button type="button" class="button" data-alert="webhook_unlink">' + esc(t('unlink')) + '</button></p>'
          : '<p><button type="button" class="button" data-alert="webhook_connect">' + esc(t('saveWebhook')) + '</button></p>');
      html += channelCard(t('webhook'), hookBody, hookAct);
      html += '</div>';
      el.innerHTML = html;

      var saveBtn = document.getElementById('korisec-save-alerts');
      if (saveBtn) {
        saveBtn.addEventListener('click', function () {
          saveBtn.disabled = true;
          account('alerts_save', { preferences: readPrefs(el) }).then(function (res) {
            saveBtn.disabled = false;
            if (!res.success) {
              window.alert(failMessage(res));
              return;
            }
            window.alert(t('prefsSaved'));
          }).catch(function () {
            saveBtn.disabled = false;
          });
        });
      }

      el.querySelectorAll('[data-alert]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var op = btn.getAttribute('data-alert');
          var payload = {};
          if (op === 'slack_connect') {
            var slackInput = document.getElementById('korisec-slack-url');
            payload = { url: slackInput ? slackInput.value : '' };
          }
          if (op === 'webhook_connect') {
            var hookInput = document.getElementById('korisec-webhook-url');
            payload = { url: hookInput ? hookInput.value : '' };
          }
          btn.disabled = true;
          account(op, payload).then(function (res) {
            btn.disabled = false;
            if (!res.success) {
              window.alert(failMessage(res));
              return;
            }
            if (op === 'telegram_link' && res.data && res.data.deep_link) {
              window.open(res.data.deep_link, '_blank', 'noopener');
              window.alert(res.data.instructions || t('openTelegram'));
              return;
            }
            if (op === 'whatsapp_link' && res.data && res.data.instructions) {
              window.alert(res.data.instructions);
              return;
            }
            if (op === 'webhook_connect' && res.data && res.data.webhook && res.data.webhook.secret) {
              window.alert(tf('webhookSecret', res.data.webhook.secret));
            }
            loadedTabs.alerts = false;
            loadTab('alerts');
          }).catch(function () {
            btn.disabled = false;
          });
        });
      });
    });
  }

  document.querySelectorAll('.korisec-tab').forEach(function (btn) {
    btn.addEventListener('click', function () {
      showTab(btn.getAttribute('data-tab'));
    });
  });

  var connectForm = document.getElementById('korisec-connect-form');
  if (connectForm) {
    connectForm.addEventListener('submit', function (e) {
      e.preventDefault();
      var input = document.getElementById('korisec-key');
      var btn = document.getElementById('korisec-connect');
      if (btn) btn.disabled = true;
      post('korisec_connect', { korisec_license: input ? input.value : '' }).then(function (data) {
        if (!data.success) {
          window.alert(failMessage(data));
          if (btn) btn.disabled = false;
          return;
        }
        window.location.reload();
      }).catch(function () {
        window.alert(t('couldNotWp'));
        if (btn) btn.disabled = false;
      });
    });
  }

  var disconnectBtn = document.getElementById('korisec-disconnect');
  if (disconnectBtn) {
    disconnectBtn.addEventListener('click', function () {
      if (!window.confirm(t('confirmDisconnect'))) return;
      disconnectBtn.disabled = true;
      post('korisec_disconnect').then(function () {
        window.location.reload();
      }).catch(function () {
        disconnectBtn.disabled = false;
      });
    });
  }

  var loginForm = document.getElementById('korisec-login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', function (e) {
      e.preventDefault();
      var btn = document.getElementById('korisec-login-save');
      var status = document.getElementById('korisec-login-status');
      var enabled = document.getElementById('korisec-login-enabled');
      var maxEl = document.getElementById('korisec-login-max');
      var minsEl = document.getElementById('korisec-login-mins');
      if (btn) btn.disabled = true;
      if (status) status.textContent = '';
      post('korisec_save_login', {
        enabled: enabled && enabled.checked ? '1' : '',
        max_attempts: maxEl ? maxEl.value : '5',
        lockout_minutes: minsEl ? minsEl.value : '15',
      }).then(function (data) {
        if (btn) btn.disabled = false;
        if (!data || !data.success) {
          if (status) status.textContent = failMessage(data) || t('loginSaveFailed');
          return;
        }
        if (status) status.textContent = (data.data && data.data.message) || t('loginSaved');
        if (data.data && data.data.settings) {
          cfg.loginSettings = data.data.settings;
        }
      }).catch(function () {
        if (btn) btn.disabled = false;
        if (status) status.textContent = t('loginSaveFailed');
      });
    });
  }

  var hardeningForm = document.getElementById('korisec-hardening-form');
  if (hardeningForm) {
    hardeningForm.addEventListener('submit', function (e) {
      e.preventDefault();
      var btn = document.getElementById('korisec-hardening-save');
      var status = document.getElementById('korisec-hardening-status');
      var xml = document.getElementById('korisec-disable-xmlrpc');
      var users = document.getElementById('korisec-block-users');
      var install = document.getElementById('korisec-block-install');
      if (btn) btn.disabled = true;
      if (status) status.textContent = '';
      post('korisec_save_hardening', {
        disable_xmlrpc: xml && xml.checked ? '1' : '',
        block_user_enumeration: users && users.checked ? '1' : '',
        block_install_php: install && install.checked ? '1' : '',
      }).then(function (data) {
        if (btn) btn.disabled = false;
        if (!data || !data.success) {
          if (status) status.textContent = failMessage(data) || t('hardeningSaveFailed');
          return;
        }
        if (status) status.textContent = (data.data && data.data.message) || t('hardeningSaved');
        syncRemedyControls((data.data && data.data.remedies) || null, (data.data && data.data.settings) || null);
        renderActions(cfg.lastFindings || []);
      }).catch(function () {
        if (btn) btn.disabled = false;
        if (status) status.textContent = t('hardeningSaveFailed');
      });
    });
  }

  document.addEventListener('click', function (e) {
    var btn = e.target && e.target.closest ? e.target.closest('.korisec-apply-remedy') : null;
    if (!btn) return;
    e.preventDefault();
    applyRemedy(btn.getAttribute('data-remedy') || '', btn);
  });

  if (cfg.connected) {
    loadDashboard().then(function () {
      if (cfg.scanId && (cfg.scanStatus === 'queued' || cfg.scanStatus === 'running')) {
        pollScan(cfg.scanId);
      }
    });
  } else {
    renderActions([]);
  }
})();
