(function () {
  var cfg = window.korisecBackup || {};
  var i18n = cfg.i18n || {};
  var root = document.getElementById('korisec-backups-root');
  if (!root) return;

  var state = null;
  var loaded = false;
  var driving = false;
  var flash = null;
  var shownKey = '';
  var cronChecked = false;

  function t(key) {
    return i18n[key] != null && i18n[key] !== '' ? i18n[key] : key;
  }

  function tf(key) {
    var args = Array.prototype.slice.call(arguments, 1);
    var i = 0;
    return String(t(key))
      .replace(/%(\d+)\$s/g, function (_, n) { return args[Number(n) - 1] == null ? '' : String(args[Number(n) - 1]); })
      .replace(/%s/g, function () { var v = args[i]; i += 1; return v == null ? '' : String(v); });
  }

  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function size(bytes) {
    bytes = Number(bytes) || 0;
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var u = 0;
    while (bytes >= 1024 && u < units.length - 1) { bytes /= 1024; u += 1; }
    return (u === 0 ? bytes : bytes.toFixed(bytes < 10 ? 1 : 0)) + ' ' + units[u];
  }

  function when(ts) {
    if (!ts) return '';
    var d = new Date(Number(ts) * 1000);
    return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }

  function api(action, extra) {
    var body = new URLSearchParams();
    body.set('action', 'korisec_backup_' + action);
    body.set('nonce', cfg.nonce || '');
    Object.keys(extra || {}).forEach(function (k) { body.set(k, extra[k]); });
    return fetch(cfg.ajaxUrl, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
      body: body.toString(),
    }).then(function (res) {
      return res.json().catch(function () { return { success: false, data: { message: t('error') } }; });
    });
  }

  function apply(data, okMessage) {
    if (data && data.data && data.data.state) {
      state = data.data.state;
    }
    if (data && !data.success) {
      flash = { type: 'error', message: (data.data && data.data.message) || t('error') };
    } else if (data && data.data && data.data.message) {
      flash = { type: 'success', message: data.data.message };
    } else if (okMessage) {
      flash = { type: 'success', message: okMessage };
    }
    render();
    maybeDrive();
    if (!cronChecked && state && state.cron && state.cron.status === 'unknown' && state.drive.connected) {
      cronChecked = true;
      api('cron_check').then(function (d) { if (d && d.data && d.data.state) { state = d.data.state; render(); } });
    }
  }

  function load() {
    loaded = true;
    root.innerHTML = '<div class="korisec-card"><p>' + esc(t('loading')) + '</p></div>';
    api('state').then(function (data) { apply(data); }).catch(function () {
      root.innerHTML = '<div class="korisec-card"><p>' + esc(t('loadFailed')) + '</p></div>';
    });
  }

  function jobRunning() {
    return state && state.job && state.job.status === 'running';
  }

  /* Drive the job from the browser while this screen is open. */
  function maybeDrive() {
    if (driving || !jobRunning()) return;
    driving = true;
    var loop = function () {
      api('step').then(function (data) {
        if (data && data.data && data.data.state) state = data.data.state;
        render();
        if (jobRunning()) {
          var busy = data && data.data && data.data.tick === 'busy';
          setTimeout(loop, busy ? 3000 : 250);
        } else {
          driving = false;
        }
      }).catch(function () {
        setTimeout(loop, 5000);
      });
    };
    loop();
  }

  function typeLabel(type) {
    return t('type' + type.charAt(0).toUpperCase() + type.slice(1));
  }

  function statusBadge(row) {
    if (row.status === 'VERIFIED' && !row.key_ok) {
      return '<span class="badge text-bg-warning">' + esc(t('keyMissing')) + '</span>';
    }
    var cls = row.status === 'VERIFIED' ? 'text-bg-success' : (row.status === 'FAILED' || row.status === 'CORRUPTED' ? 'text-bg-danger' : 'text-bg-info');
    return '<span class="badge ' + cls + '">' + esc(t('status' + row.status)) + '</span>';
  }

  function stat(label, value, sub) {
    return '<div class="col-6 col-lg-3"><div class="card kb-stat"><div class="card-body">'
      + '<div class="kb-stat-label">' + esc(label) + '</div>'
      + '<div class="kb-stat-value">' + value + (sub ? '<span class="kb-stat-sub">' + sub + '</span>' : '') + '</div>'
      + '</div></div></div>';
  }

  function renderSummary(s) {
    var health;
    var healthCls;
    if (!s.drive.connected || !s.last) {
      health = t('notSetUp');
      healthCls = 'text-bg-info';
    } else if (s.recent_failure || !s.key.acknowledged) {
      health = t('attention');
      healthCls = 'text-bg-warning';
    } else {
      health = t('healthy');
      healthCls = 'text-bg-success';
    }
    var lastSub = s.last
      ? esc(size(s.last.stored)) + ' · ' + esc(tf('tablesN', s.last.tables)) + (s.last.files ? ' · ' + esc(tf('filesN', Number(s.last.files).toLocaleString())) : '')
      : '';
    var driveSub = s.drive.connected ? esc((s.drive.email ? s.drive.email + ' · ' : '') + s.drive.folder) : '';
    var html = '<div class="row kb-stats">';
    html += stat(t('colStatus'), '<span class="badge ' + healthCls + '">' + esc(health) + '</span>');
    html += stat(t('lastBackup'), esc(s.last ? when(s.last.created) : t('never')), lastSub);
    html += stat(t('nextBackup'), esc(s.next ? when(s.next) : t('notScheduled')));
    html += stat(t('restorePoints'), esc(String(s.restore_points)));
    html += stat(t('storage'), esc(s.drive.connected ? t('driveConnected') : t('driveNotConnected')), driveSub);
    return html + '</div>';
  }

  function renderJob(s) {
    var job = s.job;
    if (!job) return '';
    if (job.status === 'running') {
      var pct = Math.max(2, Math.min(100, Number(job.pct) || 0));
      var html = '<div class="card kb-section"><div class="card-body">';
      html += '<div class="kb-stat-value">' + esc(job.label || '') + ' <span class="kb-stat-sub" style="display:inline">' + Math.round(pct) + '%</span></div>';
      html += '<div class="progress" role="progressbar" aria-valuenow="' + Math.round(pct) + '" aria-valuemin="0" aria-valuemax="100"><div class="progress-bar" style="width:' + pct + '%"></div></div>';
      html += '<p class="form-text">' + esc(t('keepOpen')) + '</p>';
      html += '<p class="kb-actions"><button type="button" class="btn btn-outline-secondary btn-sm" data-bk="cancel">' + esc(t('cancel')) + '</button></p>';
      return html + '</div></div>';
    }
    if (job.status === 'failed' || job.status === 'cancelled') {
      return '<div class="alert alert-danger"><p><strong>' + esc(job.status === 'failed' ? t('jobFailed') : t('jobCancelled')) + ':</strong> ' + esc(job.error || '') + '</p></div>';
    }
    return '';
  }

  function renderUndo(s) {
    if (!s.undo) return '';
    var html = '<div class="card kb-undo kb-section"><div class="card-body">';
    html += '<h3>' + esc(t('undoTitle')) + '</h3>';
    html += '<p>' + esc(tf('undoBody', when(s.undo.restored_at), when(s.undo.expires))) + '</p>';
    if (s.undo.siteurl_changed) html += '<p><strong>' + esc(t('undoSiteurl')) + '</strong></p>';
    html += '<p class="kb-actions"><button type="button" class="btn btn-primary" data-bk="undo">' + esc(t('undo')) + '</button>';
    html += '<button type="button" class="btn btn-outline-secondary" data-bk="keep">' + esc(t('keep')) + '</button></p>';
    return html + '</div></div>';
  }

  function renderKey(s) {
    if (!s.drive.connected && !s.key.has) return '';
    var html = '<div class="card' + (s.key.acknowledged ? '' : ' kb-attn') + '"><div class="card-body">';
    html += '<h3>' + esc(t('keyTitle')) + (s.key.acknowledged ? ' <span class="badge text-bg-success">' + esc(t('keySaved')) + '</span>' : '') + '</h3>';
    html += '<p>' + esc(t('keyIntro')) + '</p>';
    if (shownKey) {
      html += '<code class="kb-key" id="korisec-bk-key">' + esc(shownKey) + '</code>';
      html += '<p class="kb-actions"><button type="button" class="btn btn-outline-secondary btn-sm" data-bk="copy-key">' + esc(t('copyKey')) + '</button></p>';
    }
    html += '<p class="kb-actions">';
    if (!shownKey) html += '<button type="button" class="btn btn-outline-secondary" data-bk="show-key">' + esc(t('showKey')) + '</button>';
    html += '<a class="btn btn-outline-secondary" href="' + esc(s.key.download_url) + '">' + esc(t('downloadKey')) + '</a>';
    if (!s.key.acknowledged) html += '<button type="button" class="btn btn-primary" data-bk="ack-key">' + esc(t('ackKey')) + '</button>';
    html += '</p>';
    html += '<details class="kb-fold"><summary>' + esc(t('importKey')) + '</summary><p class="form-text">' + esc(t('importKeyHelp')) + '</p>';
    html += '<div class="row"><div class="col-md-8"><input type="text" class="form-control" id="korisec-bk-import" placeholder="KSK1-…" autocomplete="off"></div>';
    html += '<div class="col-md-4"><button type="button" class="btn btn-outline-secondary" data-bk="import-key">' + esc(t('importKeyBtn')) + '</button></div></div>';
    if (s.drive.connected) html += '<p class="kb-actions" style="margin-top:0.6rem"><button type="button" class="btn btn-outline-secondary btn-sm" data-bk="sync">' + esc(t('syncDrive')) + '</button></p>';
    html += '</details>';
    return html + '</div></div>';
  }

  function renderHistory(s) {
    var html = '<div class="card kb-section"><div class="card-header">' + esc(t('history')) + '</div><div class="card-body">';
    if (!s.backups.length) {
      return html + '<p>' + esc(t('noBackups')) + '</p></div></div>';
    }
    html += '<div class="table-responsive"><table class="table"><thead><tr><th>' + esc(t('colDate')) + '</th><th>' + esc(t('colType')) + '</th><th>' + esc(t('colContents')) + '</th><th>' + esc(t('colSize')) + '</th><th>' + esc(t('colStatus')) + '</th><th></th></tr></thead><tbody>';
    var busy = jobRunning();
    s.backups.forEach(function (row) {
      var contents = (row.scope === 'full' ? t('scopeFull') : t('scopeDatabase'));
      var detail = [];
      if (row.tables) detail.push(tf('tablesN', row.tables));
      if (row.files) detail.push(tf('filesN', Number(row.files).toLocaleString()));
      if (row.host && row.host !== s.host) detail.push(tf('otherSite', row.host));
      html += '<tr>';
      html += '<td>' + esc(when(row.created)) + '</td>';
      html += '<td>' + esc(typeLabel(row.type)) + '</td>';
      html += '<td>' + esc(contents) + (detail.length ? '<span class="kb-sub">' + esc(detail.join(' · ')) + '</span>' : '') + '</td>';
      html += '<td>' + esc(row.stored ? size(row.stored) : '—') + '</td>';
      html += '<td>' + statusBadge(row) + (row.error ? '<span class="kb-sub">' + esc(row.error) + '</span>' : '') + '</td>';
      html += '<td>';
      if (row.status === 'VERIFIED' && row.key_ok) {
        html += '<button type="button" class="btn btn-sm btn-outline-secondary" data-bk="restore" data-uuid="' + esc(row.uuid) + '"' + (busy || !s.drive.connected ? ' disabled' : '') + '>' + esc(t('restore')) + '</button> ';
      }
      html += '<button type="button" class="btn btn-sm btn-outline-danger" data-bk="delete" data-uuid="' + esc(row.uuid) + '"' + (busy ? ' disabled' : '') + '>' + esc(t('delete')) + '</button>';
      html += '</td></tr>';
    });
    return html + '</tbody></table></div></div></div>';
  }

  function renderSettings(s) {
    var st = s.settings;
    var hours = '';
    for (var h = 0; h < 24; h++) {
      hours += '<option value="' + h + '"' + (st.hour === h ? ' selected' : '') + '>' + (h < 10 ? '0' : '') + h + ':00</option>';
    }
    var html = '<div class="card"><div class="card-header">' + esc(t('settings')) + '</div><div class="card-body"><form id="korisec-bk-settings">';
    html += '<div class="row">';
    html += '<div class="col-md-6"><label class="form-label" for="korisec-bk-schedule">' + esc(t('schedule')) + '</label><select class="form-select" id="korisec-bk-schedule" name="schedule">';
    ['off', 'daily', 'weekly'].forEach(function (v) {
      html += '<option value="' + v + '"' + (st.schedule === v ? ' selected' : '') + '>' + esc(t('schedule' + v.charAt(0).toUpperCase() + v.slice(1))) + '</option>';
    });
    html += '</select></div>';
    html += '<div class="col-md-6"><label class="form-label" for="korisec-bk-hour">' + esc(t('atHour')) + '</label><select class="form-select" id="korisec-bk-hour" name="hour">' + hours + '</select></div>';
    html += '<div class="col-md-6"><label class="form-label" for="korisec-bk-scope">' + esc(t('scope')) + '</label><select class="form-select" id="korisec-bk-scope" name="scope"><option value="full"' + (st.scope === 'full' ? ' selected' : '') + '>' + esc(t('scopeFull')) + '</option><option value="database"' + (st.scope === 'database' ? ' selected' : '') + '>' + esc(t('scopeDatabase')) + '</option></select></div>';
    html += '<div class="col-md-6"><label class="form-label" for="korisec-bk-retention">' + esc(t('retention')) + '</label><input type="number" class="form-control" id="korisec-bk-retention" min="1" max="90" name="retention" value="' + esc(st.retention) + '"></div>';
    html += '</div>';
    html += '<div class="form-check"><input class="form-check-input" type="checkbox" id="korisec-bk-uploads" name="include_uploads" value="1"' + (st.include_uploads ? ' checked' : '') + '><label class="form-check-label" for="korisec-bk-uploads">' + esc(t('includeUploads')) + '</label></div>';
    html += '<div class="form-check"><input class="form-check-input" type="checkbox" id="korisec-bk-alltables" name="all_tables" value="1"' + (st.all_tables ? ' checked' : '') + '><label class="form-check-label" for="korisec-bk-alltables">' + esc(t('allTables')) + '</label></div>';
    html += '<div class="form-check"><input class="form-check-input" type="checkbox" id="korisec-bk-notify" name="notify_failures" value="1"' + (st.notify_failures ? ' checked' : '') + '><label class="form-check-label" for="korisec-bk-notify">' + esc(t('notify')) + '</label></div>';
    html += '<div class="kb-form-foot"><div>';
    if (s.env.disk_free != null) html += '<p class="form-text">' + esc(tf('freeDisk', size(s.env.disk_free))) + '</p>';
    if (s.cron && s.cron.status === 'ok') html += '<p class="form-text">' + esc(s.cron.last_run ? tf('cronOkLine', when(s.cron.last_run)) : t('cronOk')) + '</p>';
    html += '</div><button type="submit" class="btn btn-primary">' + esc(t('save')) + '</button></div>';
    return html + '</form></div></div>';
  }

  function renderEvents(s) {
    if (!s.events || !s.events.length) return '';
    var html = '<details class="card kb-section kb-activity"><summary>' + esc(t('activity')) + '</summary><div class="card-body table-responsive"><table class="table"><tbody>';
    s.events.forEach(function (e) {
      html += '<tr><td>' + esc(when(Date.parse(e.created_at.replace(' ', 'T') + 'Z') / 1000)) + '</td><td><code>' + esc(e.event) + '</code></td><td>' + esc(e.message || '') + '</td></tr>';
    });
    return html + '</tbody></table></div></details>';
  }

  function renderCron(s) {
    var c = s.cron;
    if (!c || (c.status !== 'broken' && c.status !== 'pending')) return '';
    var broken = c.status === 'broken';
    var html = '<div class="alert alert-' + (broken ? 'danger' : 'info') + '">';
    html += '<p><strong>' + esc(t(broken ? 'cronBrokenTitle' : 'cronPendingTitle')) + '</strong> ' + esc(c.message) + '</p>';
    if (broken) {
      if (c.fix) html += '<p>' + esc(c.fix) + '</p>';
      html += '<p>' + esc(t('cronServerJob')) + '<code class="kb-code">' + esc(c.cron_line) + '</code></p>';
      html += '<p class="form-text">' + esc(c.browser_note) + '</p>';
    }
    html += '<p><button type="button" class="btn btn-outline-secondary btn-sm" data-bk="cron-check">' + esc(t('cronCheckAgain')) + '</button></p>';
    return html + '</div>';
  }

  function render() {
    if (!state) return;
    var s = state;
    var running = jobRunning();
    var actions = '';
    if (!s.drive.connected) {
      actions = '<button type="button" class="btn btn-primary" data-bk="connect">' + esc(t('connectDrive')) + '</button>';
    } else {
      actions = '<button type="button" class="btn btn-primary" data-bk="backup"' + (running ? ' disabled' : '') + '>' + esc(t('backupNow')) + '</button>';
      actions += '<button type="button" class="btn btn-outline-secondary" data-bk="disconnect"' + (running ? ' disabled' : '') + '>' + esc(t('disconnectDrive')) + '</button>';
    }
    var html = '<div class="kb-top"><div>';
    html += '<h2>' + esc(t('title')) + ' <span class="badge text-bg-free">' + esc(t('freeBadge')) + '</span></h2>';
    html += '<p class="kb-lead">' + esc(t('lede')) + '</p></div>';
    html += '<div class="kb-actions">' + actions + '</div></div>';

    var note = flash || s.notice;
    if (note) {
      html += '<div class="alert alert-' + (note.type === 'error' ? 'danger' : 'success') + '"><p>' + esc(note.message) + '</p></div>';
    }
    if (s.env.multisite) {
      html += '<div class="alert alert-warning"><p>' + esc(t('multisite')) + '</p></div>';
      root.innerHTML = html;
      return;
    }
    if (!s.env.crypto) {
      html += '<div class="alert alert-warning"><p>' + esc(t('envMissing')) + '</p></div>';
      root.innerHTML = html;
      return;
    }
    if (!s.drive.connected) html += '<div class="alert alert-info"><p>' + esc(t('connectIntro')) + '</p></div>';
    if (s.recent_failure && !running) {
      html += '<div class="alert alert-warning"><p>' + esc(t('recentFailure')) + '</p></div>';
    }
    if (s.drive.connected) html += renderCron(s);
    html += renderSummary(s);
    html += renderJob(s);
    html += renderUndo(s);
    var keyHtml = renderKey(s);
    var settingsHtml = s.drive.connected ? renderSettings(s) : '';
    if (keyHtml || settingsHtml) {
      html += '<div class="row kb-section">';
      if (keyHtml) html += '<div class="' + (settingsHtml ? 'col-lg-5' : 'col-md-12') + '">' + keyHtml + '</div>';
      if (settingsHtml) html += '<div class="' + (keyHtml ? 'col-lg-7' : 'col-md-12') + '">' + settingsHtml + '</div>';
      html += '</div>';
    }
    if (s.drive.connected || s.backups.length) html += renderHistory(s);
    html += renderEvents(s);
    html += '<div id="korisec-bk-modal"></div>';
    root.innerHTML = html;
    flash = null;
  }

  function openRestore(uuid) {
    var row = (state.backups || []).filter(function (r) { return r.uuid === uuid; })[0];
    if (!row) return;
    var modal = document.getElementById('korisec-bk-modal');
    var html = '<div class="kb-overlay"><div class="kb-dialog card" role="dialog" aria-modal="true"><div class="card-body">';
    html += '<h2>' + esc(t('restoreTitle')) + '</h2>';
    html += '<p>' + esc(tf('restoreWarn', when(row.created))) + '</p>';
    if (row.host && row.host !== state.host) html += '<p><strong>' + esc(tf('restoreOtherHost', row.host)) + '</strong></p>';
    if (row.scope === 'full') {
      html += '<div class="form-check"><input class="form-check-input" type="checkbox" id="korisec-bk-rfiles" checked><label class="form-check-label" for="korisec-bk-rfiles">' + esc(t('restoreFiles')) + '</label></div>';
    }
    html += '<p class="form-text">' + esc(t('restoreLogout')) + '</p>';
    html += '<label class="form-label" for="korisec-bk-rconfirm">' + esc(t('restoreType')) + '</label><input type="text" class="form-control" id="korisec-bk-rconfirm" autocomplete="off">';
    html += '<p class="kb-actions" style="margin-top:1rem"><button type="button" class="btn btn-primary" data-bk="restore-go" data-uuid="' + esc(uuid) + '" disabled>' + esc(t('restoreGo')) + '</button>';
    html += '<button type="button" class="btn btn-outline-secondary" data-bk="restore-close">' + esc(t('cancel')) + '</button></p>';
    html += '</div></div></div>';
    modal.innerHTML = html;
    var input = document.getElementById('korisec-bk-rconfirm');
    var go = modal.querySelector('[data-bk="restore-go"]');
    input.addEventListener('input', function () { go.disabled = input.value.trim() !== 'RESTORE'; });
    input.focus();
  }

  root.addEventListener('submit', function (e) {
    if (e.target && e.target.id === 'korisec-bk-settings') {
      e.preventDefault();
      var f = e.target;
      api('settings', {
        schedule: f.schedule.value,
        hour: f.hour.value,
        scope: f.scope.value,
        include_uploads: f.include_uploads.checked ? '1' : '',
        retention: f.retention.value,
        all_tables: f.all_tables.checked ? '1' : '',
        notify_failures: f.notify_failures.checked ? '1' : '',
      }).then(function (d) { apply(d); });
    }
  });

  root.addEventListener('click', function (e) {
    var btn = e.target && e.target.closest ? e.target.closest('[data-bk]') : null;
    if (!btn) return;
    var action = btn.getAttribute('data-bk');
    var uuid = btn.getAttribute('data-uuid') || '';
    if (action !== 'restore-close' && action !== 'copy-key') btn.disabled = true;

    switch (action) {
      case 'connect':
        api('drive_connect').then(function (d) {
          if (d && d.success && d.data && d.data.url) {
            window.location.href = d.data.url;
          } else {
            apply(d);
          }
        });
        break;
      case 'disconnect':
        if (!window.confirm(t('confirmDisconnectDrive'))) { btn.disabled = false; return; }
        api('drive_disconnect').then(function (d) { apply(d); });
        break;
      case 'backup':
        api('start').then(function (d) { apply(d); });
        break;
      case 'cron-check':
        btn.textContent = t('cronChecking');
        api('cron_check').then(function (d) { apply(d); });
        break;
      case 'cancel':
        if (!window.confirm(t('confirmCancel'))) { btn.disabled = false; return; }
        api('cancel').then(function (d) { apply(d); });
        break;
      case 'undo':
        if (!window.confirm(t('confirmUndo'))) { btn.disabled = false; return; }
        api('undo').then(function (d) { apply(d); });
        break;
      case 'keep':
        if (!window.confirm(t('confirmKeep'))) { btn.disabled = false; return; }
        api('keep').then(function (d) { apply(d); });
        break;
      case 'delete':
        if (!window.confirm(t('confirmDelete'))) { btn.disabled = false; return; }
        api('delete', { uuid: uuid }).then(function (d) { apply(d); });
        break;
      case 'restore':
        btn.disabled = false;
        openRestore(uuid);
        break;
      case 'restore-close':
        document.getElementById('korisec-bk-modal').innerHTML = '';
        break;
      case 'restore-go':
        var files = document.getElementById('korisec-bk-rfiles');
        api('restore', {
          uuid: uuid,
          confirm: (document.getElementById('korisec-bk-rconfirm') || {}).value || '',
          include_files: files && files.checked ? '1' : '',
        }).then(function (d) { apply(d); });
        break;
      case 'show-key':
        api('recovery_key').then(function (d) {
          if (d && d.success && d.data) {
            shownKey = d.data.key;
            render();
          } else {
            apply(d);
          }
        });
        break;
      case 'copy-key':
        if (navigator.clipboard && shownKey) {
          navigator.clipboard.writeText(shownKey).then(function () { btn.textContent = t('copied'); });
        }
        break;
      case 'ack-key':
        api('ack_key').then(function (d) { apply(d); });
        break;
      case 'import-key':
        var field = document.getElementById('korisec-bk-import');
        api('import_key', { key: field ? field.value : '' }).then(function (d) { apply(d); });
        break;
      case 'sync':
        api('sync').then(function (d) { apply(d); });
        break;
      default:
        btn.disabled = false;
    }
  });

  var inPanel = root.closest && root.closest('.korisec-panel');
  if (!inPanel) {
    load();
  } else {
    document.addEventListener('korisec:backups-shown', function () {
      if (!loaded) load();
    });
    if (inPanel.classList.contains('is-active')) load();
  }
})();
