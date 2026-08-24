// ─── VulNova — Data Source Status ────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('refresh-btn').addEventListener('click', load);
    load();
});

const STATUS_META = {
    ok: { dot: 'st-ok', label: 'Operational' },
    degraded: { dot: 'st-warn', label: 'Degraded' },
    error: { dot: 'st-err', label: 'Unreachable' },
    missing: { dot: 'st-warn', label: 'Not downloaded' },
    offline: { dot: 'st-dim', label: 'Offline (optional)' },
};

async function load() {
    const grid = document.getElementById('sources-grid');
    const pill = document.getElementById('health-pill');
    pill.textContent = 'checking…';
    grid.innerHTML = `<div class="table-loading"><div class="spinner"></div>
        <div>Checking all connections…</div></div>`;

    try {
        const resp = await fetch('/api/sources');
        const data = await resp.json();
        if (data.error) {
            grid.innerHTML = `<div class="table-error">❌ ${escapeHtml(data.error)}</div>`;
            return;
        }
        pill.textContent = `${data.healthy}/${data.total} operational`;
        pill.className = 'stat-pill ' + (data.healthy === data.total ? 'pill-ok'
            : data.healthy >= data.total / 2 ? 'pill-warn' : 'pill-err');
        document.getElementById('checked-at').textContent =
            'Last checked: ' + new Date(data.checked_at * 1000).toLocaleString();

        // Group by category
        const groups = {};
        data.sources.forEach(s => { (groups[s.category] = groups[s.category] || []).push(s); });

        let html = '';
        for (const [cat, list] of Object.entries(groups)) {
            html += `<div class="source-cat-title">${escapeHtml(cat)}</div>`;
            html += '<div class="source-cards">' + list.map(renderCard).join('') + '</div>';
        }
        grid.innerHTML = html;
    } catch (err) {
        grid.innerHTML = `<div class="table-error">❌ ${escapeHtml(err.message)}</div>`;
    }
}

function renderCard(s) {
    const meta = STATUS_META[s.status] || STATUS_META.error;
    const latency = s.latency_ms ? `<span class="src-latency">${s.latency_ms} ms</span>` : '';
    const code = s.code ? `HTTP ${s.code}` : '';
    const detail = s.detail || code || '';
    const docLink = s.doc_url
        ? `<a class="src-doc" href="${s.doc_url}" target="_blank" rel="noopener">source ↗</a>` : '';

    return `
    <div class="source-card">
        <div class="source-card-head">
            <span class="src-status"><span class="st-dot ${meta.dot}"></span>${meta.label}</span>
            ${latency}
        </div>
        <div class="source-name">${escapeHtml(s.name)}</div>
        <div class="source-purpose">${escapeHtml(s.purpose)}</div>
        <div class="source-meta">
            <div class="src-meta-row">
                <span class="src-meta-k">Last refreshed</span>
                <span class="src-meta-v">${lastRefreshed(s.last_updated)}</span>
            </div>
            <div class="src-meta-row">
                <span class="src-meta-k">Cached items</span>
                <span class="src-meta-v">${(s.cached_items || 0).toLocaleString()}</span>
            </div>
            ${detail ? `<div class="src-meta-row"><span class="src-meta-k">Status detail</span><span class="src-meta-v">${escapeHtml(detail)}</span></div>` : ''}
            ${s.refresh_note ? `<div class="src-note">${escapeHtml(s.refresh_note)}</div>` : ''}
        </div>
        ${docLink}
    </div>`;
}

function lastRefreshed(ts) {
    if (!ts) return 'never (not fetched yet)';
    const diff = Math.max(0, Date.now() / 1000 - ts);
    const mins = Math.floor(diff / 60);
    let rel;
    if (mins < 1) rel = 'just now';
    else if (mins < 60) rel = mins + 'm ago';
    else if (mins < 1440) rel = Math.floor(mins / 60) + 'h ago';
    else rel = Math.floor(mins / 1440) + 'd ago';
    const abs = new Date(ts * 1000).toLocaleString();
    return `${rel} <span class="src-abs">(${abs})</span>`;
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
