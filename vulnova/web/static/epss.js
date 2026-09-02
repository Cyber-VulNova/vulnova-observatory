// ─── VulNova EPSS — exploitation prediction dashboard ───────────────────────

document.addEventListener('DOMContentLoaded', () => {
    const search = document.getElementById('epss-search');
    search.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') lookupCve(search.value.trim());
    });
    load();
});

function severityOf(cvss, severity) {
    if (severity) return severity.toUpperCase();
    const s = Number(cvss) || 0;
    if (s >= 9) return 'CRITICAL';
    if (s >= 7) return 'HIGH';
    if (s >= 4) return 'MEDIUM';
    if (s > 0) return 'LOW';
    return 'NONE';
}

async function load() {
    const topEl = document.getElementById('epss-top');
    try {
        const resp = await fetch('/api/epss');
        const data = await resp.json();
        if (data.error) {
            topEl.innerHTML = `<div class="table-error">❌ ${escapeHtml(data.error)}</div>`;
            return;
        }
        renderStats(data);
        const sub = document.getElementById('epss-top-sub');
        if (sub && data.window_days) sub.textContent = `recently-published (last ${data.window_days} days), ranked by EPSS probability`;
        renderTopCards(data.top || []);
        renderMovers(data.movers || [], data);
        const upd = data.score_date ? `EPSS model ${data.score_date}` : '';
        document.getElementById('epss-updated').textContent = upd;
        document.getElementById('epss-stat').textContent =
            data.total ? `${Number(data.total).toLocaleString()} CVEs scored` : '—';
    } catch (err) {
        topEl.innerHTML = `<div class="table-error">❌ ${escapeHtml(err.message)}</div>`;
    }
}

function renderStats(d) {
    const b = d.bands || {};
    const el = document.getElementById('epss-stats');
    const card = (label, val, cls, sub) => `
        <div class="epss-stat-card ${cls || ''}">
            <div class="epss-stat-val">${val === undefined ? '—' : Number(val).toLocaleString()}</div>
            <div class="epss-stat-label">${escapeHtml(label)}</div>
            <div class="epss-stat-sub">${escapeHtml(sub || '')}</div>
        </div>`;
    el.innerHTML =
        card('High probability', b.high, 'crit', 'EPSS ≥ 50%') +
        card('Elevated', b.elevated, 'high', 'EPSS ≥ 10%') +
        card('Moderate', b.moderate, 'mod', 'EPSS ≥ 1%');
}

function renderTopCards(top) {
    const el = document.getElementById('epss-top');
    if (!top.length) {
        el.innerHTML = `<div class="table-empty">No EPSS data available.</div>`;
        return;
    }
    el.innerHTML = top.map(r => {
        const sev = severityOf(r.cvss, r.severity);
        const vendor = (r.product_label || r.vendor || '').trim();
        const cvssTxt = (r.cvss != null && r.cvss !== '') ? r.cvss : 'N/A';
        return `
        <a class="epss-card" href="/cve/${encodeURIComponent(r.cve)}" title="Open ${escapeHtml(r.cve)}">
            <div class="epss-card-top">
                <span class="epss-card-vendor">${escapeHtml((vendor || '—').toUpperCase())}</span>
                <span class="epss-card-cvss sev-bg-${sev.toLowerCase()}">
                    <span class="epss-cvss-num">${cvssTxt}</span>
                    <span class="epss-cvss-sev">${sev}</span>
                </span>
            </div>
            <div class="epss-card-cve">${escapeHtml(r.cve)}</div>
            <div class="epss-card-pred">↗ Prediction +${r.epss}</div>
        </a>`;
    }).join('');
}

function renderMovers(movers, d) {
    const el = document.getElementById('epss-movers');
    const sub = document.getElementById('epss-movers-sub');
    if (d.prev_date && d.score_date) {
        sub.textContent = `EPSS score shifts, ${d.prev_date} → ${d.score_date}`;
    }
    if (!movers.length) {
        el.innerHTML = `<div class="table-empty">No score shifts available (the previous EPSS snapshot couldn't be loaded).</div>`;
        return;
    }
    const rows = movers.map(r => {
        const vendor = (r.product_label || r.vendor || '—');
        const up = (r.delta || 0) >= 0;
        const arrow = up ? '↗' : '↘';
        const dcls = up ? 'delta-up' : 'delta-down';
        return `
        <tr>
            <td class="mono-sm">${escapeHtml(d.score_date || '')}</td>
            <td><a class="epss-cve" href="/cve/${encodeURIComponent(r.cve)}">${escapeHtml(r.cve)}</a></td>
            <td>${escapeHtml(vendor)}</td>
            <td class="epss-prob">${r.epss}%</td>
            <td class="mono-sm">${escapeHtml(r.published || '—')}</td>
            <td class="${dcls}">${arrow} ${up ? '+' : ''}${r.delta}</td>
        </tr>`;
    }).join('');
    el.innerHTML = `
        <table class="epss-table">
            <thead><tr>
                <th>EPSS Scoring Date</th><th>CVE ID</th><th>Vendor</th>
                <th>Score</th><th>CVE Published Date</th><th>Delta</th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
}

async function lookupCve(q) {
    const detail = document.getElementById('epss-detail');
    const id = (q || '').toUpperCase();
    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) {
        detail.innerHTML = q ? `<div class="table-error">Enter a valid CVE id, e.g. CVE-2021-44228.</div>` : '';
        return;
    }
    detail.innerHTML = `<div class="epss-detail-card"><div class="spinner"></div> Looking up ${escapeHtml(id)}…</div>`;
    try {
        const resp = await fetch(`/api/epss?cve=${encodeURIComponent(id)}`);
        const dd = await resp.json();
        if (dd.error) {
            detail.innerHTML = `<div class="table-error">❌ ${escapeHtml(dd.error)}</div>`;
            return;
        }
        const factors = (dd.risk.factors || []).map(f => `
            <div class="factor-row">
                <span class="factor-name">${escapeHtml(f.name)}</span>
                <div class="factor-track"><div class="factor-fill" style="width:${(f.points / f.max * 100).toFixed(0)}%"></div></div>
                <span class="factor-pts">+${f.points}<span class="factor-max">/${f.max}</span></span>
                <span class="factor-detail">${escapeHtml(f.detail)}</span>
            </div>`).join('');
        const band = (dd.risk.band || 'Low').toLowerCase();
        detail.innerHTML = `
            <div class="epss-detail-card">
                <div class="epss-detail-head">
                    <a class="epss-detail-cve" href="/cve/${encodeURIComponent(dd.cve)}">${escapeHtml(dd.cve)}</a>
                    ${dd.in_kev ? '<span class="badge badge-kev">🔥 CISA KEV</span>' : ''}
                    <span class="epss-detail-risk risk-t-${band}">${dd.risk.score}/100 · ${escapeHtml(dd.risk.band)}</span>
                </div>
                <div class="epss-detail-metrics">
                    <span>EPSS <b>${dd.epss_percent}%</b></span>
                    <span>Percentile <b>${dd.percentile_percent}%</b></span>
                    <span>CVSS <b>${dd.cvss != null ? dd.cvss : 'N/A'}</b></span>
                </div>
                <div class="factors">${factors}</div>
                <div class="epss-detail-note">Score is an additive, KEV-informed heuristic — it augments EPSS with confirmed exploitation and severity; it does not replace EPSS.</div>
            </div>`;
    } catch (err) {
        detail.innerHTML = `<div class="table-error">❌ ${escapeHtml(err.message)}</div>`;
    }
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
