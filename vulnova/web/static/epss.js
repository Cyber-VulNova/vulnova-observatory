// ─── VulNova EPSS — exploitation prediction ranking + risk scoring ──────────

const estate = { rows: [] };

document.addEventListener('DOMContentLoaded', () => {
    const search = document.getElementById('epss-search');
    search.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') lookupCve(search.value.trim());
    });
    load();
});

async function load() {
    const el = document.getElementById('epss-table');
    try {
        const resp = await fetch('/api/epss');
        const data = await resp.json();
        if (data.error) {
            el.innerHTML = `<div class="table-error">❌ ${escapeHtml(data.error)}</div>`;
            return;
        }
        estate.rows = data.top || [];
        renderStats(data.stats || {});
        const upd = (data.stats && data.stats.date) ? `EPSS model ${data.stats.date}` : '';
        document.getElementById('epss-updated').textContent = upd;
        document.getElementById('epss-stat').textContent = `top ${estate.rows.length} ranked`;
        renderTable();
    } catch (err) {
        el.innerHTML = `<div class="table-error">❌ ${escapeHtml(err.message)}</div>`;
    }
}

function renderStats(s) {
    const el = document.getElementById('epss-stats');
    const card = (label, val, cls, sub) => `
        <div class="epss-stat-card ${cls || ''}">
            <div class="epss-stat-val">${val === undefined ? '—' : Number(val).toLocaleString()}</div>
            <div class="epss-stat-label">${escapeHtml(label)}</div>
            <div class="epss-stat-sub">${escapeHtml(sub || '')}</div>
        </div>`;
    el.innerHTML =
        card('High probability', s.high, 'crit', 'EPSS ≥ 50%') +
        card('Elevated', s.elevated, 'high', 'EPSS ≥ 10%') +
        card('Moderate', s.moderate, 'mod', 'EPSS ≥ 1%');
}

function riskBar(risk) {
    if (!risk) return '';
    const score = risk.score || 0;
    const band = (risk.band || 'Low').toLowerCase();
    return `<div class="risk-cell" title="${escapeHtml(riskTip(risk))}">
        <div class="risk-track"><div class="risk-fill risk-${band}" style="width:${score}%"></div></div>
        <span class="risk-num risk-t-${band}">${score}</span>
    </div>`;
}

function riskTip(risk) {
    const parts = (risk.factors || []).map(f => `${f.name}: +${f.points}/${f.max} (${f.detail})`);
    return `Exploitation Risk ${risk.score}/100 · ${risk.band}\n` + parts.join('\n');
}

function renderTable() {
    const el = document.getElementById('epss-table');
    if (!estate.rows.length) {
        el.innerHTML = `<div class="table-empty">No EPSS data available.</div>`;
        return;
    }
    const body = estate.rows.map((r, i) => `
        <tr>
            <td class="epss-rank">${i + 1}</td>
            <td><a class="epss-cve" href="/cve/${encodeURIComponent(r.cve)}">${escapeHtml(r.cve)}</a></td>
            <td class="epss-prob">${r.epss_percent}%</td>
            <td class="epss-pct">${r.percentile_percent}%</td>
            <td>${r.in_kev ? '<span class="badge badge-kev">🔥 KEV</span>' : '<span class="epss-dim">—</span>'}</td>
            <td>${riskBar(r.risk)}</td>
        </tr>`).join('');
    el.innerHTML = `
        <table class="epss-table">
            <thead><tr>
                <th>#</th><th>CVE</th><th>EPSS</th><th>Percentile</th><th>KEV</th>
                <th>Exploitation Risk <span class="th-note">VulNova · heuristic</span></th>
            </tr></thead>
            <tbody>${body}</tbody>
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
        const d = await resp.json();
        if (d.error) {
            detail.innerHTML = `<div class="table-error">❌ ${escapeHtml(d.error)}</div>`;
            return;
        }
        const factors = (d.risk.factors || []).map(f => `
            <div class="factor-row">
                <span class="factor-name">${escapeHtml(f.name)}</span>
                <div class="factor-track"><div class="factor-fill" style="width:${(f.points / f.max * 100).toFixed(0)}%"></div></div>
                <span class="factor-pts">+${f.points}<span class="factor-max">/${f.max}</span></span>
                <span class="factor-detail">${escapeHtml(f.detail)}</span>
            </div>`).join('');
        const band = (d.risk.band || 'Low').toLowerCase();
        detail.innerHTML = `
            <div class="epss-detail-card">
                <div class="epss-detail-head">
                    <a class="epss-detail-cve" href="/cve/${encodeURIComponent(d.cve)}">${escapeHtml(d.cve)}</a>
                    ${d.in_kev ? '<span class="badge badge-kev">🔥 CISA KEV</span>' : ''}
                    <span class="epss-detail-risk risk-t-${band}">${d.risk.score}/100 · ${escapeHtml(d.risk.band)}</span>
                </div>
                <div class="epss-detail-metrics">
                    <span>EPSS <b>${d.epss_percent}%</b></span>
                    <span>Percentile <b>${d.percentile_percent}%</b></span>
                    <span>CVSS <b>${d.cvss != null ? d.cvss : 'N/A'}</b></span>
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
