// ─── VulNova CVE Table ─────────────────────────────────────────────────

const COLSPAN = 14;

const EXPLOIT_RANK = {
    weaponized: 5, public: 4, likely: 3, elevated: 2, none: 1, "": 0,
};

const SEVERITY_RANK = {
    CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, NONE: 1, "": 0,
};

const state = {
    feed: 'recent',       // recent | kev | ransomware
    page: 1,
    size: 50,
    keyword: '',
    severity: '',
    days: 30,
    kevOnly: false,
    highEpssOnly: false,  // client-side (High EPSS preset)
    preset: 'all',
    totalPages: 0,
    total: 0,
    rows: [],
    sortKey: 'published',
    sortDir: 'desc',
    expanded: new Set(),
};

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('search-btn').addEventListener('click', applySearch);
    document.getElementById('search-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') applySearch();
    });
    document.getElementById('clear-btn').addEventListener('click', clearFilters);
    document.getElementById('severity-filter').addEventListener('change', applySearch);
    document.getElementById('days-filter').addEventListener('change', applySearch);
    document.getElementById('kev-filter').addEventListener('change', () => {
        state.kevOnly = document.getElementById('kev-filter').checked;
        render();
    });
    document.getElementById('page-size').addEventListener('change', (e) => {
        state.size = parseInt(e.target.value);
        state.page = 1;
        loadPage();
    });

    // Predefined filter pills
    document.querySelectorAll('#filter-pills .pill').forEach(pill => {
        pill.addEventListener('click', () => applyPreset(pill.dataset.preset));
    });

    // Pager
    document.getElementById('first-btn').addEventListener('click', () => goToPage(1));
    document.getElementById('prev-btn').addEventListener('click', () => goToPage(state.page - 1));
    document.getElementById('next-btn').addEventListener('click', () => goToPage(state.page + 1));
    document.getElementById('last-btn').addEventListener('click', () => goToPage(state.totalPages || 1));

    // Jump to a specific page
    const jump = () => {
        const v = parseInt(document.getElementById('page-jump').value);
        if (!isNaN(v)) goToPage(v);
    };
    document.getElementById('jump-btn').addEventListener('click', jump);
    document.getElementById('page-jump').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') jump();
    });

    // Sorting — column header clicks
    document.querySelectorAll('.cve-table th.sortable').forEach(th => {
        th.addEventListener('click', () => {
            const key = th.dataset.sort;
            // Toggle direction if same column, else switch column (default desc)
            const dir = (state.sortKey === key)
                ? (state.sortDir === 'desc' ? 'asc' : 'desc')
                : 'desc';
            setSort(key, dir);
        });
    });

    // Sorting — explicit "Sort by" dropdown
    document.getElementById('sort-by').addEventListener('change', (e) => {
        setSort(e.target.value, state.sortDir);
    });

    // Sorting — direction toggle button
    document.getElementById('sort-dir').addEventListener('click', () => {
        setSort(state.sortKey, state.sortDir === 'desc' ? 'asc' : 'desc');
    });

    loadPage();
});

// Central sort setter — keeps the dropdown, direction button, and headers in sync
function setSort(key, dir) {
    state.sortKey = key;
    state.sortDir = dir;

    const sortBy = document.getElementById('sort-by');
    if (sortBy && sortBy.value !== key) {
        // Only reflect keys that exist in the dropdown
        if ([...sortBy.options].some(o => o.value === key)) sortBy.value = key;
    }
    const dirBtn = document.getElementById('sort-dir');
    if (dirBtn) dirBtn.textContent = dir === 'desc' ? '↓ Desc' : '↑ Asc';

    render();
}

// ─── Preset filters ──────────────────────────────────────────────────────────

function applyPreset(preset) {
    state.preset = preset;
    state.page = 1;
    state.highEpssOnly = false;
    state.kevOnly = false;
    document.getElementById('kev-filter').checked = false;

    const daysSel = document.getElementById('days-filter');
    const sevSel = document.getElementById('severity-filter');

    switch (preset) {
        case 'kev':
            state.feed = 'kev';
            break;
        case 'ransomware':
            state.feed = 'ransomware';
            break;
        case 'week':
            state.feed = 'recent';
            state.days = 7; daysSel.value = '7';
            state.severity = ''; sevSel.value = '';
            break;
        case 'critical':
            state.feed = 'recent';
            state.severity = 'CRITICAL'; sevSel.value = 'CRITICAL';
            break;
        case 'highepss':
            state.feed = 'recent';
            state.highEpssOnly = true;
            state.severity = ''; sevSel.value = '';
            break;
        case 'all':
        default:
            state.feed = 'recent';
            state.days = 30; daysSel.value = '30';
            state.severity = ''; sevSel.value = '';
            break;
    }

    // Toggle active pill
    document.querySelectorAll('#filter-pills .pill').forEach(p =>
        p.classList.toggle('pill-active', p.dataset.preset === preset));

    // Disable window/severity for catalog feeds where they don't apply
    const catalogFeed = (state.feed === 'kev' || state.feed === 'ransomware');
    daysSel.disabled = catalogFeed;
    sevSel.disabled = catalogFeed;

    loadPage();
}

function applySearch() {
    state.keyword = document.getElementById('search-input').value.trim();
    if (!document.getElementById('severity-filter').disabled) {
        state.severity = document.getElementById('severity-filter').value;
        state.days = parseInt(document.getElementById('days-filter').value);
    }
    state.page = 1;
    loadPage();
}

function clearFilters() {
    document.getElementById('search-input').value = '';
    document.getElementById('severity-filter').value = '';
    document.getElementById('severity-filter').disabled = false;
    document.getElementById('days-filter').value = '30';
    document.getElementById('days-filter').disabled = false;
    document.getElementById('kev-filter').checked = false;
    Object.assign(state, {
        feed: 'recent', keyword: '', severity: '', days: 30,
        kevOnly: false, highEpssOnly: false, preset: 'all', page: 1,
    });
    document.querySelectorAll('#filter-pills .pill').forEach(p =>
        p.classList.toggle('pill-active', p.dataset.preset === 'all'));
    loadPage();
}

function goToPage(page) {
    if (page < 1 || (state.totalPages && page > state.totalPages)) return;
    state.page = page;
    loadPage();
}

// ─── Data loading ──────────────────────────────────────────────────────────

async function loadPage() {
    const tbody = document.getElementById('cve-tbody');
    tbody.innerHTML = `<tr><td colspan="${COLSPAN}" class="table-loading">
        <div class="spinner"></div><div>Loading CVEs…</div></td></tr>`;

    const params = new URLSearchParams({ page: state.page, size: state.size, feed: state.feed });
    if (state.keyword) params.set('keyword', state.keyword);
    if (state.feed === 'recent') {
        if (state.severity) params.set('severity', state.severity);
        if (state.days) params.set('days', state.days);
    }

    try {
        const resp = await fetch('/api/cves?' + params.toString());
        const data = await resp.json();
        if (data.error) {
            tbody.innerHTML = `<tr><td colspan="${COLSPAN}" class="table-error">❌ ${escapeHtml(data.error)}</td></tr>`;
            return;
        }
        state.rows = data.rows || [];
        state.total = data.total || 0;
        state.totalPages = data.pages || 0;
        state.expanded.clear();
        render();
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="${COLSPAN}" class="table-error">❌ Network error: ${escapeHtml(err.message)}</td></tr>`;
    }
}

// ─── Rendering ─────────────────────────────────────────────────────────────

function sortAccessor(row, key) {
    if (key === 'exploit_status') return EXPLOIT_RANK[(row.exploit_status && row.exploit_status.level) || ''] || 0;
    if (key === 'severity') return SEVERITY_RANK[(row.severity || '').toUpperCase()] || 0;
    if (key === 'product_label') return (row.product && row.product.label) || '';
    if (key === 'in_kev') return row.in_kev ? 1 : 0;
    if (key === 'cwe') return (row.weaknesses && row.weaknesses.length) ? row.weaknesses[0] : '';
    return row[key];
}

function render() {
    const tbody = document.getElementById('cve-tbody');

    let rows = state.rows.slice();
    if (state.kevOnly) rows = rows.filter(r => r.in_kev);
    if (state.highEpssOnly) rows = rows.filter(r => r.epss_percent >= 50);

    rows.sort((a, b) => {
        let av = sortAccessor(a, state.sortKey);
        let bv = sortAccessor(b, state.sortKey);
        if (typeof av === 'boolean') { av = av ? 1 : 0; bv = bv ? 1 : 0; }
        if (typeof av === 'string') { av = av.toLowerCase(); bv = (bv || '').toLowerCase(); }
        if (av < bv) return state.sortDir === 'asc' ? -1 : 1;
        if (av > bv) return state.sortDir === 'asc' ? 1 : -1;
        return 0;
    });

    if (rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="${COLSPAN}" class="table-empty">No CVEs match the current filters.</td></tr>`;
    } else {
        tbody.innerHTML = rows.map(renderRow).join('');
        tbody.querySelectorAll('.col-expand button').forEach(btn => {
            btn.addEventListener('click', () => toggleExpand(btn.dataset.cve));
        });
    }

    // Stats pill — include the active scope so the count isn't misleading
    let feedLabel = 'CVEs';
    if (state.feed === 'kev') feedLabel = 'KEV entries';
    else if (state.feed === 'ransomware') feedLabel = 'ransomware CVEs';

    let scope = '';
    if (state.feed === 'recent') {
        scope = state.days ? ` · last ${state.days} days` : ' · all time';
        if (state.keyword) scope = ` · "${state.keyword}"`;
        else if (state.severity) scope += ` · ${state.severity}`;
    }
    document.getElementById('stat-total').textContent =
        state.total.toLocaleString() + ' ' + feedLabel + scope;

    const startN = (state.page - 1) * state.size + 1;
    const endN = Math.min(state.page * state.size, state.total);
    document.getElementById('pager-info').textContent =
        state.total ? `Showing ${startN.toLocaleString()}–${endN.toLocaleString()} of ${state.total.toLocaleString()}` : '—';
    document.getElementById('pager-page').textContent =
        `Page ${state.page}${state.totalPages ? ' / ' + state.totalPages.toLocaleString() : ''}`;

    const jumpInput = document.getElementById('page-jump');
    if (jumpInput) jumpInput.max = state.totalPages || 1;

    document.getElementById('prev-btn').disabled = state.page <= 1;
    document.getElementById('first-btn').disabled = state.page <= 1;
    document.getElementById('next-btn').disabled = state.totalPages && state.page >= state.totalPages;
    document.getElementById('last-btn').disabled = !state.totalPages || state.page >= state.totalPages;

    document.querySelectorAll('.cve-table th.sortable').forEach(th => {
        const base = th.textContent.replace(/[▾▴]/g, '').trim();
        th.textContent = base + (state.sortKey === th.dataset.sort ? (state.sortDir === 'desc' ? ' ▾' : ' ▴') : '');
    });
}

function renderRow(r) {
    const sev = (r.triage_label || 'INFO').toLowerCase();
    const cvssSev = (r.severity || 'NONE').toLowerCase();
    const isExpanded = state.expanded.has(r.cve_id);
    const cwe = (r.weaknesses && r.weaknesses.length) ? r.weaknesses[0] : '—';
    const es = r.exploit_status || { label: '—', level: 'none', detail: '' };

    // KEV cell with ransomware marker
    let kevCell = '<span class="kev-no">—</span>';
    if (r.in_kev) {
        const ransom = (r.kev_ransomware || '').toLowerCase() === 'known';
        kevCell = `<span class="kev-yes">🔥 YES</span>${ransom ? ' <span class="ransom-tag" title="Known ransomware use">🦠</span>' : ''}`;
    }

    // Product cell
    let productCell = '<span class="prod-none">—</span>';
    if (r.product && r.product.label) {
        const more = r.product.more > 0 ? `<span class="prod-more" title="${r.product.more} more affected products">+${r.product.more}</span>` : '';
        productCell = `<span class="prod-label" title="Filter by ${escapeHtml(r.product.vendor)}">${escapeHtml(r.product.label)}</span>${more}`;
    }

    // CVSS cell (pending in KEV feed)
    const cvssCell = r.cvss_pending
        ? '<span class="cvss-pending" title="Loads when expanded">—</span>'
        : `<span class="cvss-val cvss-${cvssSev}">${r.cvss_score || '—'}</span>`;

    // Published cell (KEV feed shows date added to KEV)
    const pubCell = r.published
        ? `<span class="mono-sm">${r.published}</span>`
        : (r.kev_date_added ? `<span class="mono-sm kev-added" title="Added to CISA KEV">KEV ${r.kev_date_added}</span>` : '<span class="mono-sm">—</span>');

    const mainRow = `
    <tr class="data-row ${r.in_kev ? 'row-kev' : ''}">
        <td class="col-expand">
            <button data-cve="${r.cve_id}" class="expand-btn" title="Details">${isExpanded ? '▼' : '▶'}</button>
        </td>
        <td class="cell-cve"><a class="mono cve-link" href="/cve/${r.cve_id}" target="_blank" rel="noopener" title="Open full CVE page">${r.cve_id}</a>${(r.cve_tags && r.cve_tags.some(t => /disput/i.test(t))) ? ' <span class="disputed-flag" title="Disputed by vendor">⚑</span>' : ''}</td>
        <td><span class="triage-chip triage-${sev}">${r.triage_score}</span></td>
        <td><span class="exp-badge exp-${es.level}" title="${escapeHtml(es.detail)}">${escapeHtml(es.label)}</span></td>
        <td>${cvssCell}</td>
        <td>${r.severity ? `<span class="sev-badge sev-${cvssSev}">${r.severity}</span>` : '<span class="sev-badge sev-none">—</span>'}</td>
        <td>${r.epss_percent}%</td>
        <td>${kevCell}</td>
        <td class="col-product">${productCell}</td>
        <td class="col-desc" title="${escapeHtml(r.description)}">${escapeHtml(truncate(r.description, 110))}</td>
        <td>${pubCell}</td>
        <td class="mono-sm">${r.last_modified || '—'}</td>
        <td class="mono-sm">${escapeHtml(cwe)}</td>
        <td class="col-link"><a href="${r.nvd_url}" target="_blank" rel="noopener" title="Open in NVD">↗</a></td>
    </tr>`;

    const detailRow = isExpanded ? `
    <tr class="detail-row">
        <td colspan="${COLSPAN}">
            <div class="detail-panel" id="detail-${r.cve_id}">
                <div class="detail-loading"><div class="spinner spinner-sm"></div> Loading full detail + exploit intel…</div>
            </div>
        </td>
    </tr>` : '';

    return mainRow + detailRow;
}

async function toggleExpand(cveId) {
    if (state.expanded.has(cveId)) {
        state.expanded.delete(cveId);
        render();
        return;
    }
    state.expanded.add(cveId);
    render();

    const panel = document.getElementById('detail-' + cveId);
    if (!panel) return;

    try {
        const resp = await fetch('/api/cve/' + encodeURIComponent(cveId));
        const d = await resp.json();
        if (d.error) {
            panel.innerHTML = `<div class="table-error">${escapeHtml(d.error)}</div>`;
            return;
        }
        panel.innerHTML = renderDetail(d);
    } catch (err) {
        panel.innerHTML = `<div class="table-error">Error: ${escapeHtml(err.message)}</div>`;
    }
}

const SOURCE_CLASS = {
    ExploitDB: 'src-exploitdb', GitHub: 'src-github', Metasploit: 'src-metasploit',
    Nuclei: 'src-nuclei', Vulhub: 'src-vulhub',
};

function renderDetail(d) {
    // Exploit intel
    let exploitsBlock = '';
    if (d.exploits && d.exploits.length) {
        const items = d.exploits.map(e => `
            <li class="exploit-item">
                <span class="exploit-source ${SOURCE_CLASS[e.source] || ''}">${escapeHtml(e.source)}</span>
                <a href="${e.url}" target="_blank" rel="noopener" class="exploit-link">${escapeHtml(e.name)}</a>
                ${e.stars !== undefined ? `<span class="poc-stars">⭐ ${e.stars}</span>` : ''}
                ${e.command ? `<code class="msf-cmd">${escapeHtml(e.command)}</code>` : ''}
            </li>`).join('');
        exploitsBlock = `<div class="detail-block">
            <div class="detail-label">💥 Public Exploits &amp; PoCs (${d.exploits.length})</div>
            <ul class="exploit-list">${items}</ul></div>`;
    } else {
        exploitsBlock = `<div class="detail-block">
            <div class="detail-label">💥 Public Exploits &amp; PoCs</div>
            <div class="detail-none">No public exploits found across ExploitDB, GitHub, Metasploit, Nuclei, or Vulhub.</div></div>`;
    }

    // References grouped by category
    const catNames = { vendor: '🏢 Vendor / Patch', exploit: '💣 Exploit', advisory: '📢 Advisory', other: '🔗 Other' };
    const grouped = { vendor: [], exploit: [], advisory: [], other: [] };
    (d.references || []).forEach(r => { (grouped[r.category] || grouped.other).push(r); });
    let refsBlock = '';
    for (const cat of ['vendor', 'exploit', 'advisory', 'other']) {
        const list = grouped[cat];
        if (!list.length) continue;
        const items = list.slice(0, 8).map(r =>
            `<li><a href="${r.url}" target="_blank" rel="noopener">${escapeHtml(truncate(r.url, 68))}</a></li>`
        ).join('');
        refsBlock += `<div class="ref-group"><div class="ref-group-title">${catNames[cat]} (${list.length})</div><ul class="ref-list">${items}</ul></div>`;
    }

    const cpes = (d.cpes || []).slice(0, 12).map(c => `<code class="cpe">${escapeHtml(c)}</code>`).join('');

    let kevBlock = '';
    if (d.in_kev && d.kev_details) {
        kevBlock = `
        <div class="detail-kev">
            <strong>🔥 CISA KEV — Actively Exploited</strong><br>
            Added: ${escapeHtml(d.kev_details.date_added || '')} ·
            Due: ${escapeHtml(d.kev_details.due_date || '')} ·
            Ransomware: ${escapeHtml(d.kev_details.known_ransomware_use || 'Unknown')}<br>
            <em>${escapeHtml(d.kev_details.required_action || '')}</em>
        </div>`;
    }

    const productLine = (d.product && d.product.label)
        ? `<div class="detail-product">📦 <strong>${escapeHtml(d.product.label)}</strong></div>` : '';

    // NVD tags (Disputed, etc.)
    const tagsLine = (d.cve_tags && d.cve_tags.length)
        ? `<div class="detail-tags">${d.cve_tags.map(t =>
            `<span class="tagbadge tagbadge-warn">⚑ ${escapeHtml(t.replace(/([A-Z])/g, ' $1').trim())}</span>`).join('')}</div>`
        : '';

    // Fixed versions summary
    let fixedLine = '';
    const allFixed = [];
    (d.affected_versions || []).forEach(v => (v.fixed || []).forEach(f => allFixed.push(f)));
    if (allFixed.length) {
        const uniq = [...new Set(allFixed)].slice(0, 6);
        fixedLine = `<div class="detail-fixed">🛠️ <strong>Fixed in:</strong> ${uniq.map(f => `<span class="ver-fixed">✓ ${escapeHtml(f)}</span>`).join(' ')}</div>`;
    }

    return `
    <div class="detail-grid">
        <div class="detail-main">
            <a class="open-full-link" href="/cve/${d.cve_id}" target="_blank" rel="noopener">🔎 Open full CVE page ↗</a>
            ${productLine}
            ${tagsLine}
            <div class="detail-desc">${escapeHtml(d.description)}</div>
            ${fixedLine}
            ${kevBlock}
            <div class="detail-rec"><strong>Recommendation:</strong> ${escapeHtml(d.recommendation)}</div>
            ${exploitsBlock}
            ${cpes ? `<div class="detail-block"><div class="detail-label">🎯 Affected (CPE)</div>${cpes}</div>` : ''}
            ${refsBlock ? `<div class="detail-block"><div class="detail-label">🔗 References</div>${refsBlock}</div>` : ''}
        </div>
        <div class="detail-side">
            <div class="side-metric"><div class="side-label">Triage</div><div class="side-value triage-${d.triage_label.toLowerCase()}">${d.triage_score}/100</div></div>
            <div class="side-metric"><div class="side-label">CVSS</div><div class="side-value">${d.cvss_score} (${d.severity || 'N/A'})</div></div>
            <div class="side-metric"><div class="side-label">EPSS</div><div class="side-value">${d.epss_percent}%</div></div>
            <div class="side-metric"><div class="side-label">Vector</div><div class="side-value mono-xs">${escapeHtml(d.vector || 'N/A')}</div></div>
            <div class="side-metric"><div class="side-label">Published</div><div class="side-value mono-sm">${(d.published || '').slice(0,10) || '—'}</div></div>
            <div class="side-metric"><div class="side-label">Last Modified</div><div class="side-value mono-sm">${(d.last_modified || '').slice(0,10) || '—'}</div></div>
            <div class="side-metric"><a class="side-nvd" href="https://nvd.nist.gov/vuln/detail/${d.cve_id}" target="_blank" rel="noopener">Open in NVD ↗</a></div>
        </div>
    </div>`;
}

// ─── Utilities ───────────────────────────────────────────────────────────────

function truncate(str, n) {
    if (!str) return '';
    return str.length > n ? str.slice(0, n) + '…' : str;
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
