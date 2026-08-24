// ─── VulNova Flare — Vendor / GHSA Advisories ────────────────────────────────

const fstate = {
    all: [],
    cve: 'all',        // all | none | has
    severity: '',
    ecosystem: '',
    source: '',
    type: 'reviewed',
    search: '',
};

const SOURCE_ABBR = {
    "GitHub Advisory Database": "GHSA",
    "Ubuntu Security Notices": "Ubuntu",
    "Red Hat": "Red Hat",
    "Palo Alto Networks": "Palo Alto",
    "Microsoft": "MSRC",
    "VMware": "VMware",
    "OSV": "OSV",
};

// Display name → API source key (for focused fetching)
const SOURCE_KEY = {
    "GitHub Advisory Database": "github",
    "Ubuntu Security Notices": "ubuntu",
    "Red Hat": "redhat",
    "Palo Alto Networks": "paloalto",
    "Microsoft": "microsoft",
    "VMware": "vmware",
    "OSV": "osv",
};

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('refresh-btn').addEventListener('click', () => load(true));
    document.getElementById('sev-filter').addEventListener('change', render);
    document.getElementById('eco-filter').addEventListener('change', render);
    document.getElementById('source-filter').addEventListener('change', () => load(false));
    document.getElementById('type-filter').addEventListener('change', () => load(false));
    document.getElementById('flare-search').addEventListener('input', (e) => {
        fstate.search = e.target.value.trim().toLowerCase();
        render();
    });
    document.querySelectorAll('#cve-pills .pill').forEach(pill => {
        pill.addEventListener('click', () => {
            document.querySelectorAll('#cve-pills .pill').forEach(p => p.classList.remove('pill-active'));
            pill.classList.add('pill-active');
            fstate.cve = pill.dataset.cve;
            render();
        });
    });
    load(false);
});

async function load(force) {
    const feed = document.getElementById('flare-feed');
    fstate.type = document.getElementById('type-filter').value;
    feed.innerHTML = `<div class="table-loading"><div class="spinner"></div>
        <div>${force ? 'Refreshing advisories…' : 'Loading advisories from the GitHub Advisory Database…'}</div></div>`;

    const params = new URLSearchParams({ limit: 600, type: fstate.type });
    if (force) params.set('refresh', '1');
    // If a specific source is selected, fetch just that source so it's never
    // crowded out by the larger feeds.
    const selSource = document.getElementById('source-filter').value;
    if (selSource && SOURCE_KEY[selSource]) params.set('sources', SOURCE_KEY[selSource]);

    try {
        const resp = await fetch('/api/advisories?' + params.toString());
        const data = await resp.json();
        if (data.error) {
            feed.innerHTML = `<div class="table-error">❌ ${escapeHtml(data.error)}</div>`;
            return;
        }
        fstate.all = data.advisories || [];
        populateEcosystems(data.ecosystems || []);
        render();
    } catch (err) {
        feed.innerHTML = `<div class="table-error">❌ ${escapeHtml(err.message)}</div>`;
    }
}

function populateEcosystems(ecosystems) {
    const sel = document.getElementById('eco-filter');
    const current = sel.value;
    sel.innerHTML = '<option value="">All</option>' +
        ecosystems.map(e => `<option value="${escapeHtml(e)}">${escapeHtml(e)}</option>`).join('');
    if (ecosystems.includes(current)) sel.value = current;
}

function render() {
    const feed = document.getElementById('flare-feed');
    fstate.severity = document.getElementById('sev-filter').value;
    fstate.ecosystem = document.getElementById('eco-filter').value;

    fstate.source = document.getElementById('source-filter').value;

    let items = fstate.all.slice();
    if (fstate.cve === 'none') items = items.filter(a => !a.has_cve);
    else if (fstate.cve === 'has') items = items.filter(a => a.has_cve);
    if (fstate.severity) items = items.filter(a => a.severity === fstate.severity);
    if (fstate.ecosystem) items = items.filter(a => (a.ecosystems || []).includes(fstate.ecosystem));
    if (fstate.source) items = items.filter(a => a.source === fstate.source);
    if (fstate.search) {
        const q = fstate.search;
        items = items.filter(a =>
            a.summary.toLowerCase().includes(q) ||
            (a.advisory_id || '').toLowerCase().includes(q) ||
            (a.cve_id || '').toLowerCase().includes(q) ||
            (a.packages || []).some(p => p.toLowerCase().includes(q))
        );
    }

    // Stats
    const noCve = fstate.all.filter(a => !a.has_cve).length;
    document.getElementById('stat-total').textContent =
        `${fstate.all.length} advisories · ${noCve} no-CVE`;

    if (items.length === 0) {
        feed.innerHTML = `<div class="table-empty">No advisories match the current filters.</div>`;
        return;
    }
    feed.innerHTML = items.map(renderCard).join('');
}

function renderCard(a) {
    const sev = (a.severity || 'unknown').toLowerCase();
    const cveBadge = a.has_cve
        ? `<a class="adv-cve has" href="/cve/${a.cve_id}" target="_blank" rel="noopener" title="Open in Atlas">${a.cve_id}</a>`
        : `<span class="adv-cve none">🚩 No CVE</span>`;
    const pkgs = (a.packages || []).slice(0, 4)
        .map(p => `<span class="adv-pkg">${escapeHtml(p)}</span>`).join('');
    const cwes = (a.cwes || []).slice(0, 3)
        .map(c => `<span class="adv-cwe">${escapeHtml(c)}</span>`).join('');

    const srcAbbr = SOURCE_ABBR[a.source] || a.source;
    return `
    <div class="advisory-card sev-border-${sev}">
        <div class="adv-head">
            <span class="adv-src" title="${escapeHtml(a.source)}">${escapeHtml(srcAbbr)}</span>
            <a class="adv-ghsa" href="${a.url}" target="_blank" rel="noopener">${escapeHtml(a.advisory_id)}</a>
            <span class="sev-badge sev-${sev}">${a.severity}${a.cvss_score ? ' · ' + a.cvss_score : ''}</span>
            ${cveBadge}
            <span class="adv-date">${escapeHtml(a.published)}</span>
        </div>
        <div class="adv-summary">${escapeHtml(a.summary)}</div>
        <div class="adv-meta">
            ${pkgs}
            ${cwes}
            ${a.epss_percent ? `<span class="adv-epss">EPSS ${a.epss_percent}%</span>` : ''}
        </div>
    </div>`;
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
