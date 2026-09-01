// ─── VulNova Backlog — Build Roadmap ─────────────────────────────────────────
// Reflects the current build queue. Update statuses as items ship.

const BACKLOG = [
    { id: 1, title: 'CVSS score for KEV feed rows', status: 'done',
      desc: 'The CISA KEV catalog carries no CVSS. KEV rows are now enriched with CVSS from NVD when an NVD API key is configured (via .env); without a key, CVSS still fills in when a row is expanded.' },
    { id: 2, title: 'Column: Remote-code-exploit availability', status: 'done',
      desc: 'Atlas "RCE" column: 💥 Yes (RCE-type + public exploit), ◐ Potential (RCE-type by CWE/description), or —. Heuristic from CWE + description + exploit availability.' },
    { id: 3, title: 'Column: Exploit availability', status: 'done',
      desc: 'Atlas "Avail" column shows whether a public exploit exists (CISA KEV weaponized or an Exploit-DB entry).' },
    { id: 4, title: 'Fix the CVE page “Track” button', status: 'done',
      desc: 'The Track button overlapped the product line because the base .btn had no display value (inline anchor). Fixed by making buttons inline-flex.' },
    { id: 5, title: 'Light theme', status: 'done',
      desc: 'A light/dark theme toggle (☀️/🌙 in the top bar), persisted per browser, across all pages.' },
    { id: 6, title: 'CVEfeed.io integration', status: 'done',
      desc: 'CVE pages now show a "Remediation & Decision Intel" section from CVEfeed.io — remediation solution, SSVC decision points, and remote-exploitability. Uses the public API; set CVEFEED_API_KEY in .env to raise rate limits.' },
    { id: 7, title: 'CVSS-vector search', status: 'done',
      desc: 'Atlas has a "Vector" search box to query CVEs by CVSS v3 vector components (e.g. AV:N/AC:L/PR:N), backed by the NVD cvssV3Metrics filter.' },
    { id: 8, title: '.env for API keys (NVD + CVEfeed.io)', status: 'done',
      desc: 'NVD_API_KEY / CVEFEED_API_KEY / GITHUB_TOKEN are loaded from a .env file (see .env.example) for better data availability and higher rate limits.' },
    { id: 9, title: 'EPSS score & prediction tracking page', status: 'planned',
      desc: 'A dedicated page for exploitation-probability: EPSS scores, history, and trend/prediction. (Full custom ML is a larger effort — scope TBD.)' },
    { id: 10, title: 'Backlog page', status: 'done',
      desc: 'This page — a live roadmap tracking every build item and its status.' },
];

const STATUS = {
    done: { label: 'Done', cls: 'bk-done', icon: '✅' },
    in_progress: { label: 'In progress', cls: 'bk-progress', icon: '🚧' },
    planned: { label: 'Planned', cls: 'bk-planned', icon: '🗓' },
};

let activeFilter = 'all';

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('#backlog-filters .pill').forEach(pill => {
        pill.addEventListener('click', () => {
            document.querySelectorAll('#backlog-filters .pill').forEach(p => p.classList.remove('pill-active'));
            pill.classList.add('pill-active');
            activeFilter = pill.dataset.filter;
            render();
        });
    });
    render();
});

function render() {
    const list = document.getElementById('backlog-list');
    const counts = { done: 0, in_progress: 0, planned: 0 };
    BACKLOG.forEach(i => { counts[i.status] = (counts[i.status] || 0) + 1; });
    document.getElementById('backlog-stat').textContent =
        `${counts.done} done · ${counts.in_progress} in progress · ${counts.planned} planned`;

    const items = BACKLOG.filter(i => activeFilter === 'all' || i.status === activeFilter);
    if (!items.length) {
        list.innerHTML = `<div class="table-empty">Nothing here.</div>`;
        return;
    }
    list.innerHTML = items.map(cardHtml).join('');
}

function cardHtml(i) {
    const s = STATUS[i.status] || STATUS.planned;
    const blocked = i.blocked ? `<span class="bk-blocked" title="Blocked on external input">⛔ blocked</span>` : '';
    return `
    <div class="backlog-card ${s.cls}">
        <div class="backlog-card-head">
            <span class="backlog-num">#${i.id}</span>
            <span class="backlog-title">${escapeHtml(i.title)}</span>
            <span class="backlog-status ${s.cls}">${s.icon} ${s.label}</span>
            ${blocked}
        </div>
        <div class="backlog-desc">${escapeHtml(i.desc)}</div>
    </div>`;
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
