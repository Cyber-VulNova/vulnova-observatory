// ─── VulNova ATT&CK — MITRE ATT&CK Enterprise matrix ─────────────────────────

const astate = { tactics: [], techniques: [], search: '', subs: false };

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('attack-search').addEventListener('input', (e) => {
        astate.search = e.target.value.trim().toLowerCase();
        renderMatrix();
    });
    document.getElementById('attack-subs').addEventListener('change', (e) => {
        astate.subs = e.target.checked;
        renderMatrix();
    });
    load();
});

async function load() {
    const el = document.getElementById('attack-matrix');
    try {
        const resp = await fetch('/api/attack');
        const data = await resp.json();
        if (data.error) {
            el.innerHTML = `<div class="table-error">❌ ${escapeHtml(data.error)}</div>`;
            return;
        }
        astate.tactics = data.tactics || [];
        astate.techniques = data.techniques || [];

        const upd = data.updated ? new Date(data.updated * 1000).toLocaleDateString() : '';
        document.getElementById('attack-updated').textContent = upd ? `MITRE data cached ${upd}` : '';
        renderMatrix();
    } catch (err) {
        el.innerHTML = `<div class="table-error">❌ ${escapeHtml(err.message)}</div>`;
    }
}

function renderMatrix() {
    const el = document.getElementById('attack-matrix');
    const q = astate.search;

    // Group techniques by tactic shortname, applying the filters.
    const byTactic = {};
    astate.tactics.forEach(t => { byTactic[t.shortname] = []; });

    let shown = 0;
    astate.techniques.forEach(tech => {
        if (tech.is_sub && !astate.subs) return;
        if (q && !(tech.name.toLowerCase().includes(q) || tech.id.toLowerCase().includes(q))) return;
        shown++;
        (tech.tactics || []).forEach(sn => {
            if (byTactic[sn]) byTactic[sn].push(tech);
        });
    });

    document.getElementById('attack-stat').textContent =
        `${shown} technique${shown === 1 ? '' : 's'} · ${astate.tactics.length} tactics`;

    if (!astate.tactics.length) {
        el.innerHTML = `<div class="table-empty">No ATT&CK data available.</div>`;
        return;
    }

    const cols = astate.tactics.map(t => {
        const techs = byTactic[t.shortname] || [];
        const cells = techs.map(techCell).join('');
        return `
        <div class="attack-col">
            <div class="attack-col-head">
                <span class="attack-tactic-name">${escapeHtml(t.name)}</span>
                <span class="attack-tactic-count">${techs.length}</span>
            </div>
            <div class="attack-col-body">${cells || '<div class="attack-empty">—</div>'}</div>
        </div>`;
    }).join('');

    el.innerHTML = `<div class="attack-cols">${cols}</div>`;
}

function techCell(t) {
    const sub = t.is_sub ? ' attack-cell-sub' : '';
    const plat = (t.platforms || []).length ? ` title="${escapeHtml(t.desc || '')}\n\nPlatforms: ${escapeHtml((t.platforms||[]).join(', '))}"` : ` title="${escapeHtml(t.desc || '')}"`;
    return `<a class="attack-cell${sub}" href="${t.url}" target="_blank" rel="noopener"${plat}>
        <span class="attack-cell-id">${escapeHtml(t.id)}</span>
        <span class="attack-cell-name">${escapeHtml(t.name)}</span>
    </a>`;
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
