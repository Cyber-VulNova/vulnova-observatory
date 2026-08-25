// ─── VulNova Orbit — CVE Tracking / Watchlist ────────────────────────────────

const STATUS_LABEL = { open: 'Open', in_progress: 'In progress', resolved: 'Resolved' };

document.addEventListener('DOMContentLoaded', () => {
    // Prefill the CVE from ?cve=... (used by the "Track this CVE" button).
    const params = new URLSearchParams(location.search);
    const preCve = params.get('cve');
    if (preCve) {
        document.getElementById('f-cve').value = preCve.toUpperCase();
        document.getElementById('f-assets').focus();
    }

    document.getElementById('track-form').addEventListener('submit', onSubmit);
    document.getElementById('track-cancel').addEventListener('click', resetForm);
    load();
});

async function load() {
    const list = document.getElementById('orbit-list');
    try {
        const resp = await fetch('/api/tracking');
        const data = await resp.json();
        if (data.error) {
            list.innerHTML = `<div class="table-error">❌ ${escapeHtml(data.error)}</div>`;
            return;
        }
        renderList(data.items || []);
    } catch (err) {
        list.innerHTML = `<div class="table-error">❌ ${escapeHtml(err.message)}</div>`;
    }
}

async function onSubmit(e) {
    e.preventDefault();
    const id = document.getElementById('edit-id').value;
    const payload = {
        cve_id: document.getElementById('f-cve').value.trim(),
        assets_affected: parseInt(document.getElementById('f-assets').value) || 0,
        start_date: document.getElementById('f-start').value,
        due_date: document.getElementById('f-due').value,
        status: document.getElementById('f-status').value,
        notes: document.getElementById('f-notes').value,
    };
    if (!payload.cve_id) { setMsg('CVE ID is required.', true); return; }

    const url = id ? `/api/tracking/${id}` : '/api/tracking';
    const method = id ? 'PATCH' : 'POST';
    try {
        const resp = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await resp.json();
        if (!resp.ok) { setMsg(data.error || 'Save failed.', true); return; }
        setMsg(id ? 'Updated.' : 'Tracked.', false);
        resetForm();
        load();
    } catch (err) {
        setMsg(err.message, true);
    }
}

function resetForm() {
    document.getElementById('edit-id').value = '';
    document.getElementById('track-form').reset();
    document.getElementById('f-assets').value = '0';
    document.getElementById('track-submit').textContent = '＋ Track CVE';
    document.getElementById('track-cancel').style.display = 'none';
}

function setMsg(text, isError) {
    const el = document.getElementById('track-msg');
    el.textContent = text;
    el.className = 'orbit-form-msg' + (isError ? ' is-error' : ' is-ok');
    if (text && !isError) setTimeout(() => { el.textContent = ''; }, 2500);
}

function renderList(items) {
    const list = document.getElementById('orbit-list');
    document.getElementById('orbit-stat').textContent =
        `${items.length} tracked`;

    if (!items.length) {
        list.innerHTML = `<div class="table-empty">No CVEs tracked yet. Add one above, or use "Track this CVE" from any CVE page.</div>`;
        return;
    }

    const rows = items.map(rowHtml).join('');
    list.innerHTML = `
    <table class="orbit-table">
        <thead>
            <tr>
                <th>CVE</th><th>Assets</th><th>Start</th><th>Due</th>
                <th>Status</th><th>Notes</th><th></th>
            </tr>
        </thead>
        <tbody>${rows}</tbody>
    </table>`;

    list.querySelectorAll('[data-edit]').forEach(b =>
        b.addEventListener('click', () => startEdit(b.dataset.edit)));
    list.querySelectorAll('[data-del]').forEach(b =>
        b.addEventListener('click', () => removeItem(b.dataset.del)));
}

// Keep the raw items around for edit lookups.
let _items = [];
function rowHtml(it) {
    _items[it.id] = it;
    const st = it.status || 'open';
    const due = dueCell(it.due_date, st);
    const notes = it.notes
        ? `<span class="orbit-notes" title="${escapeHtml(it.notes)}">${escapeHtml(truncate(it.notes, 80))}</span>`
        : '<span class="orbit-dim">—</span>';
    return `
    <tr>
        <td><a class="mono cve-link" href="/cve/${encodeURIComponent(it.cve_id)}" target="_blank" rel="noopener">${escapeHtml(it.cve_id)}</a></td>
        <td class="mono-sm">${it.assets_affected}</td>
        <td class="mono-sm">${escapeHtml(it.start_date || '—')}</td>
        <td>${due}</td>
        <td><span class="orbit-status st-${st}">${STATUS_LABEL[st] || st}</span></td>
        <td>${notes}</td>
        <td class="orbit-actions">
            <button class="btn btn-ghost btn-sm" data-edit="${it.id}">Edit</button>
            <button class="btn btn-ghost btn-sm orbit-del" data-del="${it.id}">Delete</button>
        </td>
    </tr>`;
}

function dueCell(due, status) {
    if (!due) return '<span class="orbit-dim">—</span>';
    if (status === 'resolved') return `<span class="mono-sm">${escapeHtml(due)}</span>`;
    const days = Math.ceil((new Date(due) - new Date()) / 86400000);
    let cls = 'orbit-due-ok', note = '';
    if (isNaN(days)) return `<span class="mono-sm">${escapeHtml(due)}</span>`;
    if (days < 0) { cls = 'orbit-due-over'; note = ` (${Math.abs(days)}d overdue)`; }
    else if (days <= 7) { cls = 'orbit-due-soon'; note = ` (${days}d left)`; }
    return `<span class="mono-sm ${cls}">${escapeHtml(due)}${note}</span>`;
}

function startEdit(id) {
    const it = _items[id];
    if (!it) return;
    document.getElementById('edit-id').value = it.id;
    document.getElementById('f-cve').value = it.cve_id;
    document.getElementById('f-assets').value = it.assets_affected;
    document.getElementById('f-start').value = it.start_date || '';
    document.getElementById('f-due').value = it.due_date || '';
    document.getElementById('f-status').value = it.status || 'open';
    document.getElementById('f-notes').value = it.notes || '';
    document.getElementById('track-submit').textContent = 'Save changes';
    document.getElementById('track-cancel').style.display = '';
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function removeItem(id) {
    const it = _items[id];
    if (!confirm(`Stop tracking ${it ? it.cve_id : 'this CVE'}?`)) return;
    try {
        const resp = await fetch(`/api/tracking/${id}`, { method: 'DELETE' });
        if (!resp.ok) { const d = await resp.json(); setMsg(d.error || 'Delete failed.', true); return; }
        load();
    } catch (err) {
        setMsg(err.message, true);
    }
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
