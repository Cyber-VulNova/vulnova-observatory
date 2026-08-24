// ─── VulNova — Standalone CVE Detail Page ────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    const root = document.getElementById('cve-root');
    const cveId = root.dataset.cve;
    document.title = `${cveId} · VulNova`;
    loadCve(cveId, root);
});

const SOURCE_CLASS = {
    ExploitDB: 'src-exploitdb', GitHub: 'src-github', Metasploit: 'src-metasploit',
    Nuclei: 'src-nuclei', Vulhub: 'src-vulhub',
};

const TIMELINE_ICON = {
    publish: '📢', exploit: '💥', poc: '🐙', kev: '🔥', kev_due: '⏰', update: '✏️',
};

async function loadCve(cveId, root) {
    try {
        const resp = await fetch('/api/cve/' + encodeURIComponent(cveId));
        const d = await resp.json();
        if (d.error) {
            root.innerHTML = `<div class="table-error">❌ ${escapeHtml(d.error)}</div>
                <div style="margin-top:16px"><a class="btn btn-ghost" href="/">← Back to database</a></div>`;
            return;
        }
        root.innerHTML = renderPage(d);
    } catch (err) {
        root.innerHTML = `<div class="table-error">❌ ${escapeHtml(err.message)}</div>`;
    }
}

function renderPage(d) {
    const sev = (d.triage_label || 'INFO').toLowerCase();
    const cvssSev = (d.severity || 'NONE').toLowerCase();

    const kevBadge = d.in_kev ? '<span class="badge badge-kev">🔥 CISA KEV</span>' : '';
    const ransom = d.kev_details && (d.kev_details.known_ransomware_use || '').toLowerCase() === 'known'
        ? '<span class="badge badge-critical">🦠 Ransomware</span>' : '';

    const product = (d.product && d.product.label)
        ? `<div class="cve-hero-product">📦 ${escapeHtml(d.product.label)}</div>` : '';

    const tags = renderCveTags(d.cve_tags);

    return `
    <div class="cve-hero">
        <div class="cve-hero-left">
            <div class="cve-hero-id">${escapeHtml(d.cve_id)}</div>
            <div class="cve-hero-badges">
                <span class="badge badge-${sev}">${d.triage_label}</span>
                ${d.severity ? `<span class="sev-badge sev-${cvssSev}">${d.severity}</span>` : ''}
                ${kevBadge}${ransom}${tags}
            </div>
            ${product}
        </div>
        <div class="cve-hero-score">
            <div class="score-circle score-${sev}">${d.triage_score}</div>
            <div class="score-cap">Triage / 100</div>
        </div>
    </div>

    <div class="cve-metrics">
        ${metricCard('CVSS', d.cvss_score ? `${d.cvss_score}` : 'N/A', d.severity || '')}
        ${metricCard('EPSS', `${d.epss_percent}%`, 'exploitation probability')}
        ${metricCard('CISA KEV', d.in_kev ? 'Listed' : 'Not listed', d.in_kev ? 'actively exploited' : '')}
        ${metricCard('Exploits', d.exploit_count, 'public sources')}
    </div>

    <div class="cve-columns">
        <div class="cve-main">
            <section class="cve-section">
                <h2>Summary</h2>
                <p class="cve-desc">${escapeHtml(d.description)}</p>
                <div class="cve-rec">📋 ${escapeHtml(d.recommendation)}</div>
            </section>

            ${renderCvss(d)}

            ${renderVersions(d.affected_versions)}

            ${renderTimeline(d.timeline)}

            ${renderExploits(d.exploits)}

            ${renderCweSection(d.cwe_details)}

            ${renderReferences(d.references)}

            ${renderCpes(d.cpes)}
        </div>

        <aside class="cve-side">
            ${renderKevBox(d)}
            ${renderEpssTrend(d.epss_history)}
            ${renderRelated(d.related)}
            ${renderExternalLinks(d)}
        </aside>
    </div>`;
}

function metricCard(label, value, sub) {
    return `<div class="metric-card">
        <div class="metric-value">${escapeHtml(String(value))}</div>
        <div class="metric-label">${escapeHtml(label)}</div>
        ${sub ? `<div class="metric-sub">${escapeHtml(sub)}</div>` : ''}
    </div>`;
}

function renderTimeline(timeline) {
    if (!timeline || !timeline.length) return '';
    const items = timeline.map(t => `
        <li class="tl-item tl-${t.kind}">
            <div class="tl-marker">${TIMELINE_ICON[t.kind] || '•'}</div>
            <div class="tl-body">
                <div class="tl-date">${escapeHtml(t.date)}</div>
                <div class="tl-label">${escapeHtml(t.label)}</div>
            </div>
        </li>`).join('');
    return `<section class="cve-section">
        <h2>Timeline</h2>
        <ul class="timeline">${items}</ul>
    </section>`;
}

function renderExploits(exploits) {
    if (!exploits || !exploits.length) {
        return `<section class="cve-section">
            <h2>Public Exploits &amp; PoCs</h2>
            <div class="detail-none">No public exploits found across ExploitDB, GitHub, Metasploit, Nuclei, or Vulhub.</div>
        </section>`;
    }
    const items = exploits.map(e => `
        <li class="exploit-item">
            <span class="exploit-source ${SOURCE_CLASS[e.source] || ''}">${escapeHtml(e.source)}</span>
            <a href="${e.url}" target="_blank" rel="noopener" class="exploit-link">${escapeHtml(e.name)}</a>
            ${e.stars !== undefined ? `<span class="poc-stars">⭐ ${e.stars}</span>` : ''}
            ${e.date ? `<span class="exploit-date">${escapeHtml(e.date)}</span>` : ''}
            ${e.command ? `<code class="msf-cmd">${escapeHtml(e.command)}</code>` : ''}
        </li>`).join('');
    return `<section class="cve-section">
        <h2>Public Exploits &amp; PoCs <span class="count-pill">${exploits.length}</span></h2>
        <ul class="exploit-list">${items}</ul>
    </section>`;
}

function renderReferences(references) {
    if (!references || !references.length) return '';
    const catNames = { vendor: '🏢 Vendor / Patch', exploit: '💣 Exploit', advisory: '📢 Advisory', other: '🔗 Other' };
    const grouped = { vendor: [], exploit: [], advisory: [], other: [] };
    references.forEach(r => { (grouped[r.category] || grouped.other).push(r); });

    let blocks = '';
    for (const cat of ['vendor', 'exploit', 'advisory', 'other']) {
        const list = grouped[cat];
        if (!list.length) continue;
        const items = list.slice(0, 15).map(r =>
            `<li><a href="${r.url}" target="_blank" rel="noopener">${escapeHtml(truncate(r.url, 80))}</a></li>`
        ).join('');
        blocks += `<div class="ref-group"><div class="ref-group-title">${catNames[cat]} (${list.length})</div><ul class="ref-list">${items}</ul></div>`;
    }
    return `<section class="cve-section"><h2>References</h2>${blocks}</section>`;
}

function renderCpes(cpes) {
    if (!cpes || !cpes.length) return '';
    const items = cpes.map(c => `<code class="cpe">${escapeHtml(c)}</code>`).join('');
    return `<section class="cve-section"><h2>Affected Configurations (CPE)</h2><div class="cpe-wrap">${items}</div></section>`;
}

function renderKevBox(d) {
    if (!d.in_kev || !d.kev_details) return '';
    const k = d.kev_details;
    return `<div class="side-box side-box-kev">
        <div class="side-box-title">🔥 CISA KEV</div>
        <div class="side-kv"><span>Added</span><b>${escapeHtml(k.date_added || '—')}</b></div>
        <div class="side-kv"><span>Due</span><b>${escapeHtml(k.due_date || '—')}</b></div>
        <div class="side-kv"><span>Ransomware</span><b>${escapeHtml(k.known_ransomware_use || 'Unknown')}</b></div>
        ${k.required_action ? `<div class="side-action">${escapeHtml(k.required_action)}</div>` : ''}
    </div>`;
}

function renderExternalLinks(d) {
    const id = d.cve_id;
    const links = [
        { label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${id}` },
        { label: 'MITRE CVE.org', url: `https://www.cve.org/CVERecord?id=${id}` },
        { label: 'CVE Details', url: `https://www.cvedetails.com/cve/${id}/` },
        { label: 'Tenable', url: `https://www.tenable.com/cve/${id}` },
    ];
    if (d.in_kev) {
        links.push({ label: 'CISA KEV Catalog', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' });
    }
    const items = links.map(l =>
        `<a class="ext-link" href="${l.url}" target="_blank" rel="noopener">${escapeHtml(l.label)} ↗</a>`
    ).join('');
    return `<div class="side-box">
        <div class="side-box-title">External Resources</div>
        <div class="ext-links">${items}</div>
    </div>`;
}

function renderCveTags(tags) {
    if (!tags || !tags.length) return '';
    return tags.map(t => {
        const label = t.replace(/([A-Z])/g, ' $1').trim();
        const cls = /disput/i.test(t) ? 'tagbadge-disputed'
            : /unsupported|rejected/i.test(t) ? 'tagbadge-warn' : 'tagbadge-info';
        return `<span class="tagbadge ${cls}" title="NVD tag">⚑ ${escapeHtml(label)}</span>`;
    }).join('');
}

function renderCvss(d) {
    const metrics = d.cvss_breakdown || [];
    if (!metrics.length) {
        return `<section class="cve-section"><h2>CVSS</h2>
            <div class="detail-none">No CVSS score assigned yet.</div></section>`;
    }
    const blocks = metrics.map(m => {
        const sev = (m.severity || 'NONE').toLowerCase();
        const comps = (m.components || []).map(c =>
            `<div class="cvss-comp"><span class="cvss-comp-k">${escapeHtml(c.metric)}</span>
             <span class="cvss-comp-v">${escapeHtml(c.value)}</span></div>`).join('');
        return `<div class="cvss-block">
            <div class="cvss-head">
                <span class="cvss-ver">CVSS ${escapeHtml(m.version)}</span>
                <span class="cvss-src">${escapeHtml(m.source_type || '')}</span>
                <span class="cvss-score sev-text-${sev}">${m.base_score} ${escapeHtml(m.severity)}</span>
            </div>
            <div class="cvss-subscores">
                <span>Exploitability: <b>${m.exploitability_score}</b></span>
                <span>Impact: <b>${m.impact_score}</b></span>
            </div>
            <div class="cvss-comps">${comps}</div>
            ${m.vector ? `<code class="cvss-vec">${escapeHtml(m.vector)}</code>` : ''}
        </div>`;
    }).join('');
    return `<section class="cve-section"><h2>CVSS Breakdown</h2>${blocks}</section>`;
}

function renderVersions(versions) {
    if (!versions || !versions.length) return '';
    const blocks = versions.map(v => {
        const ranges = (v.ranges || []).map(r => `<span class="ver-range">${escapeHtml(r)}</span>`).join('');
        const fixed = (v.fixed || []).map(f => `<span class="ver-fixed">✓ ${escapeHtml(f)}</span>`).join('');
        const title = [v.vendor, v.product].filter(Boolean).join(' / ');
        return `<div class="ver-block">
            ${title ? `<div class="ver-title">${escapeHtml(title)}</div>` : ''}
            ${ranges ? `<div class="ver-row"><span class="ver-lbl">Affected</span><div>${ranges}</div></div>` : ''}
            ${fixed ? `<div class="ver-row"><span class="ver-lbl">Fixed in</span><div>${fixed}</div></div>` : ''}
        </div>`;
    }).join('');
    return `<section class="cve-section"><h2>Affected &amp; Fixed Versions</h2>${blocks}</section>`;
}

function renderCweSection(cwes) {
    if (!cwes || !cwes.length) return '';
    const items = cwes.map(c => {
        const title = c.name ? `${c.id}: ${c.name}` : c.id;
        const capec = (c.capec || []).map(p => `<span class="capec-chip">${escapeHtml(p)}</span>`).join('');
        return `<div class="cwe-block">
            <div class="cwe-head"><a href="${c.url}" target="_blank" rel="noopener">${escapeHtml(title)}</a></div>
            ${c.desc ? `<div class="cwe-desc">${escapeHtml(c.desc)}</div>` : ''}
            ${capec ? `<div class="cwe-capec"><span class="capec-lbl">Attack patterns:</span> ${capec}</div>` : ''}
        </div>`;
    }).join('');
    return `<section class="cve-section"><h2>Weaknesses &amp; Attack Patterns</h2>${items}</section>`;
}

function renderEpssTrend(history) {
    if (!history || history.length < 2) return '';
    const vals = history.map(h => h.epss);
    const max = Math.max(...vals), min = Math.min(...vals);
    const first = history[0].epss, last = history[history.length - 1].epss;
    const trend = last > first ? '📈 rising' : last < first ? '📉 falling' : '➡ flat';
    const w = 240, h = 48, n = history.length;
    const range = (max - min) || 1;
    const pts = history.map((p, i) => {
        const x = (i / (n - 1)) * w;
        const y = h - ((p.epss - min) / range) * (h - 6) - 3;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
    return `<div class="side-box">
        <div class="side-box-title">EPSS Trend (${history.length}d) · ${trend}</div>
        <svg class="epss-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
            <polyline fill="none" stroke="var(--accent)" stroke-width="2" points="${pts}"/>
        </svg>
        <div class="epss-range">
            <span>${(min * 100).toFixed(1)}%</span>
            <span>now: ${(last * 100).toFixed(1)}%</span>
            <span>${(max * 100).toFixed(1)}%</span>
        </div>
    </div>`;
}

function renderRelated(related) {
    if (!related || !related.length) return '';
    const items = related.map(r => {
        const sev = (r.severity || 'NONE').toLowerCase();
        return `<a class="related-item" href="/cve/${r.cve_id}" target="_blank" rel="noopener">
            <span class="related-id">${escapeHtml(r.cve_id)}</span>
            <span class="related-meta"><span class="sev-text-${sev}">${r.cvss_score || '—'}</span> · ${escapeHtml(r.published || '')}</span>
        </a>`;
    }).join('');
    return `<div class="side-box">
        <div class="side-box-title">Related CVEs (same product)</div>
        <div class="related-list">${items}</div>
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
