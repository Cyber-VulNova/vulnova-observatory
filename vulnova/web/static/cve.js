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
    const cvssSev = (d.severity || 'NONE').toLowerCase();
    const heroSev = ['critical', 'high', 'medium', 'low'].includes(cvssSev) ? cvssSev : 'info';

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
                ${d.severity ? `<span class="sev-badge sev-${cvssSev}">${d.severity}</span>` : ''}
                ${kevBadge}${ransom}${tags}
            </div>
            ${product}
            <a class="btn btn-primary btn-track" href="/orbit?cve=${encodeURIComponent(d.cve_id)}" title="Add this CVE to your tracker">＋ Track this CVE</a>
        </div>
        <div class="cve-hero-score">
            <div class="score-circle score-${heroSev}">${d.epss_percent}%</div>
            <div class="score-cap">EPSS</div>
        </div>
    </div>

    <div class="cve-metrics">
        ${metricCard('CVSS', d.cvss_score ? `${d.cvss_score}` : 'N/A', d.cvss_from_cvefeed ? ((d.severity || '') + ' · via CVEfeed').trim() : (d.severity || ''))}
        ${metricCard('EPSS', `${d.epss_percent}%`, 'exploitation probability (next 30 days)')}
        ${metricCard('CISA KEV', d.in_kev ? 'Listed' : 'Not listed', d.in_kev ? 'actively exploited' : '')}
        ${metricCard('Exploits', d.exploit_count, 'public sources')}
    </div>

    <div class="cve-grid">
        <aside class="cve-rail cve-rail-left">
            ${renderRadar(d)}
            ${renderKevBox(d)}
            ${renderRansomware(d)}
            ${renderQuickFacts(d)}
        </aside>

        <div class="cve-main">
            <section class="cve-section">
                <h2>Summary</h2>
                <p class="cve-desc">${escapeHtml(d.description)}</p>
            </section>

            ${renderCvefeed(d.cvefeed)}

            ${renderExploits(d.exploits)}

            ${renderCvss(d)}

            ${renderVersions(d.affected_versions)}

            ${renderCweSection(d.cwe_details)}

            ${renderReferences(d.references)}

            ${renderCpes(d.cpes)}
        </div>

        <aside class="cve-rail cve-rail-right">
            ${renderEpssTrend(d.epss_history)}
            ${renderTimeline(d.timeline)}
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

function clamp01(x) { return Math.max(0, Math.min(1, x || 0)); }

function renderRadar(d) {
    const bd = (d.cvss_breakdown && d.cvss_breakdown[0]) || {};
    const ransom = d.kev_details && (d.kev_details.known_ransomware_use || '').toLowerCase() === 'known';
    const threat = d.in_kev ? (ransom ? 1 : 0.7)
        : ((d.epss_percent || 0) >= 50 ? 0.45 : (d.epss_percent || 0) >= 10 ? 0.25 : 0.1);
    const axes = [
        { label: 'Severity', v: clamp01((d.cvss_score || 0) / 10) },
        { label: 'Exploitability', v: clamp01((bd.exploitability_score || 0) / 3.9) },
        { label: 'Impact', v: clamp01((bd.impact_score || 0) / 6.0) },
        { label: 'EPSS', v: clamp01((d.epss_percent || 0) / 100) },
        { label: 'Exploits', v: clamp01((d.exploit_count || 0) / 3) },
        { label: 'Threat', v: clamp01(threat) },
    ];
    const size = 260, cx = size / 2, cy = size / 2, R = 78, n = axes.length;
    const ang = i => (-90 + i * 360 / n) * Math.PI / 180;
    const pt = (i, r) => [cx + r * Math.cos(ang(i)), cy + r * Math.sin(ang(i))];

    let rings = '';
    [0.25, 0.5, 0.75, 1].forEach(f => {
        const p = axes.map((_, i) => pt(i, R * f).map(x => x.toFixed(1)).join(',')).join(' ');
        rings += `<polygon points="${p}" class="radar-ring"/>`;
    });
    let spokes = '', labels = '';
    axes.forEach((a, i) => {
        const [x, y] = pt(i, R);
        spokes += `<line x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}" class="radar-spoke"/>`;
        const [lx, ly] = pt(i, R + 14);
        const anchor = Math.abs(lx - cx) < 10 ? 'middle' : (lx > cx ? 'start' : 'end');
        labels += `<text x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" text-anchor="${anchor}" class="radar-label">${a.label}</text>`;
        labels += `<text x="${lx.toFixed(1)}" y="${(ly + 11).toFixed(1)}" text-anchor="${anchor}" class="radar-val">${Math.round(a.v * 100)}</text>`;
    });
    const poly = axes.map((a, i) => pt(i, R * a.v).map(x => x.toFixed(1)).join(',')).join(' ');

    return `<div class="side-box cve-radar">
        <div class="side-box-title">Threat Radar</div>
        <svg viewBox="0 0 ${size} ${size}" class="radar-svg" role="img" aria-label="CVE threat radar">
            ${rings}${spokes}
            <polygon points="${poly}" class="radar-area"/>
            ${labels}
        </svg>
    </div>`;
}

function renderRansomware(d) {
    const known = d.kev_details && (d.kev_details.known_ransomware_use || '').toLowerCase() === 'known';
    const groups = Array.isArray(d.ransomware_groups) ? d.ransomware_groups : [];

    // Named-group attribution from Ransomware.live (groups observed exploiting
    // this CVE). Shown as chips linking to each group's profile.
    let groupsHtml = '';
    if (groups.length) {
        const chips = groups.map(g => {
            const ctx = [g.vendor, g.product].filter(Boolean).join(' ');
            const title = ctx ? ` title="Exploits ${escapeHtml(ctx)}"` : '';
            const url = g.url || '#';
            return `<a class="ransom-group" href="${escapeHtml(url)}" target="_blank" rel="noopener"${title}>${escapeHtml(g.name)}</a>`;
        }).join('');
        groupsHtml = `<div class="ransom-groups-label">Groups linked to this CVE</div>
            <div class="ransom-groups">${chips}</div>
            <div class="side-source">Attribution · Ransomware.live</div>`;
    }

    if (known || groups.length) {
        const kevLine = known
            ? `<div class="ransom-hit">Known ransomware campaign use</div>
               <div class="side-action">Associated with ransomware operations (per CISA KEV).</div>`
            : '';
        return `<div class="side-box side-box-ransom">
            <div class="side-box-title">🦠 Ransomware</div>
            ${kevLine}
            ${groupsHtml}
        </div>`;
    }
    if (d.in_kev) {
        return `<div class="side-box">
            <div class="side-box-title">🦠 Ransomware</div>
            <div class="ransom-none">No known ransomware campaign use</div>
        </div>`;
    }
    return '';
}

function renderQuickFacts(d) {
    const rows = [
        ['Published', (d.published || '').slice(0, 10) || '—'],
        ['Last modified', (d.last_modified || '').slice(0, 10) || '—'],
        ['CVSS', d.cvss_score ? `${d.cvss_score} ${d.severity || ''}`.trim() : 'N/A'],
        ['CVSS version', d.cvss_version || '—'],
        ['EPSS', `${d.epss_percent}%`],
    ];
    const kv = rows.map(([k, v]) =>
        `<div class="side-kv"><span>${k}</span><b>${escapeHtml(String(v))}</b></div>`).join('');
    const vec = d.vector
        ? `<div class="cve-vector"><span>CVSS Vector</span><code>${escapeHtml(d.vector)}</code></div>` : '';
    return `<div class="side-box"><div class="side-box-title">Quick Facts</div>${kv}${vec}</div>`;
}

function renderCvefeed(cf) {
    if (!cf) return '';
    const sol = cf.solution || {};
    const hasSol = sol.overview || (sol.actions && sol.actions.length);
    const ssvc = cf.ssvc || {};
    const hasSsvc = Object.keys(ssvc).length > 0;
    if (!hasSol && !hasSsvc && !cf.is_remote) return '';

    let solBlock = '';
    if (hasSol) {
        const actions = (sol.actions || []).map(a => `<li>${escapeHtml(a)}</li>`).join('');
        solBlock = `
            ${sol.overview ? `<p class="cf-overview">${escapeHtml(sol.overview)}</p>` : ''}
            ${actions ? `<ul class="cf-actions">${actions}</ul>` : ''}`;
    }

    let ssvcBlock = '';
    if (hasSsvc) {
        const chips = Object.entries(ssvc).map(([k, v]) =>
            `<span class="cf-ssvc"><b>${escapeHtml(labelize(k))}:</b> ${escapeHtml(String(v))}</span>`).join('');
        ssvcBlock = `<div class="cf-ssvc-title">SSVC decision points</div><div class="cf-ssvc-row">${chips}</div>`;
    }

    const remote = cf.is_remote
        ? '<div class="cf-remote" title="Remotely exploitable per CVEfeed.io">🌐 Remotely exploitable</div>' : '';
    const link = cf.cvefeed_url
        ? `<a class="cf-link" href="${cf.cvefeed_url}" target="_blank" rel="noopener">View on CVEfeed.io ↗</a>` : '';

    return `<section class="cve-section cve-cvefeed">
        <h2>Remediation &amp; Decision Intel <span class="cf-src">via CVEfeed.io</span></h2>
        ${remote}
        ${solBlock}
        ${ssvcBlock}
        ${link}
    </section>`;
}

function labelize(k) {
    return k.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase());
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
