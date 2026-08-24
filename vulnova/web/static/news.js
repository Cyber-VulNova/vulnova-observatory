// ─── VulNova Pulse — Cyber News Feed ─────────────────────────────────────────

const news = {
    all: [],            // all fetched articles
    category: 'all',    // active category chip
    search: '',         // headline search text
    enabledSources: new Set(),
    activeTag: null,    // {type, label} currently filtering by
};

document.addEventListener('DOMContentLoaded', () => {
    // Collect enabled sources from checkboxes
    document.querySelectorAll('.source-cb').forEach(cb => {
        news.enabledSources.add(cb.value);
        cb.addEventListener('change', onSourceToggle);
    });

    // Toggle-all
    document.getElementById('toggle-all').addEventListener('click', toggleAllSources);

    // Category chips
    document.querySelectorAll('#category-chips .chip').forEach(chip => {
        chip.addEventListener('click', () => {
            document.querySelectorAll('#category-chips .chip').forEach(c => c.classList.remove('chip-active'));
            chip.classList.add('chip-active');
            news.category = chip.dataset.cat;
            render();
        });
    });

    // Search
    document.getElementById('news-search').addEventListener('input', (e) => {
        news.search = e.target.value.trim().toLowerCase();
        render();
    });

    // Refresh
    document.getElementById('refresh-btn').addEventListener('click', () => loadNews(true));

    loadNews(false);
});

function onSourceToggle(e) {
    if (e.target.checked) news.enabledSources.add(e.target.value);
    else news.enabledSources.delete(e.target.value);
    render();
}

function toggleAllSources() {
    const boxes = document.querySelectorAll('.source-cb');
    const allOn = [...boxes].every(cb => cb.checked);
    boxes.forEach(cb => {
        cb.checked = !allOn;
        if (cb.checked) news.enabledSources.add(cb.value);
        else news.enabledSources.delete(cb.value);
    });
    render();
}

async function loadNews(force) {
    const feed = document.getElementById('news-feed');
    feed.innerHTML = `<div class="table-loading"><div class="spinner"></div>
        <div>${force ? 'Refreshing feeds…' : 'Gathering intelligence from 14 sources…'}</div></div>`;

    const params = new URLSearchParams({ limit: 300, per_source: 30 });
    if (force) params.set('refresh', '1');

    try {
        const resp = await fetch('/api/news?' + params.toString());
        const data = await resp.json();
        if (data.error) {
            feed.innerHTML = `<div class="table-error">❌ ${escapeHtml(data.error)}</div>`;
            return;
        }
        news.all = data.articles || [];
        render();
    } catch (err) {
        feed.innerHTML = `<div class="table-error">❌ Network error: ${escapeHtml(err.message)}</div>`;
    }
}

function render() {
    const feed = document.getElementById('news-feed');

    let items = news.all.filter(a => news.enabledSources.has(a.source_handle));
    if (news.category !== 'all') {
        items = items.filter(a => a.category === news.category);
    }
    if (news.search) {
        items = items.filter(a =>
            a.title.toLowerCase().includes(news.search) ||
            (a.summary || '').toLowerCase().includes(news.search)
        );
    }
    if (news.activeTag) {
        items = items.filter(a =>
            (a.tags || []).some(t =>
                t.type === news.activeTag.type && t.label === news.activeTag.label)
        );
    }

    // Stats
    document.getElementById('stat-articles').textContent =
        news.all.length.toLocaleString() + ' articles';
    document.getElementById('pulse-meta').textContent =
        `${items.length} shown · ${news.enabledSources.size} sources active`;

    // Active tag filter banner
    renderActiveTagBanner();

    if (items.length === 0) {
        feed.innerHTML = `<div class="table-empty">No articles match the current filters.</div>`;
        return;
    }

    feed.innerHTML = items.map(renderArticle).join('');

    // Wire tag chip clicks
    feed.querySelectorAll('.tag').forEach(chip => {
        chip.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            setTagFilter(chip.dataset.type, chip.dataset.label);
        });
    });
}

function renderActiveTagBanner() {
    const meta = document.getElementById('pulse-meta');
    const existing = document.getElementById('tag-filter-banner');
    if (existing) existing.remove();
    if (!news.activeTag) return;

    const banner = document.createElement('div');
    banner.id = 'tag-filter-banner';
    banner.className = 'tag-filter-banner';
    banner.innerHTML = `Filtering by
        <span class="tag tag-${news.activeTag.type}">${tagIcon(news.activeTag.type)} ${escapeHtml(news.activeTag.label)}</span>
        <button class="clear-tag" title="Clear tag filter">✕ clear</button>`;
    meta.parentElement.insertBefore(banner, meta.nextSibling);
    banner.querySelector('.clear-tag').addEventListener('click', () => setTagFilter(null, null));
}

function setTagFilter(type, label) {
    if (!type || (news.activeTag && news.activeTag.type === type && news.activeTag.label === label)) {
        news.activeTag = null;  // toggle off
    } else {
        news.activeTag = { type, label };
    }
    render();
}

function renderArticle(a) {
    const tags = (a.tags || []).map(t =>
        `<span class="tag tag-${t.type}" data-type="${escapeHtml(t.type)}" data-label="${escapeHtml(t.label)}" title="Filter by ${escapeHtml(t.label)}">${tagIcon(t.type)} ${escapeHtml(t.label)}</span>`
    ).join('');

    return `
    <div class="news-card" style="--accent: ${a.accent}">
        <div class="news-card-bar"></div>
        <div class="news-card-body">
            <div class="news-card-head">
                <span class="news-source" style="color: ${a.accent}">${escapeHtml(a.source_name)}</span>
                <span class="news-cat cat-${a.category.toLowerCase()}">${a.category}</span>
                <span class="news-time">${timeAgo(a.published_ts)}</span>
            </div>
            <a class="news-title" href="${a.link}" target="_blank" rel="noopener">${escapeHtml(a.title)}</a>
            ${a.summary ? `<div class="news-summary">${escapeHtml(a.summary)}</div>` : ''}
            ${tags ? `<div class="news-tags">${tags}</div>` : ''}
        </div>
        <a class="news-arrow" href="${a.link}" target="_blank" rel="noopener">↗</a>
    </div>`;
}

function tagIcon(type) {
    switch (type) {
        case 'cve': return '🐛';
        case 'agency': return '🏛️';
        case 'product': return '📦';
        case 'country': return '🌐';
        case 'keyword': return '🏷️';
        default: return '';
    }
}

// ─── Utilities ───────────────────────────────────────────────────────────────

function timeAgo(ts) {
    if (!ts) return '';
    const now = Date.now() / 1000;
    const diff = Math.max(0, now - ts);
    const mins = Math.floor(diff / 60);
    if (mins < 1) return 'just now';
    if (mins < 60) return mins + 'm ago';
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + 'h ago';
    const days = Math.floor(hrs / 24);
    if (days < 7) return days + 'd ago';
    const weeks = Math.floor(days / 7);
    if (weeks < 5) return weeks + 'w ago';
    const months = Math.floor(days / 30);
    return months + 'mo ago';
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
