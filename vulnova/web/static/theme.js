// ─── VulNova theme (light/dark) ──────────────────────────────────────────────
// Loaded in <head> so the saved theme is applied before the body paints
// (avoids a flash). The toggle button (#theme-toggle) is wired on load.
(function () {
    var KEY = 'vn-theme';

    function current() {
        return document.documentElement.getAttribute('data-theme') || 'dark';
    }
    function apply(theme) {
        document.documentElement.setAttribute('data-theme', theme);
    }
    function icon(theme) {
        // Show the action the button performs: sun when in dark, moon when in light.
        return theme === 'light' ? '🌙' : '☀️';
    }

    // Apply the saved theme immediately.
    var saved = null;
    try { saved = localStorage.getItem(KEY); } catch (e) {}
    apply(saved === 'light' ? 'light' : 'dark');

    function toggle() {
        var next = current() === 'light' ? 'dark' : 'light';
        apply(next);
        try { localStorage.setItem(KEY, next); } catch (e) {}
        var btn = document.getElementById('theme-toggle');
        if (btn) btn.textContent = icon(next);
    }

    document.addEventListener('DOMContentLoaded', function () {
        var btn = document.getElementById('theme-toggle');
        if (btn) {
            btn.textContent = icon(current());
            btn.addEventListener('click', toggle);
        }
    });
})();
