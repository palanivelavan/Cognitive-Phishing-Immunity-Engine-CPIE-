// ── CPIE Main JS ─────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {

    // ── 1. Animate score bars ──────────────────────────
    // Reads data attributes set by the template
    var stsBar = document.getElementById('sts-bar');
    var miiBar = document.getElementById('mii-bar');

    if (stsBar) {
        var stsScore = parseInt(stsBar.getAttribute('data-score') || '0', 10);
        setTimeout(function () {
            stsBar.style.width = stsScore + '%';
        }, 200);
    }

    if (miiBar) {
        var miiScore = parseInt(miiBar.getAttribute('data-score') || '0', 10);
        setTimeout(function () {
            miiBar.style.width = miiScore + '%';
        }, 200);
    }

    // ── 2. Tooltip hover for highlighted phrases ───────
    document.querySelectorAll('.cpie-highlight').forEach(function (el) {
        var tooltip = el.querySelector('.cpie-tooltip');
        if (!tooltip) return;

        el.addEventListener('mouseenter', function () {
            tooltip.style.display = 'block';
        });
        el.addEventListener('mouseleave', function () {
            tooltip.style.display = 'none';
        });
    });

    // ── 3. Cognitive delay on suspicious URLs ──────────
    document.querySelectorAll('.cpie-url-flag').forEach(function (el) {
        el.addEventListener('click', function (e) {
            e.preventDefault();
            var reason = el.getAttribute('title') || 'Suspicious link detected';
            var url = el.textContent.trim();

            var confirmed = confirm(
                'CPIE Security Warning\n\n' +
                'This link has been flagged as suspicious.\n\n' +
                'Reason: ' + reason + '\n\n' +
                'Destination: ' + url + '\n\n' +
                'Proceed anyway?'
            );

            if (confirmed) {
                window.open(url, '_blank', 'noopener,noreferrer');
            }
        });
    });

    // ── 4. Email row click (dashboard) ────────────────
    document.querySelectorAll('.email-row[data-href]').forEach(function (row) {
        row.addEventListener('click', function (e) {
            if (e.target.type === 'checkbox') return;
            window.location.href = row.getAttribute('data-href');
        });
    });

    // ── 5. Star toggle (visual only) ──────────────────
    document.querySelectorAll('.email-star').forEach(function (star) {
        star.addEventListener('click', function (e) {
            e.preventDefault();
            e.stopPropagation();
            var isStarred = star.getAttribute('data-starred') === 'true';
            star.setAttribute('data-starred', (!isStarred).toString());
            star.style.color = isStarred ? '#ccc' : '#f4b400';
        });
    });

});