document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const container = document.getElementById('cve-table-body');
    const searchInput = document.getElementById('search-input');
    const filterBtns = document.querySelectorAll('.filter-btn');
    const loadMoreBtn = document.getElementById('load-more-btn');
    const loadMoreContainer = document.getElementById('load-more-container');
    const clearBtn = document.getElementById('clear-search-btn');
    const clockElement = document.getElementById('realtime-clock');
    const lastUpdatedEl = document.getElementById('last-updated-text');

    // State
    let cveData = [];
    let searchQuery = '';
    let currentFilter = 'all';
    let currentPage = 1;
    const itemsPerPage = 20;

    // Utility: XSS Prevention
    function escapeHTML(str) {
        if (!str) return '';
        return str.replace(/[&<>'"]/g, tag => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
        }[tag]));
    }

    // Real-time Clock — updates every second with AM/PM format
    function updateClock() {
        if (clockElement) {
            const now = new Date();
            const dateStr = now.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
            const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
            clockElement.textContent = `${dateStr} ${timeStr}`;
        }
    }
    updateClock();
    setInterval(updateClock, 1000);

    // Fetch Data
    async function fetchCVEData() {
        try {
            const cacheBuster = new Date().getTime();
            const response = await fetch(`cves.json?t=${cacheBuster}`);
            if (!response.ok) throw new Error('Data fetch failed');
            
            const data = await response.json();
            cveData = data.cves || [];

            if (lastUpdatedEl && data.last_updated) {
                const dateObj = new Date(data.last_updated);
                lastUpdatedEl.textContent = `Last Sync: ${dateObj.toLocaleString('en-US', { hour12: true })}`;
            }

            // Update stats once after data load — not on every search/filter
            updateDashboardStats();
            renderCVEs();
        } catch (error) {
            console.error('Midnight Intelligence Error:', error);
            if (container) {
                container.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:3rem; color:#f87171;">
                    <i class="ph ph-warning-circle" style="font-size: 2rem;"></i><br>
                    Data Synchronizer Offline. Please run 'python fetch_cves.py' and refresh.
                </td></tr>`;
            }
        }
    }

    // Update dashboard stat cards — called once after data load, not on every search
    function updateDashboardStats() {
        const statTotal    = document.getElementById('stat-total');
        const statCritical = document.getElementById('stat-critical');
        const statHigh     = document.getElementById('stat-high');
        const statExploited = document.getElementById('stat-exploited');
        const statActive   = document.getElementById('stat-active');

        if (statTotal) statTotal.textContent = cveData.length.toLocaleString();

        let critCount = 0, highCount = 0, kevCount = 0, edbCount = 0;
        cveData.forEach(c => {
            const mts = c.mts_score || 0;
            // MTS-based thresholds — matches header labels
            if (mts >= 80) critCount++;
            else if (mts >= 60) highCount++;
            // CISA KEV: entries explicitly marked exploited (but not Exploit-DB)
            if (c.is_exploited && c.source !== 'Exploit-DB') kevCount++;
            // Active Exploits: Exploit-DB entries only
            if (c.source === 'Exploit-DB') edbCount++;
        });

        if (statCritical) statCritical.textContent = critCount.toLocaleString();
        if (statHigh)     statHigh.textContent     = highCount.toLocaleString();
        if (statExploited) statExploited.textContent = kevCount.toLocaleString();
        if (statActive)   statActive.textContent   = edbCount.toLocaleString();
    }

    // Render Logic
    function renderCVEs(append = false) {
        if (!container) return;
        // Clear container only once on fresh render
        if (!append) {
            container.innerHTML = '';
            currentPage = 1;
        }

        const query = searchQuery.toLowerCase();
        const filteredData = cveData.filter(cve => {
            // Severity filter: support both MTS-label-based and legacy severity field
            let matchSeverity = true;
            if (currentFilter === 'CRITICAL') {
                matchSeverity = (cve.mts_score || 0) >= 80;
            } else if (currentFilter === 'HIGH') {
                const mts = cve.mts_score || 0;
                matchSeverity = mts >= 60 && mts < 80;
            } else if (currentFilter === 'MEDIUM') {
                const mts = cve.mts_score || 0;
                matchSeverity = mts >= 30 && mts < 60;
            }
            // 'all' falls through to matchSeverity = true
            
            let matchSearch = true;
            if (query) {
                if (query.includes(':')) {
                    const [key, ...rest] = query.split(':');
                    const val = rest.join(':').trim();
                    if (key === 'vendor') {
                        matchSearch = (cve.vendor || '').toLowerCase().includes(val);
                    } else if (key === 'score') {
                        // Parse operator first (>= and <= before > and <)
                        let op, num;
                        if (val.startsWith('>='))      { op = '>='; num = parseFloat(val.slice(2)); }
                        else if (val.startsWith('<=')) { op = '<='; num = parseFloat(val.slice(2)); }
                        else if (val.startsWith('>'))  { op = '>';  num = parseFloat(val.slice(1)); }
                        else if (val.startsWith('<'))  { op = '<';  num = parseFloat(val.slice(1)); }
                        else                           { op = '=='; num = parseFloat(val); }
                        const s = cve.score || 0;
                        if      (op === '>')  matchSearch = s > num;
                        else if (op === '>=') matchSearch = s >= num;
                        else if (op === '<')  matchSearch = s < num;
                        else if (op === '<=') matchSearch = s <= num;
                        else                  matchSearch = s === num;
                    } else if (key === 'mts') {
                        // Support mts:>=80 style filtering too
                        let op, num;
                        if (val.startsWith('>='))      { op = '>='; num = parseFloat(val.slice(2)); }
                        else if (val.startsWith('<=')) { op = '<='; num = parseFloat(val.slice(2)); }
                        else if (val.startsWith('>'))  { op = '>';  num = parseFloat(val.slice(1)); }
                        else if (val.startsWith('<'))  { op = '<';  num = parseFloat(val.slice(1)); }
                        else                           { op = '=='; num = parseFloat(val); }
                        const m = cve.mts_score || 0;
                        if      (op === '>')  matchSearch = m > num;
                        else if (op === '>=') matchSearch = m >= num;
                        else if (op === '<')  matchSearch = m < num;
                        else if (op === '<=') matchSearch = m <= num;
                        else                  matchSearch = m === num;
                    } else if (key === 'id') {
                        matchSearch = cve.id.toLowerCase().includes(val);
                    } else if (key === 'source') {
                        matchSearch = (cve.source || '').toLowerCase().includes(val);
                    }
                } else {
                    matchSearch = cve.id.toLowerCase().includes(query) || 
                                  (cve.description || '').toLowerCase().includes(query) || 
                                  (cve.vendor || '').toLowerCase().includes(query);
                }
            }
            return matchSeverity && matchSearch;
        });

        const startIdx = append ? (currentPage - 1) * itemsPerPage : 0;
        const newItems = filteredData.slice(startIdx, currentPage * itemsPerPage);
        
        if (!append && filteredData.length === 0) {
            container.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:3rem; color:#64748b;">No intelligence records found matching your query.</td></tr>`;
            if (loadMoreContainer) loadMoreContainer.style.display = 'none';
            return;
        }

        newItems.forEach(cve => {
            const tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid rgba(255,255,255,0.05)';
            tr.style.transition = 'background 0.2s, border-left-color 0.2s';
            tr.style.cursor = 'pointer';
            tr.title = 'Click to open on source site';
            tr.addEventListener('mouseenter', () => tr.style.background = 'rgba(255,255,255,0.025)');
            tr.addEventListener('mouseleave', () => tr.style.background = 'transparent');
            tr.addEventListener('click', () => { if (cve.source_url) window.open(cve.source_url, '_blank'); });

            const score = cve.score || 0;
            const mtsScore = cve.mts_score || score;

            // MTS badge colors — red 80+, orange 60+, yellow 40+
            let mtsBg = 'rgba(148,163,184,0.1)', mtsColor = '#94a3b8', mtsBorder = 'rgba(148,163,184,0.3)';
            if (mtsScore >= 80) { mtsBg = 'rgba(239,68,68,0.12)'; mtsColor = '#f87171'; mtsBorder = 'rgba(239,68,68,0.5)'; }
            else if (mtsScore >= 60) { mtsBg = 'rgba(249,115,22,0.12)'; mtsColor = '#fb923c'; mtsBorder = 'rgba(249,115,22,0.5)'; }
            else if (mtsScore >= 40) { mtsBg = 'rgba(234,179,8,0.1)'; mtsColor = '#fbbf24'; mtsBorder = 'rgba(234,179,8,0.3)'; }

            // Left border severity indicator
            tr.style.borderLeft = `3px solid ${mtsBorder}`;

            // CVSS color
            let cvssColor = '#94a3b8';
            if (score >= 9.0) cvssColor = '#f87171';
            else if (score >= 7.0) cvssColor = '#fb923c';
            else if (score >= 4.0) cvssColor = '#fbbf24';

            // EPSS color
            const epssVal = cve.epss || 0;
            let epssColor = '#64748b';
            if (epssVal > 0.1) epssColor = '#f87171';
            else if (epssVal > 0.01) epssColor = '#fb923c';
            else if (epssVal > 0) epssColor = '#fbbf24';

            // Source badge color
            let sourceColor = '#64748b';
            if (cve.source === 'GitHub')      sourceColor = '#4ade80';
            else if (cve.source === 'NVD')        sourceColor = '#38bdf8';
            else if (cve.source === 'Exploit-DB') sourceColor = '#f472b6';
            else if (cve.source === 'ZDI')        sourceColor = '#fb923c';
            else if (cve.source === 'GoogleP0')   sourceColor = '#f87171';
            else if (cve.source === 'CERT-CC')    sourceColor = '#c4b5fd';
            else if (cve.source === 'TR-CERT')    sourceColor = '#2dd4bf';
            else if (cve.source === 'USOM')       sourceColor = '#2dd4bf'; // legacy entries

            // NEW badge: published within last 3 days
            const pubDate = cve.published ? new Date(cve.published) : null;
            const isNew = pubDate && (Date.now() - pubDate.getTime()) < 3 * 24 * 60 * 60 * 1000;

            // Show N/A for MTS if score is effectively zero (no data available)
            const mtsDisplay = mtsScore > 1 ? Math.round(mtsScore) : '—';

            tr.innerHTML = `
                <td style="padding: 0.75rem 1rem;">
                    <div style="background:${mtsBg}; color:${mtsColor}; border:1px solid ${mtsBorder}; border-radius:6px; width:36px; height:36px; display:flex; align-items:center; justify-content:center; font-weight:800; font-size:0.78rem;" title="MTS: ${mtsScore}">
                        ${mtsDisplay}
                    </div>
                </td>
                <td style="padding: 0.75rem 1rem; font-weight:bold;">
                    <a href="${escapeHTML(cve.source_url)}" target="_blank" onclick="event.stopPropagation()" style="color:#38bdf8; text-decoration:none; border-bottom:1px dashed rgba(56,189,248,0.4);">${escapeHTML(cve.id)}</a>
                </td>
                <td style="padding: 0.75rem 1rem;">
                    <div style="display:flex; align-items:center; gap:6px; margin-bottom:4px; flex-wrap:wrap;">
                        <span style="font-size:0.6rem; font-weight:800; background:rgba(255,255,255,0.05); color:${sourceColor}; padding:1px 6px; border:1px solid ${sourceColor}44; border-radius:3px; text-transform:uppercase;">${cve.source || 'Intel'}</span>
                        ${cve.is_exploited ? '<span style="font-size:0.6rem; font-weight:800; background:rgba(239,68,68,0.1); color:#f87171; padding:1px 6px; border:1px solid #f8717144; border-radius:3px; text-transform:uppercase;">&#9888; Exploited</span>' : ''}
                        ${isNew ? '<span style="font-size:0.6rem; font-weight:800; background:rgba(34,197,94,0.15); color:#4ade80; padding:1px 6px; border:1px solid rgba(34,197,94,0.4); border-radius:3px; text-transform:uppercase; animation:pulse 2s infinite;">NEW</span>' : ''}
                    </div>
                    <div style="color:#cbd5e1; font-size:0.82rem; line-height:1.55;">${escapeHTML(cve.description || '').substring(0, 260)}${(cve.description || '').length > 260 ? '...' : ''}</div>
                </td>
                <td style="padding:0.75rem 1rem; text-align:center; font-weight:700; color:${cvssColor};">${score.toFixed(1)}</td>
                <td style="padding:0.75rem 1rem; text-align:center; font-weight:600; color:${epssColor};">${epssVal > 0 ? (epssVal * 100).toFixed(2) + '%' : '<span style="color:#475569;">—</span>'}</td>
                <td style="padding:0.75rem 1rem; color:#94a3b8; font-size:0.75rem;">${escapeHTML(cve.vendor || 'OTHER')}</td>
                <td style="padding:0.75rem 1rem; color:#64748b; font-size:0.75rem;">${(cve.published || '').split('T')[0]}</td>
            `;

            container.appendChild(tr);
        });

        if (loadMoreContainer) {
            loadMoreContainer.style.display = filteredData.length > currentPage * itemsPerPage ? 'block' : 'none';
        }
    }

    // Utility: Debounce
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // Tab Switching
    const navButtons = document.querySelectorAll('.nav-btn[data-tab]');
    const dashboardSection = document.getElementById('dashboard-section');
    const sourcesSection = document.getElementById('sources-section');
    const aboutSection = document.getElementById('about-section');

    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.getAttribute('data-tab');
            navButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            if (dashboardSection) dashboardSection.style.display = tab === 'dashboard' ? 'block' : 'none';
            if (sourcesSection)  sourcesSection.style.display  = tab === 'sources'   ? 'block' : 'none';
            if (aboutSection)    aboutSection.style.display    = tab === 'about'     ? 'block' : 'none';
        });
    });

    // Event Listeners
    if (searchInput) {
        const handleSearch = debounce((e) => {
            searchQuery = e.target.value;
            currentPage = 1;
            renderCVEs();
        }, 300);
        searchInput.addEventListener('input', handleSearch);
    }

    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilter = btn.dataset.severity;
            currentPage = 1;
            renderCVEs();
        });
    });

    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            if (searchInput) searchInput.value = '';
            searchQuery = '';
            currentFilter = 'all';
            currentPage = 1;
            filterBtns.forEach(b => b.classList.remove('active'));
            const allBtn = document.querySelector('[data-severity="all"]');
            if (allBtn) allBtn.classList.add('active');
            renderCVEs();
        });
    }

    if (loadMoreBtn) {
        loadMoreBtn.addEventListener('click', () => {
            currentPage++;
            renderCVEs(true);
        });
    }

    // Initialize
    fetchCVEData();
});
