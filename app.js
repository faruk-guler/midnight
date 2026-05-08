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
    let statsData = null;
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

    // Real-time Clock
    function updateClock() {
        if (clockElement) {
            const now = new Date();
            clockElement.textContent = now.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
        }
    }
    updateClock();

    // Fetch Data
    async function fetchCVEData() {
        try {
            const cacheBuster = new Date().getTime();
            const response = await fetch(`cves.json?t=${cacheBuster}`);
            if (!response.ok) throw new Error('Data fetch failed');
            
            const data = await response.json();
            cveData = data.cves || [];
            statsData = data.stats || null;

            if (lastUpdatedEl && data.last_updated) {
                const dateObj = new Date(data.last_updated);
                lastUpdatedEl.textContent = `Last Sync: ${dateObj.toLocaleString('en-US')}`;
            }

            renderCVEs();
        } catch (error) {
            console.error('Midnight Intelligence Error:', error);
            if (container) {
                container.innerHTML = `<tr><td colspan="9" style="text-align:center; padding:3rem; color:#f87171;">
                    <i class="ph ph-warning-circle" style="font-size: 2rem;"></i><br>
                    Data Synchronizer Offline. Please run 'python fetch_cves.py' and refresh.
                </td></tr>`;
            }
        }
    }

    // Render Logic
    function renderCVEs(append = false) {
        if (!container) return;
        if (!append) {
            container.innerHTML = '';
            currentPage = 1;
        }

        const query = searchQuery.toLowerCase();
        const filteredData = cveData.filter(cve => {
            const matchSeverity = currentFilter === 'all' || cve.severity === currentFilter;
            
            let matchSearch = true;
            if (query) {
                if (query.includes(':')) {
                    const [key, val] = query.split(':').map(s => s.trim());
                    if (key === 'vendor') matchSearch = (cve.vendor || '').toLowerCase().includes(val);
                    else if (key === 'score') {
                        const op = val.match(/[><=]+/)?.[0] || '==';
                        const num = parseFloat(val.replace(/[><=]+/, ''));
                        const s = cve.score || 0;
                        if (op === '>') matchSearch = s > num;
                        else if (op === '>=') matchSearch = s >= num;
                        else if (op === '<') matchSearch = s < num;
                        else if (op === '<=') matchSearch = s <= num;
                        else matchSearch = s === num;
                    }
                    else if (key === 'id') matchSearch = cve.id.toLowerCase().includes(val);
                } else {
                    matchSearch = cve.id.toLowerCase().includes(query) || 
                                  (cve.description || '').toLowerCase().includes(query) || 
                                  (cve.vendor || '').toLowerCase().includes(query);
                }
            }
            return matchSeverity && matchSearch;
        });

        // Update Dashboard Stats
        const statTotal = document.getElementById('stat-total');
        const statCritical = document.getElementById('stat-critical');
        const statHigh = document.getElementById('stat-high');
        const statExploited = document.getElementById('stat-exploited');
        const statActive = document.getElementById('stat-active');

        if (statTotal) statTotal.textContent = cveData.length.toLocaleString();
        
        let critCount = 0, highCount = 0, explCount = 0, activeCount = 0;
        cveData.forEach(c => {
            const score = c.score || 0;
            if (score >= 9.0) critCount++;
            else if (score >= 7.0) highCount++;
            if (c.is_exploited) explCount++;
            if (c.is_exploited || c.source === 'Exploit-DB') activeCount++;
        });

        if (statCritical) statCritical.textContent = critCount.toLocaleString();
        if (statHigh) statHigh.textContent = highCount.toLocaleString();
        if (statExploited) statExploited.textContent = explCount.toLocaleString();
        if (statActive) statActive.textContent = activeCount.toLocaleString();

        const paginatedData = filteredData.slice(0, currentPage * itemsPerPage);
        
        if (paginatedData.length === 0) {
            container.innerHTML = `<tr><td colspan="9" style="text-align:center; padding:3rem; color:#64748b;">No intelligence records found matching your query.</td></tr>`;
            if (loadMoreContainer) loadMoreContainer.style.display = 'none';
            return;
        }

        // To avoid re-rendering everything on 'append', we could just add new items.
        // But for table stability with pagination, we redraw the current slice.
        if (append) container.innerHTML = ''; 

        paginatedData.forEach(cve => {
            const tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid rgba(255,255,255,0.05)';
            tr.style.transition = 'background 0.2s';
            tr.addEventListener('mouseenter', () => tr.style.background = 'rgba(255,255,255,0.02)');
            tr.addEventListener('mouseleave', () => tr.style.background = 'transparent');

            const score = cve.score || 0;
            const mtsScore = cve.mts_score || score;
            let mtsBg = 'rgba(148, 163, 184, 0.1)', mtsColor = '#94a3b8', mtsBorder = 'rgba(148, 163, 184, 0.3)';
            if (mtsScore >= 80) { mtsBg = 'rgba(239, 68, 68, 0.1)'; mtsColor = '#f87171'; mtsBorder = 'rgba(239, 68, 68, 0.4)'; }
            else if (mtsScore >= 60) { mtsBg = 'rgba(249, 115, 22, 0.1)'; mtsColor = '#fb923c'; mtsBorder = 'rgba(249, 115, 22, 0.4)'; }
            
            let sourceColor = '#64748b';
            if (cve.source === 'GitHub') sourceColor = '#4ade80';
            else if (cve.source === 'NVD') sourceColor = '#38bdf8';
            else if (cve.source === 'Exploit-DB') sourceColor = '#f472b6';
            else if (cve.source === 'ZDI') sourceColor = '#fb923c';
            else if (cve.source === 'GoogleP0') sourceColor = '#f87171';
            else if (cve.source === 'CERT-CC') sourceColor = '#c4b5fd';

            tr.innerHTML = `
                <td style="padding: 0.8rem 1rem;">
                    <div style="background: ${mtsBg}; color: ${mtsColor}; border: 1px solid ${mtsBorder}; border-radius: 4px; width: 34px; height: 34px; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 0.75rem;" title="Midnight Threat Score: ${mtsScore}">
                        ${Math.round(mtsScore)}
                    </div>
                </td>
                <td style="padding: 0.8rem 1rem; font-weight: bold;">
                    <a href="${cve.source_url}" target="_blank" style="color: #38bdf8; text-decoration: none; border-bottom: 1px dashed rgba(56,189,248,0.4);">${escapeHTML(cve.id)}</a>
                </td>
                <td style="padding: 0.8rem 1rem;">
                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px; flex-wrap: wrap;">
                        <span style="font-size: 0.6rem; font-weight: 800; background: rgba(255,255,255,0.05); color: ${sourceColor}; padding: 1px 6px; border: 1px solid ${sourceColor}44; border-radius: 3px; text-transform: uppercase;">${cve.source || 'Intel'}</span>
                        ${cve.is_exploited ? '<span style="font-size: 0.6rem; font-weight: 800; background: rgba(239, 68, 68, 0.1); color: #f87171; padding: 1px 6px; border: 1px solid #f8717144; border-radius: 3px; text-transform: uppercase;">Exploited</span>' : ''}
                        ${cve.mitre ? `<span style="font-size: 0.6rem; font-weight: 800; background: rgba(56, 189, 248, 0.1); color: #7dd3fc; padding: 1px 6px; border: 1px solid #7dd3fc44; border-radius: 3px; text-transform: uppercase;">${cve.mitre}</span>` : ''}
                    </div>
                    <div style="color: #cbd5e1; font-size: 0.8rem; line-height: 1.4;">${escapeHTML(cve.description || '').substring(0, 120)}...</div>
                </td>
                <td style="padding: 0.8rem 1rem; text-align: center; color: #94a3b8;">${score.toFixed(1)}</td>
                <td style="padding: 0.8rem 1rem; text-align: center; color: #64748b;">${cve.epss ? (cve.epss * 100).toFixed(2) + '%' : '0%'}</td>
                <td style="padding: 0.8rem 1rem; color: #94a3b8; font-size: 0.75rem;">${escapeHTML(cve.vendor || 'OTHER')}</td>
                <td style="padding: 0.8rem 1rem; color: #64748b; font-size: 0.75rem;">${(cve.published || '').split('T')[0]}</td>
                <td style="padding: 0.8rem 1rem;">
                    <button class="action-btn remediation-trigger">ANALYZE</button>
                </td>
            `;

            const remBtn = tr.querySelector('.remediation-trigger');
            if (remBtn) remBtn.addEventListener('click', () => openRemediationModal(cve));
            
            container.appendChild(tr);
        });

        if (loadMoreContainer) {
            loadMoreContainer.style.display = filteredData.length > paginatedData.length ? 'block' : 'none';
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

    // Modal Logic
    const modalOverlay = document.getElementById('remediation-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalBody = document.getElementById('modal-body');
    const closeModal = document.getElementById('close-modal');

    window.openRemediationModal = function(cve) {
        if (!modalOverlay || !modalTitle || !modalBody) return;
        modalOverlay.classList.add('active');
        
        modalTitle.innerHTML = `<i class="ph-fill ph-sparkle" style="color: #c4b5fd;"></i> Intelligence Analysis: <span style="color: #38bdf8">${cve.id}</span>`;
        modalBody.innerHTML = `
            <div style="text-align: center; padding: 30px;">
                <div class="spinner" style="margin: 0 auto 15px auto; border-top-color: #8b5cf6;"></div>
                <p style="color: #94a3b8; font-family: 'Courier New', monospace;">[SYSTEM] Generating Midnight AI Briefing...</p>
            </div>
        `;

        setTimeout(() => {
            const score = cve.score || 0;
            const severity = score >= 9.0 ? 'CRITICAL' : (score >= 7.0 ? 'HIGH' : 'MEDIUM');
            const sevColor = score >= 9.0 ? '#f87171' : (score >= 7.0 ? '#fb923c' : '#fbbf24');
            
            // Dynamic keywords based on description
            const desc = (cve.description || '').toLowerCase();
            const impacts = [];
            if (desc.includes('remote') || desc.includes('rce')) impacts.push('Remote Code Execution (RCE)');
            if (desc.includes('sql') || desc.includes('inject')) impacts.push('Data Injection / SQLi');
            if (desc.includes('overflow')) impacts.push('Memory Corruption / Overflow');
            if (desc.includes('bypass') || desc.includes('auth')) impacts.push('Authentication Bypass');
            if (impacts.length === 0) impacts.push('Confidentiality Breach Potential', 'System Integrity Compromise');

            modalBody.innerHTML = `
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem;">
                    <div class="glass-panel" style="padding: 1rem; border-color: rgba(255,255,255,0.05); background: rgba(15, 23, 42, 0.5);">
                        <span style="display: block; color: #64748b; font-size: 0.7rem; text-transform: uppercase; margin-bottom: 5px;">Threat Context</span>
                        <div style="color: ${sevColor}; font-weight: bold; font-size: 1.1rem;">${severity} RISK LEVEL</div>
                    </div>
                    <div class="glass-panel" style="padding: 1rem; border-color: rgba(255,255,255,0.05); background: rgba(15, 23, 42, 0.5);">
                        <span style="display: block; color: #64748b; font-size: 0.7rem; text-transform: uppercase; margin-bottom: 5px;">Attack Type</span>
                        <div style="color: #7dd3fc; font-weight: bold; font-size: 1rem;">${cve.mitre || 'Generic Vulnerability'}</div>
                    </div>
                </div>
                <div class="glass-panel" style="padding: 1.5rem; margin-bottom: 1.5rem; border-left: 4px solid #8b5cf6; background: rgba(139, 92, 246, 0.05);">
                    <h4 style="color: #c4b5fd; margin: 0 0 10px 0; font-family: 'Courier New', monospace;">// EXECUTIVE SUMMARY</h4>
                    <p style="color: #e2e8f0; line-height: 1.6; font-size: 0.9rem;">
                        This <strong>${cve.mitre || 'security issue'}</strong> in ${cve.vendor || 'the affected product'} represents a <strong>${severity.toLowerCase()}</strong> threat. 
                        ${cve.is_exploited ? '<div style="margin-top: 10px; color: #f87171; background: rgba(248, 113, 113, 0.1); padding: 10px; border-radius: 4px; border: 1px solid rgba(248, 113, 113, 0.2);"><strong>URGENT:</strong> This vulnerability is being actively exploited in the wild (CISA KEV).</div>' : '<div style="margin-top: 10px; color: #94a3b8;">Currently no active mass-exploitation detected, but the risk remains high due to its score of ' + score.toFixed(1) + '.</div>'}
                    </p>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;">
                    <div>
                        <h4 style="color: #f87171; font-size: 0.8rem; text-transform: uppercase; margin-bottom: 10px;">Technical Impact</h4>
                        <ul style="color: #94a3b8; font-size: 0.85rem; padding-left: 1.2rem; line-height: 1.6;">
                            ${impacts.map(i => `<li>${i}</li>`).join('')}
                        </ul>
                    </div>
                    <div>
                        <h4 style="color: #4ade80; font-size: 0.8rem; text-transform: uppercase; margin-bottom: 10px;">Remediation Steps</h4>
                        <ul style="color: #94a3b8; font-size: 0.85rem; padding-left: 1.2rem; line-height: 1.6;">
                            <li>Apply Vendor Security Patch</li>
                            <li>Enable IPS/WAF filtering</li>
                            ${desc.includes('credential') ? '<li>Rotate API keys/Passwords</li>' : ''}
                        </ul>
                    </div>
                </div>
                <div style="margin-top: 2rem; text-align: center;">
                    <button onclick="window.print()" class="action-btn">
                        <i class="ph ph-printer"></i> EXPORT TO PDF REPORT
                    </button>
                </div>
            `;
        }, 800);
    };

    if (closeModal) closeModal.addEventListener('click', () => modalOverlay.classList.remove('active'));
    if (modalOverlay) modalOverlay.addEventListener('click', (e) => {
        if (e.target === modalOverlay) modalOverlay.classList.remove('active');
    });

    // Tab Switching
    const navButtons = document.querySelectorAll('.nav-btn[data-tab]');
    const dashboardSection = document.getElementById('dashboard-section');
    const aboutSection = document.getElementById('about-section');

    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.getAttribute('data-tab');
            navButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            if (dashboardSection) dashboardSection.style.display = tab === 'dashboard' ? 'block' : 'none';
            if (aboutSection) aboutSection.style.display = tab === 'about' ? 'block' : 'none';
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
