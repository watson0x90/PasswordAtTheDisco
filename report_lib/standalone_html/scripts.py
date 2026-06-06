# report_lib/standalone_html/scripts.py
"""
JavaScript functions for HTML reports with enhanced search and filtering.
"""

# Enhanced JavaScript for search functionality with all filters
SEARCH_JS = """
<script>
// ========================================
// HTML escaping (prevent XSS from account data injected into the DOM).
// Account usernames, domains and cracked passwords are attacker-influenceable
// (AD object names; arbitrary cracked passwords), so anything interpolated into
// innerHTML/attributes must be escaped.
// ========================================
function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ========================================
// Global State
// ========================================
let allAccounts = [];
let filteredAccounts = [];
let currentPage = 1;
const rowsPerPage = 100; // Match Flask pagination
let currentFilters = {
    search: '',
    riskLevel: 'all',
    domain: 'all',
    hibpStatus: 'all',
    daPath: 'all',
    accountStatus: 'all',
    passwordStatus: 'all',
    compliance: 'all'
};
let currentSortColumn = 'Risk Level';
let currentSortDir = 'desc';

// ========================================
// User Details Data Population
// ========================================
function populateUserDetailsData() {
    // Create userDetailsData object from allAccounts for USER_DETAIL_JS
    // This converts the flat allAccounts array into a username-keyed object
    if (typeof userDetailsData === 'undefined') {
        window.userDetailsData = {};
    }

    allAccounts.forEach(acc => {
        const username = acc.Username || acc.username;
        if (!username) return;

        // Extract score breakdown if available
        const scoreBreakdown = acc['Score Breakdown'] || {};
        const baseComponents = scoreBreakdown.base_components || {};
        const temporalComponents = scoreBreakdown.temporal_components || {};
        const environmentalComponents = scoreBreakdown.environmental_components || {};

        userDetailsData[username] = {
            username: username,
            domain: acc.Domain || acc['Domain Name'] || 'Unknown',
            enabled: acc.Enabled === 'Yes' || acc.Enabled === true || acc.Enabled === 'True',
            when_created: acc['When Created'] || 'Unknown',
            last_logon: acc['Last Logon'] || acc['Last Logon Timestamp'] || 'Unknown',
            password: acc.Password || null,
            password_hash: acc['Password Hash'] || acc.Password || 'Unknown',
            password_length: acc['Password Length'] || 'N/A',
            complexity_label: acc['Complexity Label'] || 'Unknown',
            cracked: acc['Password Length'] && acc['Password Length'] !== 'N/A',
            risk_score: acc.Score || 0.0,
            risk_level: acc['Risk Level'] || 'Unknown',
            risk_vector: acc['Risk Vector'] || 'N/A',
            base_score: scoreBreakdown.base_score || 'N/A',
            temporal_score: scoreBreakdown.temporal_score || 'N/A',
            environmental_score: scoreBreakdown.environmental_score || 'N/A',
            complexity_factor: baseComponents.complexity_factor || 'N/A',
            length_factor: baseComponents.length_factor || 'N/A',
            dictionary_factor: baseComponents.dictionary_factor || 'N/A',
            similarity_factor: baseComponents.similarity_factor || 'N/A',
            compliance_factor: temporalComponents.compliance_factor || 'N/A',
            expiration_factor: temporalComponents.expiration_factor || 'N/A',
            privilege_factor: environmentalComponents.privilege_factor || 'N/A',
            share_factor: environmentalComponents.share_factor || 'N/A',
            domain_factor: environmentalComponents.domain_factor || 'N/A',
            hibp_factor: environmentalComponents.hibp_factor || 'N/A',
            hibp_breached: acc['HIBP Breached'] === 'Yes',
            hibp_breach_count: acc['HIBP Breach Count'] || 0,
            hibp_risk_level: acc['HIBP Risk Level'] || 'None',
            da_domains: acc['DA Domains'] || 'None',
            controlled_object_count: acc['Controlled Object Count'] || 0,
            forbidden_words: acc['Forbidden Words'] || '',
            keyboard_patterns: acc['Keyboard Patterns'] || '',
            is_common: acc['Common Password'] === 'Yes',
            is_dictionary_word: acc['Is Exactly Dictionary Word'] === 'Yes',
            similar_passwords: acc['Similar Passwords'] || '',
            password_set_to_expire: acc['Password Set to Expire'] || 'Unknown',
            days_out_of_compliance: acc['Days Out of Compliance'] || 'N/A',
            password_last_set: acc['Last Password Set'] || 'Unknown',
            share_count: acc['Share Count'] || 0,
            shared_with: acc['Shared With'] || 'N/A'
        };
    });
}

// ========================================
// Initialization
// ========================================
document.addEventListener('DOMContentLoaded', () => {
    loadData();
    setupEventListeners();
});

function loadData() {
    // Try to load from password_data.json
    fetch('./password_data.json')
        .then(response => {
            if (!response.ok) throw new Error('Failed to load password_data.json');
            return response.json();
        })
        .then(data => {
            // Combine cracked and uncracked accounts
            allAccounts = [];

            // Process domains
            if (data.domains) {
                Object.keys(data.domains).forEach(domain => {
                    const domainData = data.domains[domain];
                    if (domainData.output_rows) {
                        allAccounts = allAccounts.concat(domainData.output_rows);
                    }
                });
            }

            // Add type field based on whether password was cracked
            // Uncracked accounts have Password Length = 'N/A' and Password field contains hash
            allAccounts = allAccounts.map(acc => ({
                ...acc,
                Type: (acc['Password Length'] && acc['Password Length'] !== 'N/A') ? 'Cracked' : 'Uncracked'
            }));

            // Populate userDetailsData for offcanvas (required by USER_DETAIL_JS)
            populateUserDetailsData();

            // Initialize UI
            initializeFilters();
            updateStats();
            applyFiltersAndSort();

            // Check for URL parameter and pre-populate search
            const urlParams = new URLSearchParams(window.location.search);
            const queryParam = urlParams.get('q');
            if (queryParam) {
                const searchInput = document.getElementById('searchInput');
                if (searchInput) {
                    searchInput.value = queryParam;
                    currentFilters.search = queryParam.trim().toLowerCase();
                    // Show clear button if exists
                    const clearButton = document.getElementById('clearSearch');
                    if (clearButton) {
                        clearButton.style.display = 'inline-block';
                    }
                    // Reapply filters with the search term
                    applyFiltersAndSort();
                }
            }
        })
        .catch(error => {
            console.error('Error loading data:', error);
            showError('Failed to load account data: ' + error.message);
        });
}

// ========================================
// Event Listeners Setup
// ========================================
function setupEventListeners() {
    // Search input
    const searchInput = document.getElementById('searchInput');
    const clearButton = document.getElementById('clearSearch');

    if (searchInput) {
        searchInput.addEventListener('input', debounce((e) => {
            currentFilters.search = e.target.value.trim().toLowerCase();
            currentPage = 1;
            applyFiltersAndSort();

            if (clearButton) {
                clearButton.style.display = currentFilters.search ? 'inline-block' : 'none';
            }
        }, 300));
    }

    // Clear button
    if (clearButton) {
        clearButton.addEventListener('click', () => {
            searchInput.value = '';
            currentFilters.search = '';
            currentPage = 1;
            clearButton.style.display = 'none';
            applyFiltersAndSort();
            searchInput.focus();
        });
    }

    // Risk level filter buttons
    document.querySelectorAll('[data-filter]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            currentFilters.riskLevel = btn.dataset.filter;
            currentPage = 1;

            // Update active state
            document.querySelectorAll('[data-filter]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            applyFiltersAndSort();
        });
    });

    // HIBP filter
    document.querySelectorAll('[data-hibp-filter]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            currentFilters.hibpStatus = btn.dataset.hibpFilter;
            currentPage = 1;

            document.querySelectorAll('[data-hibp-filter]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            applyFiltersAndSort();
        });
    });

    // DA Path filter
    document.querySelectorAll('[data-dapath-filter]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            currentFilters.daPath = btn.dataset.dapathFilter;
            currentPage = 1;

            document.querySelectorAll('[data-dapath-filter]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            applyFiltersAndSort();
        });
    });

    // Account Status filter
    document.querySelectorAll('[data-enabled-filter]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            currentFilters.accountStatus = btn.dataset.enabledFilter;
            currentPage = 1;

            document.querySelectorAll('[data-enabled-filter]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            applyFiltersAndSort();
        });
    });

    // Password Status filter
    document.querySelectorAll('[data-password-filter]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            currentFilters.passwordStatus = btn.dataset.passwordFilter;
            currentPage = 1;

            document.querySelectorAll('[data-password-filter]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            applyFiltersAndSort();
        });
    });

    // Compliance filter
    document.querySelectorAll('[data-compliance-filter]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            currentFilters.compliance = btn.dataset.complianceFilter;
            currentPage = 1;

            document.querySelectorAll('[data-compliance-filter]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            applyFiltersAndSort();
        });
    });

    // Sortable column headers (click + keyboard) with aria-sort
    initColumnSort();

    // Export buttons
    const exportCsvBtn = document.getElementById('exportCsvBtn');
    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', exportToCSV);
    }

    const exportJsonBtn = document.getElementById('exportJsonBtn');
    if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', exportToJSON);
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Ctrl/Cmd + K to focus search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const searchInput = document.getElementById('searchInput');
            if (searchInput) {
                searchInput.focus();
                searchInput.select();
            }
        }
    });
}

// ========================================
// Initialize Domain Filters
// ========================================
function initializeFilters() {
    const domains = [...new Set(allAccounts.map(acc => acc.Domain || acc['Domain Name']))].sort();
    const domainContainer = document.getElementById('domainFilters');

    if (domainContainer && domains.length > 1) {
        const btnGroup = document.createElement('div');
        btnGroup.className = 'btn-group btn-group-sm flex-wrap';

        // All domains button
        const allBtn = document.createElement('button');
        allBtn.className = 'btn btn-outline-primary active';
        allBtn.textContent = 'All';
        allBtn.dataset.domainFilter = 'all';
        allBtn.addEventListener('click', (e) => {
            e.preventDefault();
            currentFilters.domain = 'all';
            currentPage = 1;
            document.querySelectorAll('[data-domain-filter]').forEach(b => b.classList.remove('active'));
            allBtn.classList.add('active');
            applyFiltersAndSort();
        });
        btnGroup.appendChild(allBtn);

        // Individual domain buttons
        domains.forEach(domain => {
            const btn = document.createElement('button');
            btn.className = 'btn btn-outline-primary';
            btn.textContent = domain;
            btn.dataset.domainFilter = domain;
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                currentFilters.domain = domain;
                currentPage = 1;
                document.querySelectorAll('[data-domain-filter]').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                applyFiltersAndSort();
            });
            btnGroup.appendChild(btn);
        });

        domainContainer.innerHTML = '';
        domainContainer.appendChild(btnGroup);
    }
}

// ========================================
// Filtering and Sorting
// ========================================
function applyFiltersAndSort() {
    // Apply filters
    filteredAccounts = allAccounts.filter(account => {
        // Search filter
        if (currentFilters.search) {
            const username = (account.Username || account.username || '').toLowerCase();
            if (!username.includes(currentFilters.search)) {
                return false;
            }
        }

        // Risk level filter
        if (currentFilters.riskLevel !== 'all') {
            const riskLevel = (account['Risk Level'] || '').toLowerCase();
            if (riskLevel !== currentFilters.riskLevel) {
                return false;
            }
        }

        // Domain filter
        if (currentFilters.domain !== 'all') {
            const domain = account.Domain || account['Domain Name'];
            if (domain !== currentFilters.domain) {
                return false;
            }
        }

        // HIBP filter
        if (currentFilters.hibpStatus !== 'all') {
            const breached = account['HIBP Breached'] === 'Yes';
            if (currentFilters.hibpStatus === 'breached' && !breached) return false;
            if (currentFilters.hibpStatus === 'clean' && breached) return false;
        }

        // DA Path filter
        if (currentFilters.daPath !== 'all') {
            const hasDaPath = account['DA Domains'] && account['DA Domains'] !== 'None';
            if (currentFilters.daPath === 'has-path' && !hasDaPath) return false;
            if (currentFilters.daPath === 'no-path' && hasDaPath) return false;
        }

        // Account Status filter
        if (currentFilters.accountStatus !== 'all') {
            const enabled = account['Enabled'] === 'True' || account['Enabled'] === true;
            if (currentFilters.accountStatus === 'enabled' && !enabled) return false;
            if (currentFilters.accountStatus === 'disabled' && enabled) return false;
        }

        // Password Status filter
        if (currentFilters.passwordStatus !== 'all') {
            const cracked = account.Type === 'Cracked';
            if (currentFilters.passwordStatus === 'cracked' && !cracked) return false;
            if (currentFilters.passwordStatus === 'uncracked' && cracked) return false;
        }

        // Compliance filter
        if (currentFilters.compliance !== 'all') {
            const daysOutOfCompliance = parseFloat(account['Days Out of Compliance']) || 0;
            const compliant = daysOutOfCompliance <= 0;
            if (currentFilters.compliance === 'compliant' && !compliant) return false;
            if (currentFilters.compliance === 'non-compliant' && compliant) return false;
        }

        return true;
    });

    // Apply sorting
    filteredAccounts = applySorting(filteredAccounts);

    // Update display
    renderResults();
    updateStats();
}

function applySorting(accounts) {
    const sorted = [...accounts];
    const col = currentSortColumn;
    const dir = currentSortDir === 'asc' ? 1 : -1;
    const riskOrder = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1};

    sorted.sort((a, b) => {
        // Risk Level sorts by severity rank, not alphabetically.
        if (col === 'Risk Level') {
            const ar = riskOrder[(a['Risk Level'] || '').toLowerCase()] || 0;
            const br = riskOrder[(b['Risk Level'] || '').toLowerCase()] || 0;
            return (ar - br) * dir;
        }
        let av = a[col]; if (av === undefined) av = a[col.toLowerCase()];
        let bv = b[col]; if (bv === undefined) bv = b[col.toLowerCase()];
        av = (av === undefined || av === null) ? '' : av;
        bv = (bv === undefined || bv === null) ? '' : bv;
        const an = parseFloat(av), bn = parseFloat(bv);
        if (av !== '' && bv !== '' && !isNaN(an) && !isNaN(bn)) {
            return (an - bn) * dir;
        }
        return String(av).toLowerCase().localeCompare(String(bv).toLowerCase()) * dir;
    });

    return sorted;
}

// Reflect the current sort on the column headers for assistive tech.
function updateAriaSort() {
    document.querySelectorAll('#resultsTable thead th[data-column]').forEach(th => {
        if (th.dataset.column === currentSortColumn) {
            th.setAttribute('aria-sort', currentSortDir === 'asc' ? 'ascending' : 'descending');
        } else {
            th.setAttribute('aria-sort', 'none');
        }
    });
}

// Make the result table's column headers sortable via click and keyboard.
function initColumnSort() {
    const headers = document.querySelectorAll('#resultsTable thead th[data-column]');
    headers.forEach(th => {
        th.setAttribute('tabindex', '0');
        th.setAttribute('role', 'columnheader');
        th.style.cursor = 'pointer';
        const doSort = () => {
            const col = th.dataset.column;
            if (currentSortColumn === col) {
                currentSortDir = currentSortDir === 'asc' ? 'desc' : 'asc';
            } else {
                currentSortColumn = col;
                currentSortDir = 'asc';
            }
            currentPage = 1;
            updateAriaSort();
            applyFiltersAndSort();
        };
        th.addEventListener('click', doSort);
        th.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); doSort(); }
        });
    });
    updateAriaSort();
}

// ========================================
// Rendering
// ========================================
function renderResults() {
    const tbody = document.querySelector('#resultsTable tbody');
    if (!tbody) return;

    tbody.innerHTML = '';

    // Pagination
    const totalPages = Math.ceil(filteredAccounts.length / rowsPerPage);
    const startIndex = (currentPage - 1) * rowsPerPage;
    const endIndex = Math.min(startIndex + rowsPerPage, filteredAccounts.length);
    const pageData = filteredAccounts.slice(startIndex, endIndex);

    // Render rows
    pageData.forEach(account => {
        const row = document.createElement('tr');
        const riskLevel = (account['Risk Level'] || '').toLowerCase();

        // Create risk badge
        const riskBadge = riskLevel ?
            `<span class="badge badge-risk-${riskLevel}">${account['Risk Level']}</span>` :
            '<span class="badge bg-secondary">Unknown</span>';

        // HIBP badge
        const hibpBadge = account['HIBP Breached'] === 'Yes' ?
            `<span class="badge bg-danger">Breached (${account['HIBP Breach Count'] || 0})</span>` :
            '<span class="badge bg-success">Clean</span>';

        // DA path indicator
        const daPath = account['DA Domains'] && account['DA Domains'] !== 'None' ?
            '<span class="badge bg-warning text-dark">DA Path</span>' :
            '';

        // Enabled status
        const enabledBadge = account['Enabled'] === 'True' || account['Enabled'] === true ?
            '<span class="badge bg-primary">Enabled</span>' :
            '<span class="badge bg-secondary">Disabled</span>';

        // Type badge
        const typeBadge = account.Type === 'Cracked' ?
            '<span class="badge bg-success">Cracked</span>' :
            '<span class="badge bg-warning">Uncracked</span>';

        const username = account.Username || account.username || 'N/A';

        // Account data (username/domain/password) is escaped; badges and daPath
        // are trusted HTML generated above.
        row.innerHTML = `
            <td>
                <a href="#" class="user-detail-link text-decoration-none"
                   data-username="${escapeHtml(username)}"
                   data-coreui-toggle="offcanvas"
                   data-coreui-target="#userDetailOffcanvas">
                    <code>${escapeHtml(username)}</code>
                </a>
            </td>
            <td>${escapeHtml(account.Domain || account['Domain Name'] || 'N/A')}</td>
            <td>${account.Type === 'Cracked' ? escapeHtml(account.Password) : '<span class="text-muted">Hash: ' + escapeHtml(account.Password) + '</span>'}</td>
            <td>${typeBadge}</td>
            <td>${riskBadge}</td>
            <td>${enabledBadge}</td>
            <td>${escapeHtml(account['Last Logon Timestamp'] || 'Unknown')}</td>
            <td>${escapeHtml(account['Password Set to Expire'] || 'Unknown')}</td>
            <td>${escapeHtml(account['Controlled Object Count'] || 0)}</td>
            <td>${daPath}</td>
            <td>${escapeHtml(account['Shared With'] || 0)}</td>
            <td>${escapeHtml(account['Last Password Set'] || 'Unknown')}</td>
            <td>${escapeHtml(account['Days Out of Compliance'] || 0)}</td>
            <td><small class="text-muted">${escapeHtml(account['Risk Vector'] || 'N/A')}</small></td>
        `;
        tbody.appendChild(row);
    });

    // Update pagination
    updatePagination(totalPages);

    // Update result count
    const resultCount = document.getElementById('resultCount');
    if (resultCount) {
        resultCount.textContent = filteredAccounts.length;
    }
}

function updatePagination(totalPages) {
    const container = document.getElementById('pagination');
    if (!container) return;

    container.innerHTML = '';

    if (totalPages <= 1) return;

    const nav = document.createElement('nav');
    const ul = document.createElement('ul');
    ul.className = 'pagination justify-content-center';

    // Previous button
    const prevLi = document.createElement('li');
    prevLi.className = `page-item ${currentPage === 1 ? 'disabled' : ''}`;
    prevLi.innerHTML = `<a class="page-link" href="#" tabindex="-1">Previous</a>`;
    prevLi.addEventListener('click', (e) => {
        e.preventDefault();
        if (currentPage > 1) {
            currentPage--;
            renderResults();
        }
    });
    ul.appendChild(prevLi);

    // Page numbers
    const maxButtons = 5;
    let startPage = Math.max(1, currentPage - Math.floor(maxButtons / 2));
    let endPage = Math.min(totalPages, startPage + maxButtons - 1);

    if (endPage - startPage < maxButtons - 1) {
        startPage = Math.max(1, endPage - maxButtons + 1);
    }

    // First page if not visible
    if (startPage > 1) {
        const firstLi = document.createElement('li');
        firstLi.className = 'page-item';
        firstLi.innerHTML = `<a class="page-link" href="#">1</a>`;
        firstLi.addEventListener('click', (e) => {
            e.preventDefault();
            currentPage = 1;
            renderResults();
        });
        ul.appendChild(firstLi);

        if (startPage > 2) {
            const ellipsisLi = document.createElement('li');
            ellipsisLi.className = 'page-item disabled';
            ellipsisLi.innerHTML = `<span class="page-link">...</span>`;
            ul.appendChild(ellipsisLi);
        }
    }

    // Page buttons
    for (let i = startPage; i <= endPage; i++) {
        const pageLi = document.createElement('li');
        pageLi.className = `page-item ${i === currentPage ? 'active' : ''}`;
        pageLi.innerHTML = `<a class="page-link" href="#">${i}</a>`;
        pageLi.addEventListener('click', (e) => {
            e.preventDefault();
            currentPage = i;
            renderResults();
        });
        ul.appendChild(pageLi);
    }

    // Last page if not visible
    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            const ellipsisLi = document.createElement('li');
            ellipsisLi.className = 'page-item disabled';
            ellipsisLi.innerHTML = `<span class="page-link">...</span>`;
            ul.appendChild(ellipsisLi);
        }

        const lastLi = document.createElement('li');
        lastLi.className = 'page-item';
        lastLi.innerHTML = `<a class="page-link" href="#">${totalPages}</a>`;
        lastLi.addEventListener('click', (e) => {
            e.preventDefault();
            currentPage = totalPages;
            renderResults();
        });
        ul.appendChild(lastLi);
    }

    // Next button
    const nextLi = document.createElement('li');
    nextLi.className = `page-item ${currentPage === totalPages ? 'disabled' : ''}`;
    nextLi.innerHTML = `<a class="page-link" href="#">Next</a>`;
    nextLi.addEventListener('click', (e) => {
        e.preventDefault();
        if (currentPage < totalPages) {
            currentPage++;
            renderResults();
        }
    });
    ul.appendChild(nextLi);

    nav.appendChild(ul);
    container.appendChild(nav);
}

// ========================================
// Statistics Update
// ========================================
function updateStats() {
    // Total accounts
    const totalElement = document.getElementById('totalAccounts');
    if (totalElement) {
        totalElement.textContent = formatNumber(allAccounts.length);
    }

    // Critical count
    const criticalElement = document.getElementById('criticalCount');
    if (criticalElement) {
        const critical = allAccounts.filter(a =>
            (a['Risk Level'] || '').toLowerCase() === 'critical'
        ).length;
        criticalElement.textContent = formatNumber(critical);
    }

    // High count
    const highElement = document.getElementById('highCount');
    if (highElement) {
        const high = allAccounts.filter(a =>
            (a['Risk Level'] || '').toLowerCase() === 'high'
        ).length;
        highElement.textContent = formatNumber(high);
    }
}

// ========================================
// Export Functions
// ========================================
function exportToCSV() {
    const headers = [
        'Username', 'Domain', 'Password', 'Risk Level',
        'HIBP Breached', 'HIBP Breach Count', 'DA Domains',
        'Enabled', 'Controlled Object Count', 'Days Out of Compliance',
        'Risk Vector'
    ];

    let csv = headers.join(',') + '\\n';

    filteredAccounts.forEach(account => {
        const row = headers.map(header => {
            let value = account[header] || '';
            // Escape quotes and wrap in quotes if contains comma
            if (typeof value === 'string' && (value.includes(',') || value.includes('"'))) {
                value = '"' + value.replace(/"/g, '""') + '"';
            }
            return value;
        });
        csv += row.join(',') + '\\n';
    });

    downloadFile(csv, 'password_audit_export.csv', 'text/csv');
    showToast('Exported ' + filteredAccounts.length + ' accounts to CSV');
}

function exportToJSON() {
    const json = JSON.stringify(filteredAccounts, null, 2);
    downloadFile(json, 'password_audit_export.json', 'application/json');
    showToast('Exported ' + filteredAccounts.length + ' accounts to JSON');
}

// ========================================
// Utility Functions
// ========================================
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

function formatNumber(num) {
    return num.toString().replace(/\\B(?=(\\d{3})+(?!\\d))/g, ',');
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
}

function showToast(message) {
    // Create toast notification
    const toast = document.createElement('div');
    toast.className = 'toast show position-fixed bottom-0 end-0 m-3';
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="toast-header">
            <strong class="me-auto">Export Complete</strong>
            <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
        </div>
        <div class="toast-body">
            ${message}
        </div>
    `;
    document.body.appendChild(toast);

    // Auto-hide after 3 seconds
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

function showError(message) {
    const errorDiv = document.getElementById('errorMessage');
    if (errorDiv) {
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
    } else {
        console.error(message);
    }
}
</script>
"""

# Redacted search JavaScript (hides actual passwords)
SEARCH_REDACTED_JS = SEARCH_JS.replace(
    "<td>${account.Type === 'Cracked' ? escapeHtml(account.Password) : '<span class=\"text-muted\">Hash: ' + escapeHtml(account.Password) + '</span>'}</td>",
    "<td>${account.Type === 'Cracked' ? '********' : '<span class=\"text-muted\">Hash: ' + escapeHtml(account.Password) + '</span>'}</td>"
)
assert SEARCH_REDACTED_JS != SEARCH_JS, "Redacted search replacement failed to match -- passwords would be exposed"

# JavaScript for tab switching (Bootstrap/CoreUI)
TAB_SWITCH_JS = """
<script>
document.addEventListener('DOMContentLoaded', function() {
    // Handle tab switching for Bootstrap/CoreUI nav tabs
    const tabs = document.querySelectorAll('[data-bs-toggle="tab"], [data-coreui-toggle="tab"]');
    tabs.forEach(tab => {
        tab.addEventListener('click', function(e) {
            e.preventDefault();
            // Use Bootstrap/CoreUI tab API
            const tabTrigger = new bootstrap.Tab ? new bootstrap.Tab(tab) : new coreui.Tab(tab);
            tabTrigger.show();
        });
    });

    // Activate first tab if none active
    const activeTab = document.querySelector('.nav-tabs .nav-link.active');
    if (!activeTab) {
        const firstTab = document.querySelector('.nav-tabs .nav-link');
        if (firstTab) {
            const tabTrigger = new bootstrap.Tab ? new bootstrap.Tab(firstTab) : new coreui.Tab(firstTab);
            tabTrigger.show();
        }
    }
});
</script>
"""

# JavaScript for actionable report filtering and score breakdown
ACTIONABLE_REPORT_JS = """
<script>
// Filter table rows by risk level
function filterByRisk(riskLevel, button) {
    const table = button.closest('.card-body').querySelector('table');
    if (!table) return;

    const rows = table.querySelectorAll('tbody tr.risk-row');

    // Update active button
    const buttonGroup = button.parentElement;
    buttonGroup.querySelectorAll('.btn').forEach(b => b.classList.remove('active'));
    button.classList.add('active');

    // Show/hide rows based on filter
    rows.forEach(row => {
        if (riskLevel === 'all' || row.dataset.risk === riskLevel) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

// Toggle score breakdown collapse
function toggleScoreBreakdown(rowId) {
    const collapseElement = document.getElementById(rowId);
    if (collapseElement) {
        const bsCollapse = new bootstrap.Collapse(collapseElement, {
            toggle: true
        });
    }
}

// Parse risk vector and return human-readable breakdown
function parseRiskVector(vector) {
    if (!vector || vector === 'N/A') {
        return '<p class="text-muted">No risk vector available</p>';
    }

    const components = vector.split('/');
    let html = '<dl class="row mb-0">';

    components.forEach(comp => {
        const [key, value] = comp.split(':');
        let label = '';
        let description = value;

        switch(key) {
            case 'C': label = 'Complexity'; break;
            case 'L': label = 'Length'; break;
            case 'D': label = 'Dictionary'; break;
            case 'SM': label = 'Similarity'; break;
            case 'CM': label = 'Compliance'; break;
            case 'EX': label = 'Expiration'; break;
            case 'DA': label = 'Domain Admin'; break;
            case 'CO': label = 'Controlled Objects'; break;
            case 'S': label = 'Sharing'; break;
            case 'DR': label = 'Domain Risk'; break;
            case 'HIBP': label = 'HIBP Breach'; break;
            default: label = key;
        }

        html += `
            <dt class="col-sm-4 text-end">${label}:</dt>
            <dd class="col-sm-8"><code>${description}</code></dd>
        `;
    });

    html += '</dl>';
    return html;
}
</script>
"""

# JavaScript for user detail offcanvas panel
# Placeholder {USER_DATA_JSON} will be replaced with actual JSON data
USER_DETAIL_JS = """
<script>
// Escape account data before injecting into the offcanvas DOM (see SEARCH_JS).
function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// User detail data (populated during report generation)
let userDetailsData = {USER_DATA_JSON};

// Initialize event listeners when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Use event delegation for dynamically created user-detail-link elements
    // This ensures click handlers work even when links are created after page load
    document.body.addEventListener('click', function(e) {
        // Check if clicked element is a user-detail-link or inside one
        const link = e.target.closest('.user-detail-link');
        if (link) {
            e.preventDefault();
            const username = link.dataset.username;
            if (username) {
                loadUserDetails(username);
            }
        }
    });
});

// Main function to load user details
function loadUserDetails(username) {
    const userData = userDetailsData[username];
    if (!userData) {
        console.error('User data not found:', username);
        return;
    }

    // Populate offcanvas title
    document.getElementById('userDetailTitle').textContent = username;

    // Populate summary cards
    populateRiskSummaryCards(userData);

    // Populate detailed breakdown sections
    populateRiskBreakdown(userData);
    populateAccountProperties(userData);
    populatePrivileges(userData);
}

// Populate the 4 summary cards at the top
function populateRiskSummaryCards(userData) {
    // Risk Level Card
    const riskLevelValue = document.getElementById('riskLevelValue');
    const riskLevelCard = document.getElementById('riskLevelCard');

    riskLevelValue.innerHTML = `
        ${userData.risk_score}/10<br>
        <span class="badge ${getRiskBadgeClass(userData.risk_level)} mt-1">${userData.risk_level}</span>
    `;

    // Set card background color based on risk
    riskLevelCard.className = 'card text-center h-100 ' + getRiskCardClass(userData.risk_level);

    // Controlled Objects
    document.getElementById('controlledObjectsValue').textContent =
        userData.controlled_object_count || '0';

    // HIBP Breaches
    document.getElementById('hibpBreachesValue').innerHTML =
        userData.hibp_breached ?
        `<span class="text-danger">${(userData.hibp_breach_count || 0).toLocaleString()}</span>` :
        '<span class="text-success">0</span>';

    // Account Status
    document.getElementById('accountStatusValue').innerHTML =
        userData.enabled ?
        '<span class="badge bg-success">Enabled</span>' :
        '<span class="badge bg-secondary">Disabled</span>';
}

// Populate risk breakdown tab with high detail
function populateRiskBreakdown(userData) {
    const container = document.getElementById('riskBreakdownContent');

    let html = '';

    // Base Score Section
    html += `
        <div class="mb-4">
            <h6 class="text-muted mb-3">
                <i class="bi bi-1-circle me-2"></i>Base Score (Password Quality)
            </h6>
            ${createScoreItem('Complexity Factor', userData.complexity_factor, 'Using ' + userData.complexity_label + ' character sets')}
            ${createScoreItem('Length Factor', userData.length_factor, userData.password_length + ' characters long')}
            ${createScoreItem('Dictionary Factor', userData.dictionary_factor,
                (userData.is_common ? 'Common password, ' : '') +
                (userData.is_dictionary_word ? 'Dictionary word, ' : '') +
                (userData.forbidden_words ? 'Forbidden words: ' + userData.forbidden_words : 'No issues')
            )}
            ${createScoreItem('Similarity Factor', userData.similarity_factor,
                userData.similar_passwords ? 'Similar to: ' + userData.similar_passwords : 'No similar passwords'
            )}
        </div>
    `;

    // Temporal Score Section
    html += `
        <div class="mb-4">
            <h6 class="text-muted mb-3">
                <i class="bi bi-2-circle me-2"></i>Temporal Score (Time-Based Factors)
            </h6>
            ${createScoreItem('Compliance Factor', userData.compliance_factor,
                userData.days_out_of_compliance !== 'N/A' && userData.days_out_of_compliance !== 'Unknown' ?
                userData.days_out_of_compliance + ' days out of compliance' :
                'Compliant'
            )}
            ${createScoreItem('Expiration Factor', userData.expiration_factor,
                userData.password_set_to_expire === 'No' ? 'Password never expires' : 'Password set to expire'
            )}
        </div>
    `;

    // Environmental Score Section
    html += `
        <div class="mb-4">
            <h6 class="text-muted mb-3">
                <i class="bi bi-3-circle me-2"></i>Environmental Score (Organizational Context)
            </h6>
    `;

    // DA Pathway Alert
    if (userData.da_domains && userData.da_domains !== 'None' && userData.da_domains !== 'Unknown') {
        html += `
            <div class="alert alert-danger mb-3">
                <i class="bi bi-exclamation-triangle me-2"></i>
                <strong>Domain Admin Pathway Detected</strong><br>
                Domains: ${escapeHtml(userData.da_domains)}
            </div>
        `;
    }

    html += createScoreItem('Privilege Factor', userData.privilege_factor,
        userData.controlled_object_count > 0 ?
        'Controls ' + userData.controlled_object_count + ' objects' :
        'No controlled objects'
    );

    html += createScoreItem('Share Factor', userData.share_factor,
        userData.share_count > 0 ?
        'Shared with ' + userData.share_count + ' accounts' :
        'Not shared'
    );

    html += createScoreItem('Domain Factor', userData.domain_factor,
        'Domain: ' + userData.domain
    );

    html += createScoreItem('HIBP Factor', userData.hibp_factor,
        userData.hibp_breached ?
        'Found in ' + (userData.hibp_breach_count || 0).toLocaleString() + ' breaches (' + userData.hibp_risk_level + ')' :
        'Not found in breaches'
    );

    html += '</div>';

    // Final Score Summary
    html += `
        <div class="card bg-body-secondary">
            <div class="card-body">
                <h6 class="mb-3">Final Risk Score Calculation</h6>
                <dl class="row mb-0">
                    <dt class="col-sm-6">Base Score:</dt>
                    <dd class="col-sm-6"><span class="badge bg-info">${userData.base_score}</span></dd>
                    <dt class="col-sm-6">Temporal Score:</dt>
                    <dd class="col-sm-6"><span class="badge bg-warning text-dark">${userData.temporal_score}</span></dd>
                    <dt class="col-sm-6">Environmental Score:</dt>
                    <dd class="col-sm-6"><span class="badge bg-danger">${userData.environmental_score}</span></dd>
                    <dt class="col-sm-6"><strong>Final Score:</strong></dt>
                    <dd class="col-sm-6"><span class="badge ${getRiskBadgeClass(userData.risk_level)} fs-6">${userData.risk_score}/10</span></dd>
                </dl>
            </div>
        </div>
    `;

    container.innerHTML = html;
}

// Create a score item with progress bar
function createScoreItem(label, value, description) {
    if (value === 'N/A' || value === null || value === undefined) {
        return `
            <div class="mb-3">
                <div class="d-flex justify-content-between mb-1">
                    <span>${label}</span>
                    <span class="text-muted">N/A</span>
                </div>
                <small class="text-muted"><i class="bi bi-info-circle me-1"></i>${escapeHtml(description)}</small>
            </div>
        `;
    }

    // Normalize value to 0-100 percentage for progress bar
    let percentage = Math.round(parseFloat(value) * 100);
    if (percentage > 100) percentage = 100;
    if (percentage < 0) percentage = 0;

    // Determine color based on value
    let colorClass = 'bg-success';
    if (percentage >= 70) colorClass = 'bg-danger';
    else if (percentage >= 40) colorClass = 'bg-warning';

    return `
        <div class="mb-3">
            <div class="d-flex justify-content-between mb-1">
                <span>${label}</span>
                <span class="badge ${colorClass}">${value}</span>
            </div>
            <div class="progress mb-2" style="height: 8px;">
                <div class="progress-bar ${colorClass}" style="width: ${percentage}%"></div>
            </div>
            <small class="text-muted"><i class="bi bi-info-circle me-1"></i>${escapeHtml(description)}</small>
        </div>
    `;
}

// Populate account properties tab
function populateAccountProperties(userData) {
    const container = document.getElementById('accountPropsContent');

    const html = `
        <dt class="col-sm-5">Account Status</dt>
        <dd class="col-sm-7">
            ${userData.enabled ?
              '<span class="badge bg-success"><i class="bi bi-check-circle me-1"></i>Enabled</span>' :
              '<span class="badge bg-secondary">Disabled</span>'}
        </dd>

        <dt class="col-sm-5">Domain</dt>
        <dd class="col-sm-7">${escapeHtml(userData.domain)}</dd>

        <dt class="col-sm-5">Last Logon</dt>
        <dd class="col-sm-7">${userData.last_logon || 'Unknown'}</dd>

        <dt class="col-sm-5">Password Last Set</dt>
        <dd class="col-sm-7">
            ${userData.password_last_set || 'Unknown'}
            ${userData.days_out_of_compliance !== 'N/A' && userData.days_out_of_compliance !== 'Unknown' ?
              '<span class="badge bg-danger ms-2">' + userData.days_out_of_compliance + ' days ago</span>' :
              ''}
        </dd>

        <dt class="col-sm-5">Password Expires</dt>
        <dd class="col-sm-7">
            ${userData.password_set_to_expire === 'No' ?
              '<span class="badge bg-warning text-dark"><i class="bi bi-exclamation-triangle me-1"></i>Never</span>' :
              '<span class="badge bg-success">Yes</span>'}
        </dd>

        <dt class="col-sm-5">When Created</dt>
        <dd class="col-sm-7">${userData.when_created || 'Unknown'}</dd>

        <dt class="col-sm-5">Controlled Objects</dt>
        <dd class="col-sm-7">
            <span class="badge bg-primary">${userData.controlled_object_count || 0}</span>
        </dd>

        <dt class="col-sm-5">Password Cracked</dt>
        <dd class="col-sm-7">
            ${userData.cracked ?
              '<span class="badge bg-danger">Yes</span>' :
              '<span class="badge bg-secondary">No</span>'}
        </dd>

        <dt class="col-sm-5">Password Length</dt>
        <dd class="col-sm-7">${userData.password_length} characters</dd>

        <dt class="col-sm-5">Complexity</dt>
        <dd class="col-sm-7"><code>${escapeHtml(userData.complexity_label)}</code></dd>

        <dt class="col-sm-5">HIBP Breached</dt>
        <dd class="col-sm-7">
            ${userData.hibp_breached ?
              '<span class="badge bg-danger">Yes</span> <span class="badge bg-secondary ms-1">' +
              (userData.hibp_breach_count || 0).toLocaleString() + ' breaches</span>' :
              '<span class="badge bg-success">No</span>'}
        </dd>

        <dt class="col-sm-5">Risk Vector</dt>
        <dd class="col-sm-7"><small><code>${escapeHtml(userData.risk_vector)}</code></small></dd>
    `;

    container.innerHTML = html;
}

// Populate privileges tab
function populatePrivileges(userData) {
    const container = document.getElementById('privilegesContent');

    let html = '';

    // DA Domains
    if (userData.da_domains && userData.da_domains !== 'None' && userData.da_domains !== 'Unknown') {
        html += `
            <div class="alert alert-danger mb-3">
                <h6 class="alert-heading">
                    <i class="bi bi-exclamation-triangle me-2"></i>Domain Admin Pathway
                </h6>
                <p class="mb-0">This account has a pathway to Domain Admin in the following domains:</p>
                <p class="mb-0 mt-2"><strong>${escapeHtml(userData.da_domains)}</strong></p>
            </div>
        `;
    }

    // Controlled Objects Count
    html += `
        <div class="card mb-3">
            <div class="card-header bg-primary text-white">
                <h6 class="mb-0">
                    <i class="bi bi-diagram-3 me-2"></i>Controlled Objects
                </h6>
            </div>
            <div class="card-body">
                <p class="mb-2">This account can control <strong>${userData.controlled_object_count || 0}</strong> objects in Active Directory.</p>
                <small class="text-muted">
                    <i class="bi bi-info-circle me-1"></i>
                    Detailed object list is available in BloodHound for comprehensive attack path analysis.
                </small>
            </div>
        </div>
    `;

    // Password Sharing
    if (userData.share_count > 0) {
        html += `
            <div class="card">
                <div class="card-header bg-warning text-dark">
                    <h6 class="mb-0">
                        <i class="bi bi-people me-2"></i>Password Sharing
                    </h6>
                </div>
                <div class="card-body">
                    <p class="mb-0">This password is shared with <strong>${userData.share_count}</strong> other accounts.</p>
                    ${userData.shared_with !== 'N/A' ? '<p class="mb-0 mt-2 small text-muted">Details: ' + escapeHtml(userData.shared_with) + '</p>' : ''}
                </div>
            </div>
        `;
    }

    container.innerHTML = html;
}

// Helper function to get badge class based on risk level
function getRiskBadgeClass(riskLevel) {
    switch(riskLevel.toLowerCase()) {
        case 'critical': return 'badge-risk-critical';
        case 'high': return 'badge-risk-high';
        case 'medium': return 'badge-risk-medium';
        case 'low': return 'badge-risk-low';
        default: return 'bg-secondary';
    }
}

// Helper function to get card background class based on risk level
function getRiskCardClass(riskLevel) {
    switch(riskLevel.toLowerCase()) {
        case 'critical': return 'bg-danger text-white';
        case 'high': return 'bg-warning text-dark';
        case 'medium': return 'bg-info text-white';
        case 'low': return 'bg-success text-white';
        default: return '';
    }
}
</script>
"""


# JavaScript for sidebar toggle and navigation features
SIDEBAR_NAV_JS = """
<script>
// ========================================
// Sidebar Toggle Functionality
// ========================================
document.addEventListener('DOMContentLoaded', function() {
    const sidebar = document.getElementById('sidebar');
    const toggler = document.querySelector('.sidebar-toggler');

    if (toggler && sidebar) {
        // Desktop: Toggle narrow/wide sidebar
        toggler.addEventListener('click', function() {
            if (window.innerWidth >= 992) {
                // Desktop: toggle narrow mode
                sidebar.classList.toggle('sidebar-narrow');

                // Save state to localStorage
                const isNarrow = sidebar.classList.contains('sidebar-narrow');
                localStorage.setItem('sidebarState', isNarrow ? 'narrow' : 'wide');
            } else {
                // Mobile: toggle show/hide
                sidebar.classList.toggle('show');
            }
        });

        // Restore sidebar state from localStorage (desktop only)
        if (window.innerWidth >= 992) {
            const savedState = localStorage.getItem('sidebarState');
            if (savedState === 'narrow') {
                sidebar.classList.add('sidebar-narrow');
            }
        }

        // Mobile: Close sidebar when clicking outside
        document.addEventListener('click', function(e) {
            if (window.innerWidth < 992 &&
                sidebar.classList.contains('show') &&
                !sidebar.contains(e.target) &&
                !toggler.contains(e.target)) {
                sidebar.classList.remove('show');
            }
        });

        // Mobile: Close sidebar when clicking a link
        if (window.innerWidth < 992) {
            sidebar.querySelectorAll('.nav-link:not(.nav-group-toggle)').forEach(link => {
                link.addEventListener('click', function() {
                    sidebar.classList.remove('show');
                });
            });
        }
    }

    // Handle nav-group toggles (collapsible menus)
    document.querySelectorAll('.nav-group-toggle').forEach(toggle => {
        toggle.addEventListener('click', function(e) {
            e.preventDefault();
            const parent = this.closest('.nav-group');
            if (parent) {
                parent.classList.toggle('show');

                // Save expanded state to localStorage
                const groupId = this.textContent.trim();
                const isExpanded = parent.classList.contains('show');
                const expandedGroups = JSON.parse(localStorage.getItem('expandedNavGroups') || '[]');

                if (isExpanded && !expandedGroups.includes(groupId)) {
                    expandedGroups.push(groupId);
                } else if (!isExpanded) {
                    const index = expandedGroups.indexOf(groupId);
                    if (index > -1) expandedGroups.splice(index, 1);
                }

                localStorage.setItem('expandedNavGroups', JSON.stringify(expandedGroups));
            }
        });
    });

    // Restore expanded nav groups from localStorage
    try {
        const expandedGroups = JSON.parse(localStorage.getItem('expandedNavGroups') || '[]');
        expandedGroups.forEach(groupId => {
            document.querySelectorAll('.nav-group-toggle').forEach(toggle => {
                if (toggle.textContent.trim() === groupId) {
                    const parent = toggle.closest('.nav-group');
                    if (parent) {
                        parent.classList.add('show');
                    }
                }
            });
        });
    } catch (e) {
        // Ignore localStorage errors
    }

    // Auto-expand parent nav groups that contain active links
    document.querySelectorAll('.nav-link.active').forEach(activeLink => {
        let parent = activeLink.closest('.nav-group');
        while (parent) {
            parent.classList.add('show');
            parent = parent.parentElement.closest('.nav-group');
        }
    });
});

// ========================================
// Sidebar Toggle Function
// ========================================
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) {
        sidebar.classList.toggle('sidebar-narrow');

        // Save state to localStorage
        const isNarrow = sidebar.classList.contains('sidebar-narrow');
        localStorage.setItem('sidebarState', isNarrow ? 'narrow' : 'wide');
    }
}

// ========================================
// Theme Management - Force Dark Theme Always
// ========================================
// Always enforce dark theme on page load
document.addEventListener('DOMContentLoaded', function() {
    // Force dark theme
    document.documentElement.setAttribute('data-coreui-theme', 'dark');
    localStorage.setItem('theme', 'dark');

    // Restore sidebar state
    const sidebar = document.getElementById('sidebar');
    if (sidebar) {
        const savedState = localStorage.getItem('sidebarState');
        if (savedState === 'narrow') {
            sidebar.classList.add('sidebar-narrow');
        }
    }
});

// ========================================
// Export Functions (Placeholder)
// ========================================
function exportPDF() {
    // Check if PDF export is available on this page
    if (typeof window.print === 'function') {
        window.print();
    } else {
        alert('PDF export is not available on this page.');
    }
}

function exportCSV() {
    alert('CSV export functionality coming soon.');
}

function exportJSON() {
    alert('JSON export functionality coming soon.');
}
</script>
"""


def render_user_detail_js(user_details_json_str):
    """Embed the user-details JSON into USER_DETAIL_JS, escaped for the <script>
    context. json.dumps does not escape <, >, & -- so an attacker-controlled
    value (e.g. a cracked password containing a closing script tag) could
    otherwise break out of the script tag. Escaping them to their unicode form
    keeps the value inert JSON (the JS parser restores it at runtime)."""
    safe = (user_details_json_str
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e"))
    return USER_DETAIL_JS.replace("{USER_DATA_JSON}", safe)
