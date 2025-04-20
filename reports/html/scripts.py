# reports/html/scripts.py
"""
JavaScript functions for HTML reports.
"""

# JavaScript for table sorting
TABLE_SORT_JS = """
<script>
function sortTable(table, colIndex, ascending) {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort((a, b) => {
        const aValue = a.cells[colIndex].textContent.trim();
        const bValue = b.cells[colIndex].textContent.trim();
        const aNum = parseFloat(aValue);
        const bNum = parseFloat(bValue);
        if (!isNaN(aNum) && !isNaN(bNum)) {
            return ascending ? aNum - bNum : bNum - aNum;
        }
        return ascending ? aValue.localeCompare(bValue) : bValue.localeCompare(aValue);
    });
    rows.forEach(row => tbody.appendChild(row));
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('table').forEach(table => {
        const headers = table.querySelectorAll('th');
        headers.forEach((th, index) => {
            let ascending = true;
            th.addEventListener('click', () => {
                sortTable(table, index, ascending);
                ascending = !ascending;
                headers.forEach(h => h.classList.remove('sorted-asc', 'sorted-desc'));
                th.classList.add(ascending ? 'sorted-desc' : 'sorted-asc');
            });
        });
    });
});
</script>
"""

# JavaScript for search functionality
SEARCH_JS = """
<script src="https://cdn.jsdelivr.net/npm/choices.js/public/assets/scripts/choices.min.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/choices.js/public/assets/styles/choices.min.css" />
<script>
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('searchInput');
    const resultsTable = document.getElementById('resultsTable');
    const tbody = resultsTable.querySelector('tbody');
    let allAccounts = [];
    let filters = {};
    let currentPage = 1;
    const rowsPerPage = 20;

    fetch('/password_data.json')
        .then(response => {
            if (!response.ok) throw new Error('Failed to load password_data.json');
            return response.json();
        })
        .then(data => {
            allAccounts = [
                ...data.combined.all_cracked.map(acc => ({ ...acc, Type: 'Cracked' })),
                ...data.combined.all_uncracked.map(acc => ({ ...acc, Type: 'Uncracked' }))
            ];
            initializeFilters();
            updateTable();
        })
        .catch(error => {
            console.error('Error loading JSON:', error);
            document.getElementById('errorMessage').textContent = 'Failed to load data. ' + error.message;
            document.getElementById('errorMessage').style.display = 'block';
        });

    searchInput.addEventListener('input', () => {
        currentPage = 1;
        updateTable();
    });

    function initializeFilters() {
        const headers = ['Username', 'Domain', 'Password', 'Type', 'Risk Level', 'Enabled', 'Last Logon Timestamp', 'Password Set to Expire', 'Controlled Object Count', 'DA Domains', 'Shared With', 'Last Password Set', 'Days Out of Compliance', 'Risk Vector'];
        headers.forEach(header => {
            const selectId = `filter-${header.replace(/[^a-zA-Z0-9]/g, '')}`;
            const th = document.querySelector(`th[data-column="${header}"]`);
            if (th) {
                th.innerHTML += `<select multiple id="${selectId}" class="filter-select"></select>`;
                
                const uniqueValues = [...new Set(allAccounts.map(acc => acc[header] || 'N/A'))].sort();
                const choicesOptions = uniqueValues.map(value => ({ value: value, label: value }));
                
                const select = document.getElementById(selectId);
                if (select) {
                    new Choices(select, {
                        removeItemButton: true,
                        choices: choicesOptions,
                        placeholderValue: 'Filter ' + header,
                        maxItemCount: -1
                    });
                    
                    select.addEventListener('change', () => {
                        filters[header] = Array.from(select.selectedOptions).map(opt => opt.value);
                        currentPage = 1;
                        updateTable();
                    });
                }
            }
        });
    }

    function updateTable() {
        const searchTerm = searchInput.value.trim().toLowerCase();
        tbody.innerHTML = '';
        
        const filtered = allAccounts.filter(acc => {
            const usernameField = acc.Username || acc.username || '';
            const matchesSearch = usernameField.toLowerCase().includes(searchTerm);
            const matchesFilters = Object.keys(filters).every(header => {
                if (!filters[header] || filters[header].length === 0) return true;
                const value = acc[header] || 'N/A';
                return filters[header].includes(value);
            });
            return matchesSearch && matchesFilters;
        });
        
        // Pagination
        const totalPages = Math.ceil(filtered.length / rowsPerPage);
        const startIndex = (currentPage - 1) * rowsPerPage;
        const paginatedData = filtered.slice(startIndex, startIndex + rowsPerPage);
        
        // Update table with paginated data
        paginatedData.forEach(acc => {
            const row = document.createElement('tr');
            const riskLevel = acc['Risk Level'] || 'Unknown';
            if (riskLevel) {
                row.classList.add('risk-' + riskLevel.toLowerCase());
            }
            row.innerHTML = `
                <td>${acc.Username || 'N/A'}</td>
                <td>${acc.Domain || 'N/A'}</td>
                <td>${acc.Password || 'N/A'}</td>
                <td>${acc.Type || 'N/A'}</td>
                <td>${acc['Risk Level'] || 'N/A'}</td>
                <td>${acc['Enabled'] || 'Unknown'}</td>
                <td>${acc['Last Logon Timestamp'] || 'Unknown'}</td>
                <td>${acc['Password Set to Expire'] || 'Unknown'}</td>
                <td>${acc['Controlled Object Count'] || 'N/A'}</td>
                <td>${acc['DA Domains'] ? (acc['DA Domains'] === 'None' ? 'No' : 'Yes') : 'No'}</td>
                <td>${acc['Shared With'] || '0'}</td>
                <td>${acc['Last Password Set'] || 'Unknown'}</td>
                <td>${acc['Days Out of Compliance'] || 'N/A'}</td>
                <td>${acc['Risk Vector'] || 'N/A'}</td>
            `;
            tbody.appendChild(row);
        });
        
        // Update pagination controls
        updatePagination(totalPages);
        
        // Show result count
        document.getElementById('resultCount').textContent = `Showing ${paginatedData.length} of ${filtered.length} results`;
    }
    
    // Function to update pagination controls
    function updatePagination(totalPages) {
        const paginationContainer = document.getElementById('pagination');
        paginationContainer.innerHTML = '';
        
        // Don't show pagination if less than 1 page
        if (totalPages <= 1) {
            return;
        }
        
        // Previous button
        const prevButton = document.createElement('button');
        prevButton.textContent = 'Previous';
        prevButton.disabled = currentPage === 1;
        prevButton.addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                updateTable();
            }
        });
        paginationContainer.appendChild(prevButton);
        
        // Page buttons (with limit and ellipsis for many pages)
        const maxButtons = 5;
        let startPage = Math.max(1, currentPage - Math.floor(maxButtons / 2));
        let endPage = Math.min(totalPages, startPage + maxButtons - 1);
        
        if (endPage - startPage < maxButtons - 1) {
            startPage = Math.max(1, endPage - maxButtons + 1);
        }
        
        // First page if not in range
        if (startPage > 1) {
            const firstButton = document.createElement('button');
            firstButton.textContent = '1';
            firstButton.addEventListener('click', () => {
                currentPage = 1;
                updateTable();
            });
            paginationContainer.appendChild(firstButton);
            
            if (startPage > 2) {
                const ellipsis = document.createElement('span');
                ellipsis.textContent = '...';
                paginationContainer.appendChild(ellipsis);
            }
        }
        
        // Page buttons
        for (let i = startPage; i <= endPage; i++) {
            const pageButton = document.createElement('button');
            pageButton.textContent = i;
            if (i === currentPage) {
                pageButton.classList.add('current-page');
            }
            pageButton.addEventListener('click', () => {
                currentPage = i;
                updateTable();
            });
            paginationContainer.appendChild(pageButton);
        }
        
        // Last page if not in range
        if (endPage < totalPages) {
            if (endPage < totalPages - 1) {
                const ellipsis = document.createElement('span');
                ellipsis.textContent = '...';
                paginationContainer.appendChild(ellipsis);
            }
            
            const lastButton = document.createElement('button');
            lastButton.textContent = totalPages;
            lastButton.addEventListener('click', () => {
                currentPage = totalPages;
                updateTable();
            });
            paginationContainer.appendChild(lastButton);
        }
        
        // Next button
        const nextButton = document.createElement('button');
        nextButton.textContent = 'Next';
        nextButton.disabled = currentPage === totalPages;
        nextButton.addEventListener('click', () => {
            if (currentPage < totalPages) {
                currentPage++;
                updateTable();
            }
        });
        paginationContainer.appendChild(nextButton);
    }
});
</script>
"""

# JavaScript for redacted search (modified version of SEARCH_JS)
SEARCH_REDACTED_JS = """
<script src="https://cdn.jsdelivr.net/npm/choices.js/public/assets/scripts/choices.min.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/choices.js/public/assets/styles/choices.min.css" />
<script>
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('searchInput');
    const resultsTable = document.getElementById('resultsTable');
    const tbody = resultsTable.querySelector('tbody');
    let allAccounts = [];
    let filters = {};
    let currentPage = 1;
    const rowsPerPage = 20;

    fetch('/password_data_with_placeholders.json')
        .then(response => {
            if (!response.ok) throw new Error('Failed to load password_data_with_placeholders.json');
            return response.json();
        })
        .then(data => {
            allAccounts = [
                ...data.combined.all_cracked.map(acc => ({ ...acc, Type: 'Cracked' })),
                ...data.combined.all_uncracked.map(acc => ({ ...acc, Type: 'Uncracked' }))
            ];
            initializeFilters();
            updateTable();
        })
        .catch(error => {
            console.error('Error loading JSON:', error);
            document.getElementById('errorMessage').textContent = 'Failed to load data. ' + error.message;
            document.getElementById('errorMessage').style.display = 'block';
        });

    searchInput.addEventListener('input', () => {
        currentPage = 1;
        updateTable();
    });

    function initializeFilters() {
        const headers = ['Username', 'Domain', 'Password Placeholder', 'Type', 'Risk Level', 'Enabled', 'Last Logon Timestamp', 'Password Set to Expire', 'Controlled Object Count', 'DA Domains', 'Shared With', 'Last Password Set', 'Days Out of Compliance', 'Risk Vector'];
        headers.forEach(header => {
            const selectId = `filter-${header.replace(/[^a-zA-Z0-9]/g, '')}`;
            const th = document.querySelector(`th[data-column="${header}"]`);
            if (th) {
                th.innerHTML += `<select multiple id="${selectId}" class="filter-select"></select>`;
                
                const uniqueValues = [...new Set(allAccounts.map(acc => acc[header] || 'N/A'))].sort();
                const choicesOptions = uniqueValues.map(value => ({ value: value, label: value }));
                
                const select = document.getElementById(selectId);
                if (select) {
                    new Choices(select, {
                        removeItemButton: true,
                        choices: choicesOptions,
                        placeholderValue: 'Filter ' + header,
                        maxItemCount: -1
                    });
                    
                    select.addEventListener('change', () => {
                        filters[header] = Array.from(select.selectedOptions).map(opt => opt.value);
                        currentPage = 1;
                        updateTable();
                    });
                }
            }
        });
    }

    function updateTable() {
        const searchTerm = searchInput.value.trim().toLowerCase();
        tbody.innerHTML = '';
        
        const filtered = allAccounts.filter(acc => {
            const usernameField = acc.Username || acc.username || '';
            const matchesSearch = usernameField.toLowerCase().includes(searchTerm);
            const matchesFilters = Object.keys(filters).every(header => {
                if (!filters[header] || filters[header].length === 0) return true;
                const value = acc[header] || 'N/A';
                return filters[header].includes(value);
            });
            return matchesSearch && matchesFilters;
        });
        
        // Pagination
        const totalPages = Math.ceil(filtered.length / rowsPerPage);
        const startIndex = (currentPage - 1) * rowsPerPage;
        const paginatedData = filtered.slice(startIndex, startIndex + rowsPerPage);
        
        // Update table with paginated data
        paginatedData.forEach(acc => {
            const row = document.createElement('tr');
            const riskLevel = acc['Risk Level'] || 'Unknown';
            if (riskLevel) {
                row.classList.add('risk-' + riskLevel.toLowerCase());
            }
            row.innerHTML = `
                <td>${acc.Username || 'N/A'}</td>
                <td>${acc.Domain || 'N/A'}</td>
                <td>${acc['Password Placeholder'] || 'N/A'}</td>
                <td>${acc.Type || 'N/A'}</td>
                <td>${acc['Risk Level'] || 'N/A'}</td>
                <td>${acc['Enabled'] || 'Unknown'}</td>
                <td>${acc['Last Logon Timestamp'] || 'Unknown'}</td>
                <td>${acc['Password Set to Expire'] || 'Unknown'}</td>
                <td>${acc['Controlled Object Count'] || 'N/A'}</td>
                <td>${acc['DA Domains'] ? (acc['DA Domains'] === 'None' ? 'No' : 'Yes') : 'No'}</td>
                <td>${acc['Shared With'] || '0'}</td>
                <td>${acc['Last Password Set'] || 'Unknown'}</td>
                <td>${acc['Days Out of Compliance'] || 'N/A'}</td>
                <td>${acc['Risk Vector'] || 'N/A'}</td>
            `;
            tbody.appendChild(row);
        });
        
        // Update pagination controls
        updatePagination(totalPages);
        
        // Show result count
        document.getElementById('resultCount').textContent = `Showing ${paginatedData.length} of ${filtered.length} results`;
    }
    
    // Function to update pagination controls
    function updatePagination(totalPages) {
        const paginationContainer = document.getElementById('pagination');
        paginationContainer.innerHTML = '';
        
        // Don't show pagination if less than 1 page
        if (totalPages <= 1) {
            return;
        }
        
        // Previous button
        const prevButton = document.createElement('button');
        prevButton.textContent = 'Previous';
        prevButton.disabled = currentPage === 1;
        prevButton.addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                updateTable();
            }
        });
        paginationContainer.appendChild(prevButton);
        
        // Page buttons (with limit and ellipsis for many pages)
        const maxButtons = 5;
        let startPage = Math.max(1, currentPage - Math.floor(maxButtons / 2));
        let endPage = Math.min(totalPages, startPage + maxButtons - 1);
        
        if (endPage - startPage < maxButtons - 1) {
            startPage = Math.max(1, endPage - maxButtons + 1);
        }
        
        // First page if not in range
        if (startPage > 1) {
            const firstButton = document.createElement('button');
            firstButton.textContent = '1';
            firstButton.addEventListener('click', () => {
                currentPage = 1;
                updateTable();
            });
            paginationContainer.appendChild(firstButton);
            
            if (startPage > 2) {
                const ellipsis = document.createElement('span');
                ellipsis.textContent = '...';
                paginationContainer.appendChild(ellipsis);
            }
        }
        
        // Page buttons
        for (let i = startPage; i <= endPage; i++) {
            const pageButton = document.createElement('button');
            pageButton.textContent = i;
            if (i === currentPage) {
                pageButton.classList.add('current-page');
            }
            pageButton.addEventListener('click', () => {
                currentPage = i;
                updateTable();
            });
            paginationContainer.appendChild(pageButton);
        }
        
        // Last page if not in range
        if (endPage < totalPages) {
            if (endPage < totalPages - 1) {
                const ellipsis = document.createElement('span');
                ellipsis.textContent = '...';
                paginationContainer.appendChild(ellipsis);
            }
            
            const lastButton = document.createElement('button');
            lastButton.textContent = totalPages;
            lastButton.addEventListener('click', () => {
                currentPage = totalPages;
                updateTable();
            });
            paginationContainer.appendChild(lastButton);
        }
        
        // Next button
        const nextButton = document.createElement('button');
        nextButton.textContent = 'Next';
        nextButton.disabled = currentPage === totalPages;
        nextButton.addEventListener('click', () => {
            if (currentPage < totalPages) {
                currentPage++;
                updateTable();
            }
        });
        paginationContainer.appendChild(nextButton);
    }
});
</script>
"""

# JavaScript for tab switching functionality
TAB_SWITCH_JS = """
<script>
function openTab(evt, tabName) {
    // Hide all tab content
    var tabcontent = document.getElementsByClassName("tab-content");
    for (var i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }
    
    // Remove active class from all tablinks
    var tablinks = document.getElementsByClassName("tablink");
    for (var i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
    }
    
    // Show the current tab and add active class to the button
    document.getElementById(tabName).style.display = "block";
    evt.currentTarget.className += " active";
}

function filterByRisk(riskLevel, button) {
    // Update button active state
    var buttons = button.parentNode.getElementsByClassName("filter-button");
    for (var i = 0; i < buttons.length; i++) {
        buttons[i].classList.remove("active");
    }
    button.classList.add("active");
    
    // Filter table rows
    var rows = button.closest(".table-container").querySelectorAll("tr.risk-row");
    for (var i = 0; i < rows.length; i++) {
        if (riskLevel === "all") {
            rows[i].style.display = "";
        } else {
            if (rows[i].classList.contains("risk-" + riskLevel.toLowerCase())) {
                rows[i].style.display = "";
            } else {
                rows[i].style.display = "none";
            }
        }
    }
}
</script>
"""

# JavaScript for loading domain data
DOMAIN_DATA_LOADER_JS = """
<script>
// Load data for domain cards
document.addEventListener('DOMContentLoaded', () => {
    // Try to load password_data.json if it exists
    fetch('./password_data.json')
        .then(response => {
            if (!response.ok) {
                throw new Error('Data file not found');
            }
            return response.json();
        })
        .then(data => {
            // Update domain cards with real data if available
            const domainCards = document.querySelectorAll('.domain-card');
            domainCards.forEach(card => {
                const domainName = card.querySelector('h3').textContent;
                const domainData = data.domains[domainName];
                
                if (domainData) {
                    // Count accounts
                    const accountCount = domainData.output_rows ? domainData.output_rows.length : 0;
                    
                    // Update the count display
                    const metricElement = card.querySelector('.metric');
                    if (metricElement && metricElement.textContent === '--') {
                        metricElement.textContent = accountCount.toString();
                    }
                    
                    // Add risk information if available
                    if (domainData.domain_risk) {
                        const riskScore = domainData.domain_risk.risk_score;
                        const riskLevel = domainData.domain_risk.overall_risk_level;
                        
                        // Insert risk info after metric-label
                        const metricLabel = card.querySelector('.metric-label');
                        if (metricLabel && !card.querySelector('.risk-info')) {
                            const riskElement = document.createElement('p');
                            riskElement.className = `risk-${riskLevel.toLowerCase()}`;
                            riskElement.textContent = `Risk Score: ${riskScore}/10.0 (${riskLevel})`;
                            metricLabel.insertAdjacentElement('afterend', riskElement);
                        }
                    }
                }
            });
        })
        .catch(error => {
            console.error('Error loading data:', error);
        });
});
</script>
"""