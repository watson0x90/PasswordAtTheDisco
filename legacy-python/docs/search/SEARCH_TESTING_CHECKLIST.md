# Search Interface Testing Checklist

## Prerequisites

- Flask server running (`python app.py`)
- At least one report with password data exists
- Browser with JavaScript enabled

## Manual Testing Checklist

### 1. Page Load
- [ ] Navigate to `/bootstrap/search`
- [ ] Verify page loads without errors (check console)
- [ ] Verify loading spinner appears briefly
- [ ] Verify data loads (statistics show non-zero counts)
- [ ] Verify all accounts displayed in results (no search query)

### 2. Search Functionality
- [ ] Type in search box - verify debouncing (wait 250ms before search)
- [ ] Search for username (e.g., "admin") - verify results
- [ ] Search for domain (e.g., "GHOST.CORP") - verify results
- [ ] Search for password (e.g., "password") - verify results
- [ ] Search for risk level (e.g., "critical") - verify results
- [ ] Verify matching terms are highlighted in yellow
- [ ] Clear search with X button - verify all results return
- [ ] Clear search with Escape key - verify all results return
- [ ] Search with no matches - verify empty state displays

### 3. Filter Functionality
- [ ] Click "Filter by Risk" dropdown
- [ ] Select "Critical Risk" - verify only critical accounts shown
- [ ] Select "High Risk" - verify only high risk accounts shown
- [ ] Select "Medium Risk" - verify only medium risk accounts shown
- [ ] Select "Low Risk" - verify only low risk accounts shown
- [ ] Select "All Risk Levels" - verify all accounts shown
- [ ] Combine search + filter - verify both apply

### 4. Domain Filtering (if multiple domains)
- [ ] Verify domain pills appear below search
- [ ] Click a domain pill - verify only that domain's accounts shown
- [ ] Click multiple domain pills - verify union of domains shown
- [ ] Click "All Domains" - verify all domains shown
- [ ] Combine search + domain filter - verify both apply

### 5. Sort Functionality
- [ ] Click "Sort Results" dropdown
- [ ] Select "Risk Score (High to Low)" - verify sorting correct
- [ ] Select "Risk Score (Low to High)" - verify sorting correct
- [ ] Select "Username (A-Z)" - verify alphabetical sorting
- [ ] Select "Domain (A-Z)" - verify domain sorting
- [ ] Verify active sort option has "active" class

### 6. Result Display
- [ ] Verify each result card shows:
  - [ ] Username with person icon
  - [ ] Domain badge
  - [ ] Risk level badge (colored correctly)
  - [ ] CVSS score
  - [ ] Password (if cracked) or "[Not Cracked]"
  - [ ] Policy violations as red badges
  - [ ] DA Path badge (if applicable)
  - [ ] HIBP breach badge (if applicable)
  - [ ] Controlled object count
  - [ ] Last password set date
  - [ ] Account enabled/disabled status
  - [ ] Shared password count
- [ ] Verify "View Details" button links to correct domain report
- [ ] Verify left border color matches risk level:
  - [ ] Critical = Red
  - [ ] High = Orange
  - [ ] Medium = Yellow
  - [ ] Low = Green

### 7. Statistics Dashboard
- [ ] Verify "Total Accounts" matches actual count
- [ ] Verify "Critical Risk" count is correct
- [ ] Verify "High Risk" count is correct
- [ ] Verify "Search Results" updates when searching/filtering

### 8. Keyboard Shortcuts
- [ ] Press Ctrl+K (or Cmd+K on Mac) - verify search input focused
- [ ] Type in search, press Escape - verify search cleared
- [ ] Tab through interface - verify logical tab order

### 9. Theme Switching
- [ ] Switch to Flatly (light) theme - verify:
  - [ ] Colors update correctly
  - [ ] Search input readable
  - [ ] Cards have appropriate contrast
  - [ ] Highlights visible
- [ ] Switch to Darkly (dark) theme - verify same
- [ ] Verify theme persists on page reload

### 10. Responsive Design
- [ ] Resize browser to mobile width (< 768px)
- [ ] Verify layout stacks vertically
- [ ] Verify search input full width
- [ ] Verify filters accessible
- [ ] Verify result cards readable
- [ ] Test on actual mobile device (if available)

### 11. Performance
- [ ] Search with 100+ accounts - verify < 100ms response
- [ ] Search with 1000+ accounts - verify still responsive
- [ ] Verify no console errors during heavy use
- [ ] Verify smooth scrolling with many results

### 12. Error Handling
- [ ] Delete password_data.json temporarily - verify error message
- [ ] Invalid run_id - verify error message
- [ ] Network error (simulate offline) - verify error message

### 13. Edge Cases
- [ ] Search with special characters (e.g., "@", ".", "$")
- [ ] Search with very long query (100+ characters)
- [ ] Account with no password (uncracked)
- [ ] Account with Unicode in username/password
- [ ] Account with very long password (30+ characters)
- [ ] Single domain (verify domain filter hidden)

### 14. Browser Compatibility
- [ ] Test in Chrome/Chromium
- [ ] Test in Firefox
- [ ] Test in Safari (if available)
- [ ] Test in Edge (if available)

## Automated Testing (Optional)

### FlexSearch Index
```javascript
// Test index creation
console.assert(flexSearchIndex !== undefined, 'FlexSearch index should be created');
console.assert(allAccounts.length > 0, 'Accounts should be loaded');
```

### Search Results
```javascript
// Test search returns results
const results = flexSearchIndex.search('admin');
console.assert(results.length > 0, 'Search should return results for "admin"');
```

### Filtering
```javascript
// Test risk level filter
currentFilters.riskLevel = 'Critical';
const filteredResults = applyFilters(allAccounts);
const allCritical = filteredResults.every(r => r.doc['Risk Level'] === 'Critical');
console.assert(allCritical, 'All filtered results should be Critical risk');
```

## Performance Benchmarks

| Operation | Target Time | Actual Time |
|-----------|-------------|-------------|
| Page load + data load | < 2s | _____ |
| FlexSearch index build | < 1s | _____ |
| Search query execution | < 100ms | _____ |
| Result rendering (100 items) | < 200ms | _____ |
| Filter application | < 50ms | _____ |
| Sort application | < 50ms | _____ |

## Known Issues / Limitations

- [ ] Virtual scrolling not implemented (may be slow with 10,000+ accounts)
- [ ] Autocomplete not implemented
- [ ] Export functionality not implemented
- [ ] Saved searches not implemented
- [ ] Search history not implemented

## Sign-Off

- [ ] All critical tests passing
- [ ] No console errors
- [ ] Performance acceptable
- [ ] Works in primary browser
- [ ] Mobile-friendly
- [ ] Theme switching works

**Tested by:** _________________
**Date:** _________________
**Browser/OS:** _________________
**Notes:** _________________
