# HTML Report Generation Module

This module handles the generation of interactive HTML reports for the password security audit tool.

## Structure

The module has been refactored into a more maintainable structure:

- `__init__.py`: Exports all public functions
- `report.py`: Main entry point that imports and coordinates the other modules
- `styles.py`: CSS styles and styling constants
- `scripts.py`: JavaScript functions and utilities
- `components.py`: Reusable HTML components (headers, tables, explanation blocks)
- `single_domain.py`: Single domain report generation
- `actionable.py`: Actionable report generation
- `combined.py`: Combined/cross-domain report generation and main dashboard
- `search.py`: Search functionality

## Main Functions

- `generate_html_report()`: Creates detailed reports for individual domains
- `generate_html_actionable_report()`: Creates actionable reports for individual domains
- `generate_combined_html_report()`: Creates cross-domain analysis reports
- `generate_main_html()`: Creates the main dashboard page
- `generate_search_html()`: Creates the search page
- `generate_search_redacted_html()`: Creates the redacted search page

## Design Principles

1. **Separation of Concerns**: Each file has a clear and specific responsibility
2. **Reusability**: Common components and styles are centralized for reuse
3. **Error Handling**: All functions include robust error handling
4. **Consistent Interfaces**: Functions maintain consistent parameter interfaces

## Customization

- Modify `styles.py` to change the visual appearance
- Modify `scripts.py` to change interactive behaviors
- Modify `components.py` to change reusable HTML blocks
- Each report type can be modified independently in its respective file

## Usage

```python
from reports.html import (
    generate_html_report, 
    generate_html_actionable_report,
    generate_combined_html_report, 
    generate_main_html
)

# Generate a standard report for a domain
generate_html_report('example.com', domain_data, visuals, logger)

# Generate an actionable report
generate_html_actionable_report('example.com', domain_data, seed, visuals, logger)

# Generate a combined cross-domain report
generate_combined_html_report(combined_rows, global_password_to_users, 
                             global_hash_to_users, visuals, logger)

# Generate the main dashboard
generate_main_html(domains, logger)
```