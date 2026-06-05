# processor.py
#!/usr/bin/env python3
"""
Processor module for orchestrating password security analysis.
Coordinates data processing, analysis, and report generation.
"""

import os
import sys
import json
import uuid
import signal
import hashlib
import time
from concurrent.futures import ProcessPoolExecutor
import concurrent.futures
from copy import deepcopy

from core.config import (reports_folder, markdown_folder, pdf_folder, ENABLE_ANIMATION, create_report_directory)
from core.data import process_domain
from core.domain_analysis import analyze_domain, analyze_cross_domain_sharing, shutdown_event
import core.config as config_module

from report_lib.csv.report import write_csv_report

# Optional import for Excel (requires pandas)
try:
    from report_lib.excel.report import write_actionable_excel
except ImportError:
    write_actionable_excel = None
# SQLite functionality disabled - using standalone HTML reports instead
ReportWriter = None
from report_lib.markdown.report import (generate_markdown_report, generate_combined_report,
                                 generate_actionable_report, generate_explained_actionable_report)
# Add standalone HTML generation
from report_lib.standalone_html.single_domain import generate_html_report
from report_lib.standalone_html.combined import generate_combined_html_report, generate_main_html
from report_lib.standalone_html.actionable import generate_html_actionable_report
from report_lib.standalone_html.search import generate_search_html, generate_search_redacted_html
from report_lib.standalone_html.about import generate_about_html
from visualizations.core import generate_visualizations, generate_combined_visualizations

from utils.file_utils import load_list, generate_pdfs_from_markdown
from utils.misc import (display_banner, print_success, 
                    print_info, print_warning, print_error, error_suppression)
# Import terminal animation (with fallback if Rich not available)
try:
    from utils.terminal_animation import PasswordAuditAnimation
except ImportError:
    from utils.terminal_animation_simple import PasswordAuditAnimation
from collections import defaultdict


def signal_handler(signum, frame):
    """Handle SIGINT (Ctrl+C) to gracefully shutdown."""
    print_warning("\nReceived CTRL+C, shutting down gracefully...")
    shutdown_event.set()
    sys.exit(0)


def process_single_domain(domain_entry, forbidden_words, keyboard_patterns, common_passwords, dictionary_words, seed, logger, report_dirs=None, sqlite_writer=None):
    """Process a single domain entry and generate reports."""
    try:
        # If report_dirs provided, update config to use new directories
        if report_dirs:
            # Import all report modules that need patching
            import report_lib.csv.report as csv_mod
            try:
                import report_lib.excel.report as excel_mod
            except ImportError:
                excel_mod = None
            import report_lib.markdown.report as md_mod
            import report_lib.markdown.single_domain as md_single_mod
            import report_lib.markdown.combined as md_combined_mod
            import report_lib.markdown.actionable as md_actionable_mod
            import report_lib.markdown.components as md_comp_mod
            import visualizations.core as viz_mod

            # Patch CSV folder
            if hasattr(csv_mod, 'csv_folder'):
                csv_mod.csv_folder = report_dirs['csv_dir']

            # Patch Excel folder
            if excel_mod and hasattr(excel_mod, 'excel_folder'):
                excel_mod.excel_folder = report_dirs['excel_dir']

            # Patch Markdown folders in all markdown modules
            md_modules = [md_mod, md_single_mod, md_combined_mod, md_actionable_mod, md_comp_mod]
            for mod in md_modules:
                if hasattr(mod, 'markdown_folder'):
                    mod.markdown_folder = report_dirs['markdown_dir']

            # Patch visualizations folder for storing PNG files
            if hasattr(viz_mod, 'html_reports_folder'):
                viz_mod.html_reports_folder = report_dirs['html_dir']

        domain, cracked_file, uncracked_file = domain_entry.split(':')
        cracked_accounts, uncracked_accounts = process_domain(domain, cracked_file, uncracked_file)

        # Get domain-specific password policy
        from core.config import get_policy_for_domain
        domain_policy = get_policy_for_domain(domain)

        domain_data = {
            'cracked': cracked_accounts,
            'uncracked': uncracked_accounts,
            'password_to_users': defaultdict(list),
            'hash_to_users': defaultdict(list)
        }

        for acc in cracked_accounts:
            domain_data['password_to_users'][acc['password']].append(acc['username'])
        for acc in uncracked_accounts:
            domain_data['hash_to_users'][acc['hash']].append(acc['username'])

        result = analyze_domain(domain, domain_data['cracked'], domain_data['uncracked'],
                               domain_data['password_to_users'], domain_data['hash_to_users'],
                               forbidden_words, keyboard_patterns, common_passwords,
                               dictionary_words, logger, domain_policy=domain_policy)
        
        # Generate reports
        with error_suppression(logger.error):
            # Generate CSV and Excel reports
            write_csv_report(domain, result['output_rows'])
            if write_actionable_excel:
                write_actionable_excel(domain, result['output_rows'], seed)

            # Generate visualizations
            visuals = generate_visualizations(domain, result)

            # Add visualizations to the result
            result['visualizations'] = visuals

            # Generate Markdown reports
            generate_markdown_report(domain, result, {k: v['png'] for k, v in visuals.items()})
            generate_actionable_report(domain, result, seed, logger)
            generate_explained_actionable_report(domain, result, seed, logger)

            # Write to SQLite if writer provided
            if sqlite_writer:
                sqlite_writer.write_domain_data(
                    sqlite_writer.current_report_id,
                    domain,
                    result,
                    result['output_rows']
                )

                # Store visualizations in SQLite
                for viz_name, viz_data in visuals.items():
                    if 'plotly' in viz_data:
                        sqlite_writer.write_visualization(
                            sqlite_writer.current_report_id,
                            domain,
                            viz_name,
                            'plotly',
                            viz_data['plotly']
                        )

        logger.info(f"Generated reports for {domain}")
        
        return domain_data['cracked'], domain_data['uncracked'], result, len(cracked_accounts) + len(uncracked_accounts)
    except Exception as e:
        with error_suppression(logger.error):
            logger.error(f"Error processing domain {domain_entry}: {str(e)}", exc_info=True)
        return [], [], None, 0


def process_domain_wrapper(args):
    """Wrapper function for parallel processing with multiprocessing."""
    return process_single_domain(*args)


def generate_pdfs(logger):
    """Generate PDFs from existing Markdown reports."""
    try:
        display_banner("PDF Generation")
        generate_pdfs_from_markdown(markdown_folder, pdf_folder)
        print_success("PDF generation complete")
    except Exception as e:
        with error_suppression(logger.error):
            logger.error(f"Error generating PDFs: {str(e)}")


def count_accounts_in_domain(domain_entry):
    """Count accounts in a domain without processing them fully."""
    try:
        domain, cracked_file, uncracked_file = domain_entry.split(':')
        
        # Count cracked accounts
        cracked_count = 0
        if os.path.exists(cracked_file):
            with open(cracked_file, 'r', encoding='utf-8') as f:
                for _ in f:
                    cracked_count += 1
                    
        # Count uncracked accounts
        uncracked_count = 0
        if os.path.exists(uncracked_file):
            with open(uncracked_file, 'r', encoding='utf-8') as f:
                for _ in f:
                    uncracked_count += 1
                    
        return cracked_count + uncracked_count
    except Exception:
        return 100  # Default fallback count


def process_domains(domain_entries, logger):
    """Process multiple domains and generate combined reports."""
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Track start time for duration
    start_time = time.time()

    # Extract domain names for directory creation
    domain_list = [d.split(':')[0] for d in domain_entries]

    # Create timestamped report directory
    report_dirs = create_report_directory(domain_list)

    # Store directory paths for easy access
    base_dir = report_dirs['base_dir']
    run_id = report_dirs['run_id']

    # Override global config variables to use new directories for this run
    # Store originals to restore later if needed
    getattr(config_module, 'excel_folder', None)

    # Set new directories
    config_module.csv_folder = report_dirs['csv_dir']
    config_module.excel_folder = report_dirs['excel_dir']
    config_module.html_reports_folder = report_dirs['html_dir']
    config_module.markdown_folder = report_dirs['markdown_dir']
    config_module.pdf_folder = report_dirs['pdf_dir']

    # Initialize SQLite writer for this report
    # Use report-specific database path
    # Optional SQLite database setup
    if ReportWriter:
        try:
            from report_lib.sqlite.database import get_db_path
            db_path = get_db_path(run_id)
            sqlite_writer = ReportWriter(db_path)
            report_id = sqlite_writer.start_report(run_id, domain_list)
            logger.info(f"Created SQLite report with ID {report_id} at {db_path}")
        except ImportError:
            sqlite_writer = None
            report_id = None
    else:
        sqlite_writer = None
        report_id = None

    # Monkeypatch report modules to use new directories
    # This updates the already-imported config variables in report modules
    import report_lib.csv.report as csv_report_module
    try:
        import report_lib.excel.report as excel_report_module
    except ImportError:
        excel_report_module = None
    import report_lib.markdown.report as md_report_module
    import report_lib.markdown.single_domain as md_single_module
    import report_lib.markdown.components as md_components_module
    import visualizations.core as viz_core_module

    # Update CSV report module
    if hasattr(csv_report_module, 'csv_folder'):
        csv_report_module.csv_folder = report_dirs['csv_dir']

    # Update Excel report module
    if excel_report_module and hasattr(excel_report_module, 'excel_folder'):
        excel_report_module.excel_folder = report_dirs['excel_dir']

    # Update visualizations module (for PNG storage)
    if hasattr(viz_core_module, 'html_reports_folder'):
        viz_core_module.html_reports_folder = report_dirs['html_dir']

    # Update Markdown report modules
    for module in [md_report_module, md_single_module, md_components_module]:
        if hasattr(module, 'markdown_folder'):
            module.markdown_folder = report_dirs['markdown_dir']

    # Generate a global seed for password hashing
    global_seed = str(uuid.uuid4())

    # Display banner with domain count
    display_banner(f"Processing {len(domain_entries)} Domains")
    
    try:
        # Load word lists
        print_info("Loading word lists...")
        try:
            forbidden_words = load_list('lists/forbidden_words.txt')
            keyboard_patterns = load_list('lists/keyboard_patterns.txt')
            common_passwords = load_list('lists/common_passwords.txt')
            dictionary_words = load_list('lists/dictionary_words.txt')
            print_success("Word lists loaded successfully")
        except Exception as e:
            with error_suppression(logger.error):
                logger.error(f"Error loading word lists: {str(e)}")
            sys.exit(1)
    
        all_cracked = []
        all_uncracked = []
        all_data = {"domains": {}, "combined": {}}
        results = []
        total_accounts_processed = 0

        # Tracking for metadata
        hibp_breached_count = 0
        hibp_not_breached_count = 0
        risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        # Process domains with animation
        if ENABLE_ANIMATION:
            # Precount accounts in each domain for better progress reporting
            domain_account_counts = {}
            print_info("Counting accounts in each domain...")
            for i, domain_entry in enumerate(domain_entries):
                domain = domain_entry.split(':')[0]
                count = count_accounts_in_domain(domain_entry)
                domain_account_counts[domain] = count
                print_info(f"  {domain}: {count} accounts")
            
            # Initialize the simplified animation
            animation = PasswordAuditAnimation(domain_list)
            
            # Process domains in parallel
            with ProcessPoolExecutor(max_workers=min(os.cpu_count(), 4)) as executor:
                # Prepare all tasks
                task_args = [(domain_entry, forbidden_words, keyboard_patterns, common_passwords,
                            dictionary_words, global_seed, logger, report_dirs, sqlite_writer) for domain_entry in domain_entries]
                
                # Submit all tasks
                futures = [executor.submit(process_domain_wrapper, arg) for arg in task_args]
                
                # Keep track of which futures correspond to which domains
                future_to_domain_idx = {future: i for i, future in enumerate(futures)}
                {domain_list[i]: future for i, future in enumerate(futures)}
                
                # Initialize active domain tracking
                active_domains = set()
                
                # Start with the first N domains based on max_workers
                max_concurrent = min(len(futures), executor._max_workers)
                
                # Set up initial active domains
                for i in range(min(max_concurrent, len(domain_list))):
                    domain = domain_list[i]
                    active_domains.add(domain)
                    # Set domain as active with account count
                    animation.set_domain_active(domain, is_active=True, 
                                              total_accounts=domain_account_counts.get(domain, 100))
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(futures):
                    try:
                        # Get domain information
                        domain_idx = future_to_domain_idx[future]
                        domain_entry = domain_entries[domain_idx]
                        domain = domain_entry.split(':')[0]
                        
                        if shutdown_event.is_set():
                            print_warning("Shutdown requested. Cancelling remaining tasks...")
                            executor.shutdown(wait=False, cancel_futures=True)
                            break
                        
                        # Get the result
                        cracked, uncracked, domain_data, accounts_count = future.result()
                        results.append((cracked, uncracked, domain_data))
                        
                        # Mark domain as completed in animation
                        animation.mark_domain_completed(domain, accounts_count)
                        
                        # Remove from active domains
                        active_domains.remove(domain)
                        
                        # Update total accounts processed
                        total_accounts_processed += accounts_count
                        
                        # Find next domain to process
                        next_domain = None
                        for d in domain_list:
                            if (d not in active_domains and 
                                animation.domain_status.get(d) == "PENDING"):
                                next_domain = d
                                break
                        
                        # Set next domain as active if available
                        if next_domain:
                            active_domains.add(next_domain)
                            animation.set_domain_active(next_domain, is_active=True, 
                                                     total_accounts=domain_account_counts.get(next_domain, 100))
                        
                        # Print status message for logging
                        logger.info(f"Completed {domain} with {accounts_count} accounts ({animation.completed_domains}/{len(domain_entries)})")
                    except Exception as e:
                        logger.error(f"Error during domain processing: {str(e)}", exc_info=True)
                        print_error(f"Error processing {domain}: {str(e)}")
                        
                        # Mark domain as error
                        if domain in active_domains:
                            active_domains.remove(domain)
                        animation.mark_domain_error(domain)
            
            # Stop the animation tracker
            animation.tracker.stop()
                
        else:
            # Non-animation path (fallback for when animation is disabled)
            print_info("Processing domains...")
            try:
                # Process domains in parallel
                with ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
                    task_args = [(domain_entry, forbidden_words, keyboard_patterns, common_passwords,
                                dictionary_words, global_seed, logger, report_dirs, sqlite_writer) for domain_entry in domain_entries]
                    results = list(executor.map(process_domain_wrapper, task_args))
                    
                    # Count total accounts
                    for cracked, uncracked, _, count in results:
                        total_accounts_processed += count
                        all_cracked.extend(cracked)
                        all_uncracked.extend(uncracked)
                        
                    # Extract just the data results (first 3 elements)
                    results = [(c, u, d) for c, u, d, _ in results]
            except Exception as e:
                with error_suppression(logger.error):
                    logger.error(f"Error during domain processing: {str(e)}", exc_info=True)
                results = []
            print_success("Domain processing complete")
    
        # Collect results and aggregate statistics
        for i, (cracked, uncracked, result) in enumerate(results):
            if result:
                domain = None
                if result['output_rows']:
                    domain = result['output_rows'][0]['Domain']
                else:
                    domain = domain_list[i] if i < len(domain_list) else f"domain_{i}"

                if domain:
                    all_data['domains'][domain] = {
                        'output_rows': result['output_rows'],
                        'password_lengths': result['password_lengths'],
                        'risk_counter': dict(result['risk_counter']),
                        'issues_counter': dict(result['issues_counter']),
                        'complexity_counter': dict(result['complexity_counter']),
                        'banned_word_counter': dict(result['banned_word_counter']),
                        'visualizations': result.get('visualizations', {}),
                        'domain_risk': result.get('domain_risk', {})
                    }

                    # Aggregate risk counts
                    risk_counter = result.get('risk_counter', {})
                    for level in ['Critical', 'High', 'Medium', 'Low']:
                        risk_summary[level.lower()] += risk_counter.get(level, 0)

                    # Count HIBP stats
                    for row in result.get('output_rows', []):
                        if row.get('HIBP Breached') == 'Yes':
                            hibp_breached_count += 1
                        else:
                            hibp_not_breached_count += 1

            all_cracked.extend(cracked)
            all_uncracked.extend(uncracked)
    
        logger.info(f"Processed {len(results)} domains, collected {len(all_cracked)} cracked, "
                   f"{len(all_uncracked)} uncracked accounts")
        print_success(f"Processed {len(results)} domains, collected {len(all_cracked)} cracked, "
                     f"{len(all_uncracked)} uncracked accounts")
    
        # Check if shutdown was requested
        if shutdown_event.is_set():
            print_warning("Shutdown requested, exiting before combined report generation.")
            return
    
        # Generate combined reports
        print_info("Generating combined reports...")

        # Re-patch modules for combined report generation (in main process)
        import report_lib.csv.report as csv_mod
        import report_lib.markdown.combined as md_combined_mod
        import visualizations.core as viz_mod

        if hasattr(csv_mod, 'csv_folder'):
            csv_mod.csv_folder = report_dirs['csv_dir']
        if hasattr(md_combined_mod, 'markdown_folder'):
            md_combined_mod.markdown_folder = report_dirs['markdown_dir']
        if hasattr(viz_mod, 'html_reports_folder'):
            viz_mod.html_reports_folder = report_dirs['html_dir']

        # TEMPORARILY DISABLED error_suppression to debug HTML generation issues
        # with error_suppression(logger.error):
        if True:  # Maintain indentation structure
            display_banner("Cross-Domain Analysis")

            combined_rows, global_password_to_users, global_hash_to_users = analyze_cross_domain_sharing(
                all_cracked, all_uncracked, domain_list)

            combined_visuals = generate_combined_visualizations(
                combined_rows, global_password_to_users, global_hash_to_users)

            # Generate Markdown combined report
            generate_combined_report(
                combined_rows, global_password_to_users, global_hash_to_users,
                {k: v['png'] for k, v in combined_visuals.items()})

            # Write password shares to SQLite (if available)
            if sqlite_writer:
                sqlite_writer.write_password_shares(
                    report_id,
                    global_password_to_users,
                    global_hash_to_users
                )

                # Store combined visualizations in SQLite
                for viz_name, viz_data in combined_visuals.items():
                    if 'plotly' in viz_data:
                        sqlite_writer.write_visualization(
                            report_id,
                            None,  # No domain for combined visualizations
                            viz_name,
                            'plotly',
                            viz_data['plotly']
                        )

            write_csv_report('combined', combined_rows, is_combined=True)
            
            # Prepare enriched data for JSON files
            # Process raw cracked data to add enriched fields with standardized names
            enriched_cracked = []
            for acc in all_cracked:
                # Find the corresponding enriched data from domain results
                domain = acc.get('domain', 'Unknown')
                username = acc.get('username', '')
                password = acc.get('password', '')
                
                # Find matching enriched data from domain output rows
                enriched_data = None
                if domain in all_data['domains']:
                    for row in all_data['domains'][domain]['output_rows']:
                        if row.get('Username') == username and row.get('Password') == password:
                            enriched_data = row
                            break
                
                # Create new enriched record with standardized field names
                enriched_acc = {
                    'Username': username,
                    'Domain': domain,
                    'Password': password,
                    'Type': 'Cracked'
                }
                
                # Add all enriched fields if found
                if enriched_data:
                    for key, value in enriched_data.items():
                        if key not in enriched_acc:  # Don't overwrite existing fields
                            enriched_acc[key] = value
                else:
                    # Provide default values for essential fields
                    enriched_acc['Password Length'] = len(password) if password else 'N/A'
                    enriched_acc['Shared With'] = len(global_password_to_users.get(password, [])) - 1 if password else 0
                
                # Ensure essential fields exist with defaults
                enriched_acc['Risk Level'] = enriched_acc.get('Risk Level', 'Unknown')
                enriched_acc['Enabled'] = enriched_acc.get('Enabled', 'Unknown')
                enriched_acc['Last Logon Timestamp'] = enriched_acc.get('Last Logon Timestamp', 'Unknown')
                enriched_acc['Password Set to Expire'] = enriched_acc.get('Password Set to Expire', 'Unknown')
                enriched_acc['Controlled Object Count'] = enriched_acc.get('Controlled Object Count', 'Unknown')
                enriched_acc['DA Domains'] = enriched_acc.get('DA Domains', 'None')
                enriched_acc['Shared With'] = enriched_acc.get('Shared With', 0)
                enriched_acc['Last Password Set'] = enriched_acc.get('Last Password Set', 'Unknown')
                enriched_acc['Days Out of Compliance'] = enriched_acc.get('Days Out of Compliance', 'N/A')
                enriched_acc['Risk Vector'] = enriched_acc.get('Risk Vector', 'N/A')
                
                enriched_cracked.append(enriched_acc)
            
            # Process uncracked accounts similarly
            enriched_uncracked = []
            for acc in all_uncracked:
                domain = acc.get('domain', 'Unknown')
                username = acc.get('username', '')
                hash_value = acc.get('hash', '')
                
                # Find matching enriched data from domain output rows
                enriched_data = None
                if domain in all_data['domains']:
                    for row in all_data['domains'][domain]['output_rows']:
                        if row.get('Username') == username and row.get('Password Length', 'x') == 'N/A':
                            enriched_data = row
                            break
                
                # Create new enriched record
                enriched_acc = {
                    'Username': username,
                    'Domain': domain,
                    'Password': hash_value,
                    'Password Length': 'N/A',
                    'Type': 'Uncracked'
                }
                
                # Add enriched fields if found
                if enriched_data:
                    for key, value in enriched_data.items():
                        if key not in enriched_acc:
                            enriched_acc[key] = value
                else:
                    # Provide default values
                    enriched_acc['Shared With'] = len(global_hash_to_users.get(hash_value, [])) - 1 if hash_value else 0
                
                # Ensure essential fields with defaults
                enriched_acc['Risk Level'] = enriched_acc.get('Risk Level', 'Unknown')
                enriched_acc['Enabled'] = enriched_acc.get('Enabled', 'Unknown')
                enriched_acc['Last Logon Timestamp'] = enriched_acc.get('Last Logon Timestamp', 'Unknown')
                enriched_acc['Password Set to Expire'] = enriched_acc.get('Password Set to Expire', 'Unknown')
                enriched_acc['Controlled Object Count'] = enriched_acc.get('Controlled Object Count', 'Unknown')
                enriched_acc['DA Domains'] = enriched_acc.get('DA Domains', 'None')
                enriched_acc['Shared With'] = enriched_acc.get('Shared With', 0)
                enriched_acc['Last Password Set'] = enriched_acc.get('Last Password Set', 'Unknown')
                enriched_acc['Days Out of Compliance'] = enriched_acc.get('Days Out of Compliance', 'N/A')
                enriched_acc['Risk Vector'] = enriched_acc.get('Risk Vector', 'N/A')
                
                enriched_uncracked.append(enriched_acc)
            
            # Update the JSON data with enriched accounts
            all_data['combined'] = {
                'combined_rows': combined_rows,
                'global_password_to_users': {k: list(v) for k, v in global_password_to_users.items()},
                'global_hash_to_users': {k: list(v) for k, v in global_hash_to_users.items()},
                'all_cracked': enriched_cracked,
                'all_uncracked': enriched_uncracked
            }
            
            # Save enriched data to JSON
            json_file = report_dirs['html_dir'] / 'password_data.json'
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(all_data, f, indent=2)
            logger.info(f"Saved enriched data to JSON: {json_file}")

            # Create redacted version with password placeholders
            all_data_with_placeholders = deepcopy(all_data)

            # Replace passwords with placeholders in all_cracked
            for acc in all_data_with_placeholders['combined']['all_cracked']:
                if 'Password' in acc:
                    password = acc['Password']
                    acc['Password Placeholder'] = hashlib.md5((global_seed + password).encode()).hexdigest()
                    # Keep the password for reference but mark it as placeholder

            # Also add placeholders to combined rows
            for row in all_data_with_placeholders['combined']['combined_rows']:
                if 'Password' in row and row['Password'] not in global_hash_to_users:  # Only for cracked passwords
                    password = row['Password']
                    row['Password Placeholder'] = hashlib.md5((global_seed + password).encode()).hexdigest()

            json_file_with_placeholders = report_dirs['html_dir'] / 'password_data_with_placeholders.json'
            with open(json_file_with_placeholders, 'w', encoding='utf-8') as f:
                json.dump(all_data_with_placeholders, f, indent=2)
            logger.info(f"Saved data with placeholders to JSON: {json_file_with_placeholders}")

            # Generate static HTML reports
            logger.info("Generating static HTML reports...")

            # Generate main landing page
            try:
                generate_main_html(domain_list, all_data['domains'], logger)
                logger.info("Generated main HTML landing page")
            except Exception as e:
                logger.error(f"Failed to generate main HTML page: {e}")

            # Generate individual domain reports and actionable reports
            for domain in domain_list:
                if domain in all_data['domains']:
                    result = all_data['domains'][domain]
                    visuals = result.get('visualizations', {})
                    try:
                        # Generate full domain report
                        generate_html_report(domain, result, visuals, logger)
                        logger.info(f"Generated HTML report for {domain}")

                        # Generate actionable report for this domain
                        generate_html_actionable_report(domain, result, global_seed, visuals, logger)
                        logger.info(f"Generated actionable HTML report for {domain}")
                    except Exception as e:
                        logger.error(f"Failed to generate HTML reports for {domain}: {e}")

            # Generate combined report
            try:
                generate_combined_html_report(combined_rows, global_password_to_users,
                                             global_hash_to_users,
                                             {'combined_visualizations': all_data.get('combined_visualizations', {})},
                                             logger)
                logger.info("Generated combined HTML report")
            except Exception as e:
                logger.error(f"Failed to generate combined HTML report: {e}")

            # Note: Individual domain actionable reports are generated above with domain reports
            # No need for a separate combined actionable report here

            # Generate search pages
            try:
                generate_search_html(json_file, logger)
                generate_search_redacted_html(json_file_with_placeholders, logger)
                logger.info("Generated search HTML pages")
            except Exception as e:
                logger.error(f"Failed to generate search HTML pages: {e}")

            # Generate about page
            try:
                about_metadata = {
                    'timestamp': report_dirs['timestamp'],
                    'domains': domain_list,
                    'version': '1.0.0',
                    'total_accounts': len(all_cracked) + len(all_uncracked),
                    'cracked_accounts': len(all_cracked),
                    'uncracked_accounts': len(all_uncracked),
                    'tool_name': 'Password!AtTheDisco'
                }
                generate_about_html(about_metadata, domain_list, logger)
                logger.info("Generated about HTML page")
            except Exception as e:
                logger.error(f"Failed to generate about HTML page: {e}")

            # Generate executive summary
            try:
                from report_lib.executive.summary import generate_executive_summary
                executive_metadata = {
                    'run_id': report_dirs['run_id'],
                    'timestamp': report_dirs['timestamp'],
                    'domains': domain_list,
                    'total_accounts': len(all_cracked) + len(all_uncracked),
                    'cracked_accounts': len(all_cracked),
                    'uncracked_accounts': len(all_uncracked)
                }
                generate_executive_summary(all_data['domains'], executive_metadata, logger)
                logger.info("Generated executive summary report")
            except Exception as e:
                logger.error(f"Failed to generate executive summary: {e}")

            print_success("All reports generated successfully")

        # Calculate duration
        duration_seconds = time.time() - start_time

        # Generate metadata.json
        metadata = {
            "run_id": run_id,
            "timestamp": report_dirs['timestamp'],
            "domains": domain_list,
            "total_accounts": len(all_cracked) + len(all_uncracked),
            "cracked_accounts": len(all_cracked),
            "uncracked_accounts": len(all_uncracked),
            "risk_summary": risk_summary,
            "hibp_breached": hibp_breached_count,
            "hibp_not_breached": hibp_not_breached_count,
            "hibp_enabled": True,  # Assume enabled if we have counts
            "bloodhound_enabled": True,  # Assume enabled
            "duration_seconds": duration_seconds,
            "output_dir": str(base_dir),
            "base_dir": str(base_dir)
        }

        # Finalize SQLite report
        if sqlite_writer:
            sqlite_writer.finalize_report(report_id, metadata)
        logger.info(f"Finalized SQLite report {run_id}")

        # Write metadata.json (for backward compatibility)
        metadata_file = base_dir / 'metadata.json'
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)
        logger.info(f"Saved metadata to {metadata_file}")

        # Move log file to report directory
        try:
            import glob
            from shutil import copy2
            # Find the most recent log file
            log_files = glob.glob(str(reports_folder.parent / 'output' / 'audit_*.log'))
            if log_files:
                latest_log = max(log_files, key=os.path.getctime)
                dest_log = base_dir / 'audit.log'
                copy2(latest_log, dest_log)
                logger.info(f"Copied log file to {dest_log}")
        except Exception as e:
            logger.warning(f"Could not copy log file: {e}")

        logger.info("All processing completed successfully")
        print_success("All processing completed successfully")

        # Return metadata for potential use by main.py
        return metadata
        
    except Exception as e:
        with error_suppression(logger.error):
            logger.error(f"Critical error in process_domains: {str(e)}", exc_info=True)
        print_error("A critical error occurred during processing. Check logs for details.")


def extract_password_insights(domain_data):
    """
    Extract interesting insights from password data for reporting.
    
    Args:
        domain_data (dict): Processed domain data
        
    Returns:
        list: List of insight dictionaries with message and severity
    """
    insights = []
    
    # Check complexity distribution
    complexity_counter = domain_data.get('complexity_counter', {})
    if complexity_counter:
        # Find the most common complexity type
        most_common = max(complexity_counter.items(), key=lambda x: x[1])
        complexity_type, count = most_common
        
        # Map complexity to human-readable format
        complexity_readable = {
            'loweralpha': 'lowercase letters only',
            'upperalpha': 'uppercase letters only',
            'numeric': 'numbers only',
            'mixedalphaspecialnum': 'strong (mixed case, numbers, symbols)',
            'loweralphanum': 'lowercase letters and numbers'
        }.get(complexity_type, complexity_type)
        
        total = sum(complexity_counter.values())
        percentage = (count / total) * 100 if total > 0 else 0
        
        # Determine severity
        if complexity_type in ['numeric', 'loweralpha', 'upperalpha']:
            severity = "High"
        elif complexity_type in ['loweralphanum', 'upperalphanum']:
            severity = "Medium"
        else:
            severity = "Low"
            
        insights.append({
            "message": f"{percentage:.1f}% of passwords use {complexity_readable}",
            "severity": severity
        })
    
    # Check common password issues
    issues_counter = domain_data.get('issues_counter', {})
    if issues_counter:
        # Find the most common issue
        most_common_issue = max(issues_counter.items(), key=lambda x: x[1])
        issue, count = most_common_issue
        
        insights.append({
            "message": f"Found {count} accounts with issue: {issue}",
            "severity": "Medium"
        })
    
    # Check banned words
    banned_word_counter = domain_data.get('banned_word_counter', {})
    if banned_word_counter:
        # Find the most common banned word
        top_words = sorted(banned_word_counter.items(), key=lambda x: x[1], reverse=True)[:3]
        if top_words:
            word, count = top_words[0]
            
            insights.append({
                "message": f"Common banned word found: '{word}' (used {count} times)",
                "severity": "High"
            })
    
    # Check password lengths
    password_lengths = domain_data.get('password_lengths', [])
    if password_lengths:
        avg_length = sum(password_lengths) / len(password_lengths) if password_lengths else 0
        min_length = min(password_lengths) if password_lengths else 0
        
        if min_length < 8:
            insights.append({
                "message": f"Shortest password is only {min_length} characters (average: {avg_length:.1f})",
                "severity": "Critical" if min_length < 6 else "High"
            })
        elif avg_length < 10:
            insights.append({
                "message": f"Average password length is only {avg_length:.1f} characters",
                "severity": "Medium"
            })
    
    return insights