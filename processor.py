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

from core.config import reports_folder, html_reports_folder, markdown_folder, pdf_folder, ENABLE_ANIMATION
from core.data import process_domain
from core.domain_analysis import analyze_domain, analyze_cross_domain_sharing, shutdown_event

from reports.csv.report import write_csv_report
from reports.excel.report import write_actionable_excel
from reports.html.report import (generate_html_report, generate_html_actionable_report, 
                             generate_combined_html_report, generate_main_html, 
                             generate_search_html, generate_search_redacted_html)
from reports.markdown.report import (generate_markdown_report, generate_combined_report, 
                                 generate_actionable_report, generate_explained_actionable_report)
from visualizations.core import generate_visualizations, generate_combined_visualizations

from utils.file_utils import load_list, generate_pdfs_from_markdown
from utils.misc import (display_banner, print_success, 
                    print_info, print_warning, print_error, error_suppression)
from utils.terminal_animation import PasswordAuditAnimation
from collections import defaultdict

from rich.live import Live


def signal_handler(signum, frame):
    """Handle SIGINT (Ctrl+C) to gracefully shutdown."""
    print_warning("\nReceived CTRL+C, shutting down gracefully...")
    shutdown_event.set()
    sys.exit(0)


def process_single_domain(domain_entry, forbidden_words, keyboard_patterns, common_passwords, dictionary_words, seed, logger):
    """Process a single domain entry and generate reports."""
    try:
        domain, cracked_file, uncracked_file = domain_entry.split(':')
        cracked_accounts, uncracked_accounts = process_domain(domain, cracked_file, uncracked_file)
        
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
                               dictionary_words, logger)
        
        # Generate reports
        with error_suppression(logger.error):
            write_csv_report(domain, result['output_rows'])
            write_actionable_excel(domain, result['output_rows'], seed)
            
            visuals = generate_visualizations(domain, result)
            
            generate_markdown_report(domain, result, {k: v['png'] for k, v in visuals.items()})
            generate_html_report(domain, result, visuals, logger)  # Pass the entire visuals dict
            generate_actionable_report(domain, result, seed, logger)
            generate_explained_actionable_report(domain, result, seed, logger)
            generate_html_actionable_report(domain, result, seed, visuals, logger)  # Pass the entire visuals dict
        
        logger.info(f"Generated reports for {domain}")
        
        return domain_data['cracked'], domain_data['uncracked'], result
    except Exception as e:
        with error_suppression(logger.error):
            logger.error(f"Error processing domain {domain_entry}: {str(e)}", exc_info=True)
        return [], [], None


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


def process_domains(domain_entries, logger):
    """Process multiple domains and generate combined reports."""
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Ensure output directories exist
    os.makedirs(reports_folder, exist_ok=True)
    os.makedirs(html_reports_folder, exist_ok=True)
    
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
        domain_list = [d.split(':')[0] for d in domain_entries]
        all_data = {"domains": {}, "combined": {}}
        results = []
        
        # Process domains with animation
        if ENABLE_ANIMATION:
            # Initialize the animation with the domain list
            animation = PasswordAuditAnimation(domain_list)
            
            # Add initial findings
            animation.add_finding(
                f"Starting password security audit on {len(domain_list)} domains",
                "Medium"
            )
            animation.add_finding(
                "Loaded word lists for pattern detection",
                "Low"
            )
            
            with Live(animation.render(), refresh_per_second=10, screen=True) as live:
                # Process domains in parallel
                with ProcessPoolExecutor(max_workers=min(os.cpu_count(), 4)) as executor:
                    task_args = [(domain_entry, forbidden_words, keyboard_patterns, common_passwords, 
                                dictionary_words, global_seed, logger) for domain_entry in domain_entries]
                    
                    # Submit all tasks
                    futures = [executor.submit(process_domain_wrapper, arg) for arg in task_args]
                    
                    # Initial state - first domain
                    animation.set_domain_progress(0, 100)  # Start with a default value
                    animation.update()
                    
                    # Process results as they complete
                    for i, future in enumerate(concurrent.futures.as_completed(futures)):
                        try:
                            # Get the domain for the completed result
                            domain_entry = domain_entries[i]
                            domain = domain_entry.split(':')[0]
                            
                            if shutdown_event.is_set():
                                print_warning("Shutdown requested. Cancelling remaining tasks...")
                                animation.add_finding(
                                    "Shutdown requested - cancelling remaining tasks",
                                    "Critical"
                                )
                                animation.update()
                                executor.shutdown(wait=False, cancel_futures=True)
                                break
                            
                            # Get the result
                            result = future.result()
                            results.append(result)
                            
                            # Update animation with real data
                            cracked, uncracked, domain_data = result
                            
                            # Skip updating stats if no valid data
                            if not domain_data:
                                animation.add_finding(
                                    f"Failed to process domain {domain}",
                                    "Critical"
                                )
                                # Still mark this domain as complete to move to the next one
                                animation.complete_current_domain()
                                animation.update()
                                continue
                            
                            # Extract stats from the result
                            total_accounts = len(domain_data.get('output_rows', []))
                            cracked_count = sum(1 for row in domain_data.get('output_rows', []) 
                                              if row.get('Password Length', 'N/A') != 'N/A')
                            uncracked_count = total_accounts - cracked_count
                            
                            # Update global stats
                            animation.stats["total_accounts"] += total_accounts
                            animation.stats["analyzed_accounts"] += total_accounts
                            animation.stats["cracked_accounts"] += cracked_count
                            animation.stats["uncracked_accounts"] += uncracked_count
                            
                            # Update risk counts
                            risk_counter = domain_data.get('risk_counter', {})
                            animation.risk_counts["Critical"] += risk_counter.get('Critical', 0)
                            animation.risk_counts["High"] += risk_counter.get('High', 0)
                            animation.risk_counts["Medium"] += risk_counter.get('Medium', 0)
                            animation.risk_counts["Low"] += risk_counter.get('Low', 0)
                            
                            # Add findings based on real data
                            da_path_accounts = sum(1 for row in domain_data.get('output_rows', [])
                                                 if row.get('DA Domains', 'None') not in ('None', 'Unknown'))
                            animation.stats["da_pathway_accounts"] += da_path_accounts
                            
                            # Add compliance stats
                            out_of_compliance = sum(1 for row in domain_data.get('output_rows', [])
                                                 if row.get('Days Out of Compliance', 'N/A') not in ('N/A', 'Unknown')
                                                 and int(row.get('Days Out of Compliance', 0)) > 0)
                            animation.stats["compliance_issues"] += out_of_compliance
                            
                            # Add non-expiring stats
                            non_expiring = sum(1 for row in domain_data.get('output_rows', [])
                                             if row.get('Password Set to Expire', 'Yes') == 'No')
                            animation.stats["non_expiring_accounts"] += non_expiring
                            
                            # Mark current domain as complete and prepare for the next one
                            animation.complete_current_domain()
                            
                            # If there are more domains to process, set up the next one
                            if i + 1 < len(domain_entries):
                                next_domain_index = animation.current_domain_index
                                # Get an estimate of total accounts in next domain if possible
                                # For now we use a default of 100 which will be updated as we process
                                next_domain_accounts = 100
                                animation.set_domain_progress(next_domain_index, next_domain_accounts)
                            
                            # Add summary finding
                            animation.add_finding(
                                f"Completed {domain}: {cracked_count} cracked, {uncracked_count} uncracked",
                                "Medium"
                            )
                            
                            # Add significant findings
                            if da_path_accounts > 0:
                                animation.add_finding(
                                    f"Found {da_path_accounts} accounts with DA pathway in {domain}",
                                    "Critical" if da_path_accounts > 5 else "High"
                                )
                            
                            if out_of_compliance > 0:
                                animation.add_finding(
                                    f"Detected {out_of_compliance} out-of-compliance accounts in {domain}",
                                    "Medium"
                                )
                            
                            if non_expiring > 0:
                                animation.add_finding(
                                    f"Found {non_expiring} accounts with non-expiring passwords in {domain}",
                                    "Medium"
                                )
                            
                            # Find and report on any accounts with critical issues
                            critical_accounts = [row for row in domain_data.get('output_rows', [])
                                              if row.get('Risk Level') == 'Critical']
                            if critical_accounts:
                                animation.add_finding(
                                    f"Identified {len(critical_accounts)} critical risk accounts in {domain}",
                                    "Critical"
                                )
                            
                            # Password insight findings
                            password_insights = extract_password_insights(domain_data)
                            if password_insights:
                                for insight in password_insights[:2]:  # Limit to top 2 insights
                                    animation.add_finding(insight["message"], insight["severity"])
                            
                            # Update the animation
                            animation.update()
                            
                            # Short sleep to allow animation to update
                            time.sleep(0.1)
                            
                            # Print status message for logging
                            logger.info(f"Completed {domain} ({i+1}/{len(domain_entries)})")
                        except Exception as e:
                            logger.error(f"Error during domain processing: {str(e)}", exc_info=True)
                            print_error(f"Error processing {domain}: {str(e)}")
                            
                            # Update animation with error
                            animation.add_finding(
                                f"Error processing domain {domain}: {str(e)}",
                                "Critical"
                            )
                            animation.update()
                
                # Add finding for completion
                animation.add_finding(
                    f"Completed processing of all {len(domain_list)} domains",
                    "Medium"
                )
                animation.update()
                
                # Wait a moment for final animation update
                time.sleep(0.5)
                
        else:
            # Non-animation path (fallback for when animation is disabled)
            print_info("Processing domains...")
            try:
                # Process domains in parallel
                with ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
                    task_args = [(domain_entry, forbidden_words, keyboard_patterns, common_passwords, 
                                dictionary_words, global_seed, logger) for domain_entry in domain_entries]
                    results = list(executor.map(process_domain_wrapper, task_args))
            except Exception as e:
                with error_suppression(logger.error):
                    logger.error(f"Error during domain processing: {str(e)}", exc_info=True)
                results = []
            print_success("Domain processing complete")
    
        # Collect results
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
                        'banned_word_counter': dict(result['banned_word_counter'])
                    }
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
        with error_suppression(logger.error):
            display_banner("Cross-Domain Analysis")
            
            combined_rows, global_password_to_users, global_hash_to_users = analyze_cross_domain_sharing(
                all_cracked, all_uncracked, domain_list)
            
            combined_visuals = generate_combined_visualizations(
                combined_rows, global_password_to_users, global_hash_to_users)
            
            generate_combined_report(
                combined_rows, global_password_to_users, global_hash_to_users, 
                {k: v['png'] for k, v in combined_visuals.items()})
            
            generate_combined_html_report(
                    combined_rows, global_password_to_users, global_hash_to_users, 
                    combined_visuals, logger)
            
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
            json_file = html_reports_folder / 'password_data.json'
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
                if 'Password' in row and 'Password' in row:
                    password = row['Password']
                    if password not in global_hash_to_users:  # Only for cracked passwords
                        row['Password Placeholder'] = hashlib.md5((global_seed + password).encode()).hexdigest()
            
            json_file_with_placeholders = html_reports_folder / 'password_data_with_placeholders.json'
            with open(json_file_with_placeholders, 'w', encoding='utf-8') as f:
                json.dump(all_data_with_placeholders, f, indent=2)
            logger.info(f"Saved data with placeholders to JSON: {json_file_with_placeholders}")
            
            # Generate navigation pages
            generate_main_html(domain_list, logger)
            generate_search_html(json_file, logger)
            generate_search_redacted_html(json_file_with_placeholders, logger)
            
            print_success("All reports generated successfully")
        
        logger.info("All processing completed successfully")
        print_success("All processing completed successfully")
        
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