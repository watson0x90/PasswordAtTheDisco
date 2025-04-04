import argparse
from core.config import reports_folder, html_reports_folder, markdown_folder, pdf_folder, ENABLE_ANIMATION
from core.data import process_domain
from core.analysis import analyze_domain, analyze_cross_domain_sharing
from reports.csv_report import write_csv_report, write_actionable_excel
from reports.visualizations import generate_visualizations, generate_combined_visualizations
from reports.markdown_report import generate_markdown_report, generate_combined_report, generate_actionable_report, generate_explained_actionable_report
from reports.html_reports import generate_html_report, generate_combined_html_report, generate_html_actionable_report, generate_main_html, generate_search_html, generate_search_redacted_html
from utils.file_utils import load_list, generate_pdfs_from_markdown
from utils.misc import show_processing_animation
from utils.logging import setup_logging
import os
import http.server
import socketserver
from collections import defaultdict
import uuid
from concurrent.futures import ProcessPoolExecutor
import threading
import signal
import sys
from core.analysis import shutdown_event
from contextlib import redirect_stdout, redirect_stderr
import json
import hashlib

os.makedirs(reports_folder, exist_ok=True)
os.makedirs(html_reports_folder, exist_ok=True)

def signal_handler(signum, frame):
    print("\nReceived CTRL+C, shutting down gracefully...")
    shutdown_event.set()
    sys.exit(0)

def process_single_domain(domain_entry, forbidden_words, keyboard_patterns, common_passwords, dictionary_words, seed, logger):
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
        
        result = analyze_domain(domain, domain_data['cracked'], domain_data['uncracked'], domain_data['password_to_users'], domain_data['hash_to_users'], forbidden_words, keyboard_patterns, common_passwords, dictionary_words, logger)
        write_csv_report(domain, result['output_rows'])
        write_actionable_excel(domain, result['output_rows'], seed)
        visuals = generate_visualizations(domain, result)
        generate_markdown_report(domain, result, {k: v['png'] for k, v in visuals.items()})
        generate_html_report(domain, result, {k: v['html'] for k, v in visuals.items()}, logger)
        generate_actionable_report(domain, result, seed, logger)
        generate_explained_actionable_report(domain, result, seed, logger)
        generate_html_actionable_report(domain, result, seed, {k: v['html'] for k, v in visuals.items()}, logger)
        logger.info(f"Generated actionable report for {domain}")
        for orig_acc, enriched_acc in zip(domain_data['cracked'], result['enriched_cracked']):
            orig_acc.update(enriched_acc)
        
        for acc in domain_data['cracked']:
            acc['Domain'] = domain
        for acc in domain_data['uncracked']:
            acc['Domain'] = domain
        
        return domain_data['cracked'], domain_data['uncracked'], result
    except Exception as e:
        logger.error(f"Error processing domain {domain_entry}: {str(e)}", exc_info=True)
        return [], [], None

def process_domain_wrapper(args):
    return process_single_domain(*args)

def serve_html_reports(logger):
    PORT = 8000
    if not os.path.exists(html_reports_folder):
        logger.error(f"Directory {html_reports_folder} does not exist. Please run the audit first with -d to generate reports.")
        sys.exit(1)
    
    os.chdir(html_reports_folder)
    handler = http.server.SimpleHTTPRequestHandler
    
    with open(os.devnull, 'w') as null_file:
        with redirect_stdout(null_file), redirect_stderr(null_file):
            try:
                with socketserver.TCPServer(("", PORT), handler) as httpd:
                    logger.info(f"Serving HTML reports at http://localhost:{PORT}")
                    logger.info("Press Ctrl+C to stop the server")
                    httpd.serve_forever()
            except KeyboardInterrupt:
                logger.info("Server stopped.")
                sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='Audit password files across multiple domains.')
    parser.add_argument('-d', '--domains', nargs='+', help='Domain and files in format domain:cracked_file:uncracked_file')
    parser.add_argument('-p', '--pdf', action='store_true', help='Generate PDFs from existing Markdown reports')
    parser.add_argument('-s', '--serve', action='store_true', help='Serve the HTML reports folder using a local HTTP server')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0', help='Show program version and exit')
    args = parser.parse_args()

    logger = setup_logging()
    global_seed = str(uuid.uuid4())

    if args.serve:
        serve_html_reports(logger)
        return

    if args.pdf:
        try:
            generate_pdfs_from_markdown(markdown_folder, pdf_folder)
        except Exception as e:
            logger.error(f"Error generating PDFs: {str(e)}")
        return

    if args.domains:
        try:
            forbidden_words = load_list('lists/forbidden_words.txt')
            keyboard_patterns = load_list('lists/keyboard_patterns.txt')
            common_passwords = load_list('lists/common_passwords.txt')
            dictionary_words = load_list('lists/dictionary_words.txt')
        except Exception as e:
            logger.error(f"Error loading word lists: {str(e)}")
            sys.exit(1)

        all_cracked = []
        all_uncracked = []
        domain_list = [d.split(':')[0] for d in args.domains]
        all_data = {"domains": {}, "combined": {}}

        if ENABLE_ANIMATION:
            stop_event = threading.Event()
            animation_thread = threading.Thread(target=show_processing_animation, args=(stop_event,))
            animation_thread.start()
        else:
            print("Processing domains...")

        try:
            with ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
                task_args = [(domain_entry, forbidden_words, keyboard_patterns, common_passwords, dictionary_words, global_seed, logger) for domain_entry in args.domains]
                results = list(executor.map(process_domain_wrapper, task_args))
        except Exception as e:
            logger.error(f"Error during domain processing: {str(e)}", exc_info=True)
            results = []
        finally:
            if ENABLE_ANIMATION:
                stop_event.set()
                animation_thread.join()
            else:
                print("Processing domains... Done!")

        for cracked, uncracked, result in results:
            if result:
                domain = result['output_rows'][0]['Domain'] if result['output_rows'] else None
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

        logger.info(f"Processed {len(results)} domains, collected {len(all_cracked)} cracked, {len(all_uncracked)} uncracked accounts")

        if shutdown_event.is_set():
            print("Shutdown requested, exiting before combined report generation.")
            return

        combined_rows, global_password_to_users, global_hash_to_users = analyze_cross_domain_sharing(all_cracked, all_uncracked, domain_list)
        combined_visuals = generate_combined_visualizations(combined_rows, global_password_to_users, global_hash_to_users)
        generate_combined_report(combined_rows, global_password_to_users, global_hash_to_users, {k: v['png'] for k, v in combined_visuals.items()})
        generate_combined_html_report(combined_rows, global_password_to_users, global_hash_to_users, {k: v['html'] for k, v in combined_visuals.items()}, logger)
        write_csv_report('combined', combined_rows, is_combined=True)

        # Original JSON output with raw data
        all_data['combined'] = {
            'combined_rows': combined_rows,
            'global_password_to_users': {k: list(v) for k, v in global_password_to_users.items()},
            'global_hash_to_users': {k: list(v) for k, v in global_hash_to_users.items()},
            'all_cracked': all_cracked,
            'all_uncracked': all_uncracked
        }
        json_file = html_reports_folder / 'password_data.json'
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(all_data, f, indent=2)
        logger.info(f"Saved raw data to JSON: {json_file}")

        # New JSON output with password placeholders
        all_data_with_placeholders = {
            'combined': {
                'combined_rows': [
                    {**row, 'Password Placeholder': hashlib.md5((global_seed + row['Password']).encode()).hexdigest()} if 'Password' in row else row
                    for row in combined_rows
                ],
                'global_password_to_users': {k: list(v) for k, v in global_password_to_users.items()},
                'global_hash_to_users': {k: list(v) for k, v in global_hash_to_users.items()},
                'all_cracked': [
                    {**acc, 'Password Placeholder': hashlib.md5((global_seed + acc['password']).encode()).hexdigest()}
                    for acc in all_cracked
                ],
                'all_uncracked': all_uncracked
            }
        }
        json_file_with_placeholders = html_reports_folder / 'password_data_with_placeholders.json'
        with open(json_file_with_placeholders, 'w', encoding='utf-8') as f:
            json.dump(all_data_with_placeholders, f, indent=2)
        logger.info(f"Saved data with placeholders to JSON: {json_file_with_placeholders}")

        generate_main_html(domain_list, logger)
        generate_search_html(json_file, logger)
        generate_search_redacted_html(json_file_with_placeholders, logger)

    else:
        print("No arguments provided. Use -d/--domains to process domains, -p/--pdf to generate PDFs, or -s/--serve to serve HTML reports.")
        sys.exit(1)

if __name__ == '__main__':
    main()