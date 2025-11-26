#!/usr/bin/env python3
"""
LFIBay - Automated LFI Testing Tool
Main entry point and orchestration
"""

import os
import sys
from datetime import datetime

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import auth, scanner, analyzer
from utils import logger, config, reporter


def load_payloads():
    """
    Load all payloads from payload files
    Returns: List of payload strings
    """
    payloads = []
    
    for payload_type, filename in config.PAYLOAD_FILES.items():
        filepath = os.path.join(os.path.dirname(__file__), filename)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                file_payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                payloads.extend(file_payloads)
                logger.log_success(f"Loaded {len(file_payloads)} payloads from {payload_type}")
        except FileNotFoundError:
            logger.log_warning(f"Payload file not found: {filename}")
        except Exception as e:
            logger.log_error(f"Error loading {filename}: {str(e)}")
    
    return payloads


def progress_callback(current, total, result):
    """
    Callback function for progress updates during scanning
    """
    payload = result.get('payload', 'N/A')
    
    # Show progress bar
    logger.progress_bar(current, total, 'Testing Payloads')
    
    # Check if vulnerable
    detection = analyzer.analyze_response(result, payload)
    if detection['vulnerable']:
        logger.log_vulnerable(f"Payload: {payload[:60]}... | Confidence: {detection['confidence']}")


def main():
    """
    Main function - orchestrates the entire workflow
    """
    try:
        # Print banner
        logger.print_banner()
        
        # Step 1: Get login URL
        logger.print_header("STEP 1: AUTHENTICATION")
        login_url = input(f"{logger.Fore.CYAN}[?] Enter login URL: {logger.Style.RESET_ALL}").strip()
        
        if not login_url:
            logger.log_error("Login URL is required")
            return
        
        # Step 2: Get upload form URL
        upload_url = input(f"{logger.Fore.CYAN}[?] Enter upload form URL: {logger.Style.RESET_ALL}").strip()
        
        if not upload_url:
            logger.log_error("Upload URL is required")
            return
        
        logger.print_separator()
        
        # Step 3: Selenium authentication
        logger.log_info("Starting browser for authentication...")
        
        try:
            session_data = auth.get_session_data(login_url, upload_url)
            
            logger.log_success(f"Cookies extracted: {len(session_data['cookies'])} cookies")
            
            if session_data['waf_detected']:
                logger.log_warning(f"WAF detected: {session_data['waf_name']}")
            else:
                logger.log_info("No WAF detected")
            
            logger.log_success("Browser closed")
            
        except Exception as e:
            logger.log_error(f"Authentication failed: {str(e)}")
            return
        
        logger.print_separator()
        
        # Step 4: Detect form fields
        logger.print_header("STEP 2: FORM ANALYSIS")
        logger.log_info("Detecting form fields...")
        
        try:
            form_info = scanner.detect_form_fields(upload_url, session_data['cookies'])
            
            if not form_info:
                logger.log_error("No form found on the page")
                return
            
            field_names = list(form_info['fields'].keys())
            logger.log_success(f"Found fields: {', '.join(field_names)}")
            logger.log_info(f"Form action: {form_info['action']}")
            logger.log_info(f"Form method: {form_info['method']}")
            
        except Exception as e:
            logger.log_error(f"Form detection failed: {str(e)}")
            return
        
        logger.print_separator()
        
        # Step 5: Load payloads
        logger.print_header("STEP 3: PAYLOAD LOADING")
        logger.log_info("Loading payloads from files...")
        
        payloads = load_payloads()
        
        if not payloads:
            logger.log_error("No payloads loaded")
            return
        
        logger.log_success(f"Total payloads loaded: {len(payloads)}")
        
        logger.print_separator()
        
        # Step 6: Establish baseline
        logger.log_info("Establishing baseline metrics...")
        
        try:
            baseline = analyzer.baseline_request(
                upload_url,
                session_data['cookies'],
                session_data['headers'],
                form_info,
                scanner
            )
            logger.log_success(f"Baseline established: {baseline['content_length']} bytes, {baseline['response_time']:.2f}s")
        except Exception as e:
            logger.log_warning(f"Could not establish baseline: {str(e)}")
            baseline = None
        
        logger.print_separator()
        
        # Step 7: Test payloads
        logger.print_header("STEP 4: PAYLOAD TESTING")
        logger.log_info(f"Starting tests with {config.DEFAULT_MIN_DELAY}-{config.DEFAULT_MAX_DELAY}s delay...")
        print()
        
        try:
            results = scanner.batch_test(
                upload_url,
                payloads,
                form_info,
                session_data['cookies'],
                session_data['headers'],
                delay_min=config.DEFAULT_MIN_DELAY,
                delay_max=config.DEFAULT_MAX_DELAY,
                progress_callback=progress_callback
            )
            
            print()  # New line after progress bar
            logger.log_success("Testing complete!")
            
        except KeyboardInterrupt:
            print()
            logger.log_warning("Testing interrupted by user")
            return
        except Exception as e:
            logger.log_error(f"Testing failed: {str(e)}")
            return
        
        logger.print_separator()
        
        # Step 8: Analyze results
        logger.print_header("STEP 5: ANALYSIS")
        logger.log_info("Analyzing responses for vulnerabilities...")
        
        findings = analyzer.generate_findings(results, baseline)
        
        logger.log_success(f"Found {len(findings)} successful payloads")
        
        # Print findings summary
        logger.print_findings_summary(findings)
        
        logger.print_separator()
        
        # Step 9: Generate reports
        logger.print_header("STEP 6: REPORT GENERATION")
        logger.log_info("Generating reports...")
        
        metadata = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target_url': upload_url,
            'login_url': login_url,
            'total_payloads': len(payloads),
            'waf_detected': session_data['waf_detected'],
            'waf_name': session_data['waf_name'],
            'baseline': baseline
        }
        
        try:
            report_paths = reporter.generate_reports(findings, metadata)
            
            logger.log_success(f"JSON report saved: {report_paths['json']}")
            logger.log_success(f"HTML report saved: {report_paths['html']}")
            
        except Exception as e:
            logger.log_error(f"Report generation failed: {str(e)}")
        
        logger.print_separator()
        
        # Final summary
        logger.print_header("SCAN COMPLETE")
        
        if findings:
            high_findings = [f for f in findings if f['confidence'] == 'high']
            if high_findings:
                logger.log_warning(f"⚠️  {len(high_findings)} HIGH CONFIDENCE vulnerabilities detected!")
            else:
                logger.log_info("Vulnerabilities detected - review the report for details")
        else:
            logger.log_info("No vulnerabilities detected with the tested payloads")
        
        print()
        logger.log_success("Thank you for using LFIBay!")
        print()
        
    except KeyboardInterrupt:
        print()
        logger.log_warning("Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.log_error(f"Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
