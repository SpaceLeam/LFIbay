"""
LFIBay - Reporter Module
Generate JSON and HTML reports
"""

import json
import os
from datetime import datetime


def generate_json_report(findings, metadata):
    """
    Generate JSON report
    Args:
        findings: List of finding dictionaries
        metadata: Dictionary with scan metadata
    Returns: JSON string
    """
    report = {
        'scan_metadata': metadata,
        'summary': {
            'total_findings': len(findings),
            'high_confidence': len([f for f in findings if f['confidence'] == 'high']),
            'medium_confidence': len([f for f in findings if f['confidence'] == 'medium']),
            'low_confidence': len([f for f in findings if f['confidence'] == 'low']),
        },
        'findings': findings
    }
    
    return json.dumps(report, indent=2)


def generate_html_report(findings, metadata):
    """
    Generate HTML report with findings
    Args:
        findings: List of finding dictionaries
        metadata: Dictionary with scan metadata
    Returns: HTML string
    """
    timestamp = metadata.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    target_url = metadata.get('target_url', 'N/A')
    total_payloads = metadata.get('total_payloads', 0)
    waf_detected = metadata.get('waf_detected', False)
    waf_name = metadata.get('waf_name', 'Unknown')
    
    # Count findings by confidence
    high = len([f for f in findings if f['confidence'] == 'high'])
    medium = len([f for f in findings if f['confidence'] == 'medium'])
    low = len([f for f in findings if f['confidence'] == 'low'])
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LFIBay Report - {timestamp}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        
        header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .metadata {{
            background: #f8f9fa;
            padding: 20px 30px;
            border-bottom: 2px solid #e9ecef;
        }}
        
        .metadata-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }}
        
        .metadata-item {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }}
        
        .metadata-item strong {{
            display: block;
            color: #667eea;
            margin-bottom: 5px;
            font-size: 0.9em;
        }}
        
        .summary {{
            padding: 30px;
            background: white;
        }}
        
        .summary h2 {{
            color: #1e3c72;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }}
        
        .stat-card.high {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }}
        
        .stat-card.medium {{
            background: linear-gradient(135deg, #ffd89b 0%, #ff9a56 100%);
        }}
        
        .stat-card.low {{
            background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
        }}
        
        .stat-card h3 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .stat-card p {{
            font-size: 1em;
            opacity: 0.9;
        }}
        
        .findings {{
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .findings h2 {{
            color: #1e3c72;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        
        .finding {{
            background: white;
            margin-bottom: 20px;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 5px solid #667eea;
        }}
        
        .finding.high {{
            border-left-color: #f5576c;
        }}
        
        .finding.medium {{
            border-left-color: #ff9a56;
        }}
        
        .finding.low {{
            border-left-color: #4fc3f7;
        }}
        
        .finding-header {{
            padding: 20px;
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .finding-header h3 {{
            color: #333;
            margin-bottom: 10px;
            word-break: break-all;
        }}
        
        .confidence-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .confidence-badge.high {{
            background: #f5576c;
            color: white;
        }}
        
        .confidence-badge.medium {{
            background: #ff9a56;
            color: white;
        }}
        
        .confidence-badge.low {{
            background: #4fc3f7;
            color: white;
        }}
        
        .finding-body {{
            padding: 20px;
        }}
        
        .finding-section {{
            margin-bottom: 15px;
        }}
        
        .finding-section h4 {{
            color: #667eea;
            margin-bottom: 8px;
            font-size: 0.95em;
        }}
        
        .finding-section ul {{
            list-style: none;
            padding-left: 0;
        }}
        
        .finding-section li {{
            padding: 5px 0;
            padding-left: 20px;
            position: relative;
        }}
        
        .finding-section li:before {{
            content: "→";
            position: absolute;
            left: 0;
            color: #667eea;
        }}
        
        .code-block {{
            background: #282c34;
            color: #abb2bf;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        footer {{
            background: #1e3c72;
            color: white;
            padding: 20px;
            text-align: center;
        }}
        
        .warning {{
            background: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 30px;
        }}
        
        .warning strong {{
            display: block;
            margin-bottom: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 LFIBay Security Report</h1>
            <p>Local File Inclusion Vulnerability Assessment</p>
        </header>
        
        <div class="warning">
            <strong>⚠️ Confidential Security Report</strong>
            This report contains sensitive security information. Handle with care and share only with authorized personnel.
        </div>
        
        <div class="metadata">
            <div class="metadata-grid">
                <div class="metadata-item">
                    <strong>Scan Date</strong>
                    <div>{timestamp}</div>
                </div>
                <div class="metadata-item">
                    <strong>Target URL</strong>
                    <div>{target_url}</div>
                </div>
                <div class="metadata-item">
                    <strong>Total Payloads Tested</strong>
                    <div>{total_payloads}</div>
                </div>
                <div class="metadata-item">
                    <strong>WAF Detection</strong>
                    <div>{'Yes - ' + waf_name if waf_detected else 'No WAF detected'}</div>
                </div>
            </div>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <h3>{len(findings)}</h3>
                    <p>Total Vulnerabilities</p>
                </div>
                <div class="stat-card high">
                    <h3>{high}</h3>
                    <p>High Confidence</p>
                </div>
                <div class="stat-card medium">
                    <h3>{medium}</h3>
                    <p>Medium Confidence</p>
                </div>
                <div class="stat-card low">
                    <h3>{low}</h3>
                    <p>Low Confidence</p>
                </div>
            </div>
        </div>
        
        <div class="findings">
            <h2>Detailed Findings</h2>
"""
    
    # Add each finding
    if findings:
        for i, finding in enumerate(findings, 1):
            payload = finding.get('payload', 'N/A')
            confidence = finding.get('confidence', 'none')
            evidence = finding.get('evidence', [])
            methods = finding.get('detection_methods', [])
            status_code = finding.get('status_code', 'N/A')
            response_time = finding.get('response_time', 'N/A')
            preview = finding.get('response_preview', '')
            
            html += f"""
            <div class="finding {confidence}">
                <div class="finding-header">
                    <h3>Finding #{i}: <code>{payload}</code></h3>
                    <span class="confidence-badge {confidence}">{confidence} Confidence</span>
                </div>
                <div class="finding-body">
                    <div class="finding-section">
                        <h4>Detection Methods</h4>
                        <ul>
"""
            for method in methods:
                html += f"                            <li>{method}</li>\n"
            
            html += f"""
                        </ul>
                    </div>
                    
                    <div class="finding-section">
                        <h4>Evidence</h4>
                        <ul>
"""
            for ev in evidence:
                html += f"                            <li>{ev}</li>\n"
            
            html += f"""
                        </ul>
                    </div>
                    
                    <div class="finding-section">
                        <h4>Response Details</h4>
                        <ul>
                            <li>Status Code: {status_code}</li>
                            <li>Response Time: {response_time:.2f}s</li>
                        </ul>
                    </div>
                    
                    <div class="finding-section">
                        <h4>Response Preview</h4>
                        <div class="code-block">{preview[:500] if preview else 'N/A'}</div>
                    </div>
                </div>
            </div>
"""
    else:
        html += """
            <div class="finding">
                <div class="finding-header">
                    <h3>No vulnerabilities detected</h3>
                </div>
                <div class="finding-body">
                    <p>The scan completed successfully but did not detect any LFI vulnerabilities with the tested payloads.</p>
                </div>
            </div>
"""
    
    html += """
        </div>
        
        <footer>
            <p>Generated by LFIBay - Automated LFI Testing Tool</p>
            <p>Use only on authorized systems</p>
        </footer>
    </div>
</body>
</html>
"""
    
    return html


def save_report(filename, content, output_dir='output/reports'):
    """
    Save report to file
    Args:
        filename: Name of the file
        content: Content to save
        output_dir: Output directory
    Returns: Full path to saved file
    """
    # Create directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Full path
    filepath = os.path.join(output_dir, filename)
    
    # Write file
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    return filepath


def generate_reports(findings, metadata, output_dir='output/reports'):
    """
    Generate both JSON and HTML reports
    Args:
        findings: List of findings
        metadata: Scan metadata
        output_dir: Output directory
    Returns: Dictionary with paths to generated reports
    """
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    
    # Generate reports
    json_content = generate_json_report(findings, metadata)
    html_content = generate_html_report(findings, metadata)
    
    # Save reports
    json_path = save_report(f'report_{timestamp}.json', json_content, output_dir)
    html_path = save_report(f'report_{timestamp}.html', html_content, output_dir)
    
    return {
        'json': json_path,
        'html': html_path
    }
