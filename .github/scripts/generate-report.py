#!/usr/bin/env python3
"""
HTML Report Generator for Security Scans
Uses external HTML templates for cleaner code
"""
import json
import os
import sys
import html as html_module
import xml.etree.ElementTree as ET
from datetime import datetime


def load_template(template_name):
    """Load HTML template from .github/templates/"""
    template_path = f'.github/templates/{template_name}'
    if not os.path.exists(template_path):
        print(f"❌ Template not found: {template_path}")
        sys.exit(1)

    with open(template_path, 'r') as f:
        return f.read()


def generate_njsscan_report(json_file, output_file):
    """Generate njsscan HTML report"""
    # Load data
    if not os.path.exists(json_file):
        data = {}
    else:
        with open(json_file, 'r') as f:
            try:
                data = json.load(f)
            except:
                data = {}

    # Count issues
    total_issues = 0
    severity_counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}

    if data and 'nodejs' in data:
        for severity in ['ERROR', 'WARNING', 'INFO']:
            if severity.lower() in data['nodejs']:
                issues = data['nodejs'][severity.lower()]
                count = len(issues) if isinstance(issues, dict) else 0
                severity_counts[severity] = count
                total_issues += count

    # Generate content
    if total_issues == 0:
        content = '<div class="no-issues">✅ No security issues found! Your Python Code looks good.</div>'
    else:
        content = ''
        for severity in ['error', 'warning', 'info']:
            if 'nodejs' in data and severity in data['nodejs']:
                issues = data['nodejs'][severity]
                if issues:
                    severity_upper = severity.upper()
                    content += f'<h2>🚨 {severity_upper} Issues ({len(issues)})</h2>'
                    content += '<table><thead><tr><th>Rule ID</th><th>File</th><th>Line</th><th>Description</th><th>Metadata</th></tr></thead><tbody>'

                    for rule_id, findings in issues.items():
                        if isinstance(findings, list):
                            for finding in findings:
                                file_path = finding.get('filename', 'Unknown')
                                line_num = finding.get('line_number', 'N/A')
                                description = finding.get('metadata', {}).get('description', rule_id)
                                metadata = finding.get('metadata', {})
                                cwe = metadata.get('cwe', 'N/A')
                                owasp = metadata.get('owasp', 'N/A')

                                content += f'''
                                    <tr>
                                        <td><span class="badge {severity}">{rule_id}</span></td>
                                        <td class="file-path">{file_path}</td>
                                        <td class="line-num">Line {line_num}</td>
                                        <td>{description}</td>
                                        <td class="metadata">CWE: {cwe}<br>OWASP: {owasp}</td>
                                    </tr>
                                '''

                    content += '</tbody></table>'

    # Load template and replace placeholders
    template = load_template('njsscan-template.html')
    html = template.replace('{{SCAN_DATE}}', datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
    html = html.replace('{{TOTAL_ISSUES}}', str(total_issues))
    html = html.replace('{{ERROR_COUNT}}', str(severity_counts['ERROR']))
    html = html.replace('{{WARNING_COUNT}}', str(severity_counts['WARNING']))
    html = html.replace('{{INFO_COUNT}}', str(severity_counts['INFO']))
    html = html.replace('{{CONTENT}}', content)

    # Write output
    with open(output_file, 'w') as f:
        f.write(html)

    print(f"✅ njsscan HTML report generated: {output_file}")


def generate_semgrep_report(json_file, output_file):
    """Generate Semgrep HTML report"""
    # Load data
    if not os.path.exists(json_file):
        data = {"results": []}
    else:
        with open(json_file, 'r') as f:
            try:
                data = json.load(f)
            except:
                data = {"results": []}

    # Count issues
    results = data.get('results', [])
    total_issues = len(results)
    severity_counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}

    for result in results:
        severity = result.get('extra', {}).get('severity', 'INFO').upper()
        if severity in severity_counts:
            severity_counts[severity] += 1

    # Generate content
    if total_issues == 0:
        content = '<div class="no-issues">✅ No security issues found! Your code looks secure.</div>'
    else:
        content = ''
        for sev in ['ERROR', 'WARNING', 'INFO']:
            sev_results = [r for r in results if r.get('extra', {}).get('severity', 'INFO').upper() == sev]

            if sev_results:
                content += f'<h2>🚨 {sev} Issues ({len(sev_results)})</h2>'
                content += '<table><thead><tr><th>Rule ID</th><th>File</th><th>Line</th><th>Message</th><th>Code Snippet</th></tr></thead><tbody>'

                for result in sev_results:
                    rule_id = result.get('check_id', 'unknown').split('.')[-1]
                    file_path = result.get('path', 'Unknown')
                    line_start = result.get('start', {}).get('line', 'N/A')
                    message = result.get('extra', {}).get('message', 'No description')
                    code = result.get('extra', {}).get('lines', '')
                    severity_class = sev.lower()

                    content += f'''
                        <tr>
                            <td class="rule-id">{rule_id}</td>
                            <td class="file-path">{file_path}</td>
                            <td class="line-num">Line {line_start}</td>
                            <td>{message}</td>
                            <td><div class="code-snippet">{code}</div></td>
                        </tr>
                    '''

                content += '</tbody></table>'

    # Load template and replace placeholders
    template = load_template('semgrep-template.html')
    html = template.replace('{{SCAN_DATE}}', datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
    html = html.replace('{{TOTAL_ISSUES}}', str(total_issues))
    html = html.replace('{{ERROR_COUNT}}', str(severity_counts['ERROR']))
    html = html.replace('{{WARNING_COUNT}}', str(severity_counts['WARNING']))
    html = html.replace('{{INFO_COUNT}}', str(severity_counts['INFO']))
    html = html.replace('{{CONTENT}}', content)

    # Write output
    with open(output_file, 'w') as f:
        f.write(html)

    print(f"✅ Semgrep HTML report generated: {output_file}")


def generate_trivy_report(json_file, output_file):
    """Generate Trivy HTML report"""
    # Load data
    with open(json_file, 'r') as f:
        data = json.load(f)

    # Count vulnerabilities
    total_vulns = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    results = data.get('Results', [])
    for result in results:
        vulns = result.get('Vulnerabilities', [])
        if vulns:
            for vuln in vulns:
                severity = vuln.get('Severity', 'UNKNOWN')
                if severity in severity_counts:
                    severity_counts[severity] += 1
                total_vulns += 1

    # Generate content
    if total_vulns == 0:
        content = '<div class="no-vulns">✅ No vulnerabilities found! Your image is secure.</div>'
    else:
        content = ''
        for result in results:
            target = result.get('Target', 'Unknown')
            vulns = result.get('Vulnerabilities', [])

            if vulns:
                content += f'<h2>📦 {target}</h2>'
                content += '<table><thead><tr><th>Vulnerability ID</th><th>Package</th><th>Severity</th><th>Installed Version</th><th>Fixed Version</th><th>Title</th></tr></thead><tbody>'

                for vuln in vulns:
                    vuln_id = vuln.get('VulnerabilityID', 'N/A')
                    pkg_name = vuln.get('PkgName', 'N/A')
                    severity = vuln.get('Severity', 'UNKNOWN')
                    installed = vuln.get('InstalledVersion', 'N/A')
                    fixed = vuln.get('FixedVersion', 'Not available')
                    title = vuln.get('Title', vuln.get('Description', 'No description')[:100])
                    severity_class = severity.lower()

                    content += f'''
                        <tr>
                            <td class="vuln-id">{vuln_id}</td>
                            <td>{pkg_name}</td>
                            <td><span class="badge {severity_class}">{severity}</span></td>
                            <td>{installed}</td>
                            <td>{fixed}</td>
                            <td>{title}</td>
                        </tr>
                    '''

                content += '</tbody></table>'

    # Load template and replace placeholders
    template = load_template('trivy-template.html')
    html = template.replace('{{SCAN_DATE}}', datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
    html = html.replace('{{TOTAL_VULNS}}', str(total_vulns))
    html = html.replace('{{CRITICAL_COUNT}}', str(severity_counts['CRITICAL']))
    html = html.replace('{{HIGH_COUNT}}', str(severity_counts['HIGH']))
    html = html.replace('{{MEDIUM_COUNT}}', str(severity_counts['MEDIUM']))
    html = html.replace('{{LOW_COUNT}}', str(severity_counts['LOW']))
    html = html.replace('{{CONTENT}}', content)

    # Write output
    with open(output_file, 'w') as f:
        f.write(html)

    print(f"✅ Trivy HTML report generated: {output_file}")


def generate_zap_report(xml_file, output_file):
    """Generate OWASP ZAP HTML report from baseline XML"""
    # Parse ZAP XML
    if not os.path.exists(xml_file):
        alerts = []
        target = "N/A"
    else:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            target = root.get('host', 'N/A')
            alerts = []
            for site in root.findall('.//site'):
                if not target or target == 'N/A':
                    target = site.get('name', 'N/A')
                for alert in site.findall('.//alertitem'):
                    alerts.append(alert)
        except ET.ParseError:
            alerts = []
            target = "N/A"

    # Risk mapping: 0=Info, 1=Low, 2=Medium, 3=High
    risk_map = {'0': 'Informational', '1': 'Low', '2': 'Medium', '3': 'High'}
    total_alerts = len(alerts)
    severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}

    for alert in alerts:
        riskcode = alert.findtext('riskcode', '0')
        risk = risk_map.get(riskcode, 'Informational')
        severity_counts[risk] += 1

    # Generate content
    if total_alerts == 0:
        content = '<div class="no-alerts">✅ No alerts found! Your application looks secure.</div>'
    else:
        content = ''
        for risk_level in ['High', 'Medium', 'Low', 'Informational']:
            risk_alerts = [a for a in alerts if risk_map.get(a.findtext('riskcode', '0'), 'Informational') == risk_level]
            if not risk_alerts:
                continue

            css_class = risk_level.lower()
            content += f'<h2><span class="badge {css_class}">{risk_level.upper()}</span> {risk_level} Risk Alerts ({len(risk_alerts)})</h2>'
            content += '<table><thead><tr><th>Alert</th><th>Risk</th><th>CWE</th><th>Instances</th><th>Description</th><th>Solution</th></tr></thead><tbody>'

            for alert in risk_alerts:
                name = html_module.escape(alert.findtext('alert', 'N/A'))
                riskdesc = html_module.escape(alert.findtext('riskdesc', 'N/A'))
                cweid = alert.findtext('cweid', 'N/A')
                count = alert.findtext('count', '0')
                desc = html_module.escape(alert.findtext('desc', 'N/A')[:300])
                solution = html_module.escape(alert.findtext('solution', 'N/A')[:300])

                content += f'''
                    <tr>
                        <td class="alert-name">{name}</td>
                        <td><span class="badge {css_class}">{riskdesc}</span></td>
                        <td class="cwe-id">CWE-{cweid}</td>
                        <td>{count}</td>
                        <td>{desc}</td>
                        <td>{solution}</td>
                    </tr>
                '''

            content += '</tbody></table>'

    # Load template and replace placeholders
    template = load_template('zap-template.html')
    html = template.replace('{{SCAN_DATE}}', datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
    html = html.replace('{{TARGET}}', html_module.escape(target))
    html = html.replace('{{TOTAL_ALERTS}}', str(total_alerts))
    html = html.replace('{{HIGH_COUNT}}', str(severity_counts['High']))
    html = html.replace('{{MEDIUM_COUNT}}', str(severity_counts['Medium']))
    html = html.replace('{{LOW_COUNT}}', str(severity_counts['Low']))
    html = html.replace('{{INFO_COUNT}}', str(severity_counts['Informational']))
    html = html.replace('{{CONTENT}}', content)

    with open(output_file, 'w') as f:
        f.write(html)

    print(f"✅ ZAP HTML report generated: {output_file}")


def load_json_safe(filepath):
    """Safely load a JSON file, returning None on failure"""
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except:
        return None


def generate_snyk_report(input_file, output_file, scan_type, title):
    """Generate Snyk HTML report (OpenSource, Code, or Container)"""
    data = load_json_safe(input_file)

    vulns = []
    if data:
        if scan_type == "opensource":
            vulns = data.get("vulnerabilities", [])
        elif scan_type == "code":
            for run in data.get("runs", []):
                vulns.extend(run.get("results", []))
        elif scan_type == "container":
            vulns = data.get("vulnerabilities", [])

    total = len(vulns)
    critical = high = medium = low = 0

    for v in vulns:
        sev = v.get("severity", v.get("level", "unknown")).lower()
        if sev == "critical": critical += 1
        elif sev in ["high", "error"]: high += 1
        elif sev in ["medium", "warning"]: medium += 1
        elif sev in ["low", "note"]: low += 1

    vuln_rows = ""
    if total > 0:
        for v in vulns[:100]:
            if scan_type == "code":
                name = v.get("ruleId", "N/A")
                desc = html_module.escape(v.get("message", {}).get("text", "N/A")[:200])
                sev = v.get("level", "unknown")
                pkg = v.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "N/A")
            else:
                name = html_module.escape(v.get("title", v.get("id", "N/A")))
                desc = html_module.escape(v.get("description", "N/A")[:200])
                sev = v.get("severity", "unknown")
                pkg = html_module.escape(v.get("packageName", v.get("moduleName", "N/A")))

            colors = {"critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107", "low": "#28a745", "error": "#dc3545", "warning": "#ffc107", "note": "#28a745"}
            color = colors.get(sev.lower(), "#6c757d")
            badge = f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold">{sev.upper()}</span>'

            vuln_rows += f"""
            <tr>
                <td>{badge}</td>
                <td><strong>{name}</strong></td>
                <td>{pkg}</td>
                <td>{desc}</td>
            </tr>"""

        content = f'''
        <table>
            <thead><tr><th>Severity</th><th>Vulnerability</th><th>Package / File</th><th>Description</th></tr></thead>
            <tbody>{vuln_rows}</tbody>
        </table>
        {"<div style='padding:10px;background:white;text-align:center;color:#999;font-size:12px'>Showing first 100 of " + str(total) + " vulnerabilities</div>" if total > 100 else ""}
        '''
    else:
        content = '<div class="no-vulns">✅ No vulnerabilities found!</div>'

    template = load_template('snyk-template.html')
    html_out = template.replace('{{TITLE}}', title)
    html_out = html_out.replace('{{SCAN_DATE}}', datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
    html_out = html_out.replace('{{SCAN_TYPE}}', scan_type.title())
    html_out = html_out.replace('{{TOTAL_COUNT}}', str(total))
    html_out = html_out.replace('{{CRITICAL_COUNT}}', str(critical))
    html_out = html_out.replace('{{HIGH_COUNT}}', str(high))
    html_out = html_out.replace('{{MEDIUM_COUNT}}', str(medium))
    html_out = html_out.replace('{{LOW_COUNT}}', str(low))
    html_out = html_out.replace('{{CONTENT}}', content)

    with open(output_file, 'w') as f:
        f.write(html_out)
    print(f"✅ Snyk {scan_type} report generated: {output_file}")


def generate_snyk_combined_report(output_file, scan_args):
    """Generate Snyk Combined HTML report from multiple scan results"""
    # scan_args format: "Label1,type1,file1;Label2,type2,file2"
    scans = []
    for part in scan_args.split(';'):
        if part.strip():
            scans.append(part.strip().split(','))

    summary_rows = ""
    detail_sections = ""
    for label, stype, input_file in scans:
        data = load_json_safe(input_file)
        vulns = []
        if data:
            if stype == "opensource":
                vulns = data.get("vulnerabilities", [])
            elif stype == "code":
                for run in data.get("runs", []):
                    vulns.extend(run.get("results", []))
            elif stype == "container":
                vulns = data.get("vulnerabilities", [])

        total = len(vulns)
        critical = high = medium = low = 0
        for v in vulns:
            sev = v.get("severity", v.get("level", "unknown")).lower()
            if sev == "critical":
                critical += 1
            elif sev in ["high", "error"]:
                high += 1
            elif sev in ["medium", "warning"]:
                medium += 1
            elif sev in ["low", "note"]:
                low += 1

        status = "✅ No issues" if total == 0 else f"⚠️ {total} findings"
        status_class = "status-ok" if total == 0 else "status-warn"
        counts = f'C:{critical} H:{high} M:{medium} L:{low}'
        summary_rows += f'<tr><td><strong>{label}</strong></td><td class="{status_class}">{status}</td><td>{counts}</td></tr>'

        if total == 0:
            section_html = '<div class="no-issues">✅ No vulnerabilities found!</div>'
        else:
            rows = ""
            for v in vulns:
                if stype == "code":
                    name = html_module.escape(v.get("ruleId", "N/A"))
                    desc = html_module.escape(v.get("message", {}).get("text", "N/A"))
                    sev = v.get("level", "unknown").lower()
                    pkg = v.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "N/A")
                    pkg = html_module.escape(pkg)
                else:
                    name = html_module.escape(v.get("title", v.get("id", "N/A")))
                    desc = html_module.escape(v.get("description", "N/A"))
                    sev = v.get("severity", "unknown").lower()
                    pkg = html_module.escape(v.get("packageName", v.get("moduleName", "N/A")))

                badge_class = "badge-unknown"
                if sev == "critical":
                    badge_class = "badge-critical"
                elif sev in ["high", "error"]:
                    badge_class = "badge-high"
                elif sev in ["medium", "warning"]:
                    badge_class = "badge-medium"
                elif sev in ["low", "note"]:
                    badge_class = "badge-low"

                rows += f"""
                <tr>
                    <td><span class="badge {badge_class}">{sev.upper()}</span></td>
                    <td><strong>{name}</strong></td>
                    <td>{pkg}</td>
                    <td>{desc}</td>
                </tr>"""

            section_html = f'''
            <table>
                <thead><tr><th>Severity</th><th>Vulnerability</th><th>Package / File</th><th>Description</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
            '''

        detail_sections += f'''
        <div class="section">
            <h2>{html_module.escape(label)}</h2>
            {section_html}
        </div>
        '''

    template = load_template('snyk-combined-template.html')
    html_out = template.replace('{{SCAN_DATE}}', datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
    html_out = html_out.replace('{{SUMMARY_ROWS}}', summary_rows)
    html_out = html_out.replace('{{DETAILS}}', detail_sections)

    with open(output_file, 'w') as f:
        f.write(html_out)
    print(f"✅ Snyk combined report generated: {output_file}")


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: generate-report.py <tool> <input_file> <output_html> [extra_args]")
        print("Tools: njsscan, semgrep, trivy, zap, snyk-opensource, snyk-code, snyk-container, snyk-combined")
        sys.exit(1)

    tool = sys.argv[1]

    if tool == 'snyk-combined':
        # Usage: generate-report.py snyk-combined <output_html> "Label1,type1,file1;Label2,type2,file2"
        output_file = sys.argv[2]
        scan_args = sys.argv[3]
        generate_snyk_combined_report(output_file, scan_args)
    else:
        if len(sys.argv) < 4:
            print("Usage: generate-report.py <tool> <input_file> <output_html>")
            sys.exit(1)
        input_file = sys.argv[2]
        output_file = sys.argv[3]

        if tool == 'njsscan':
            generate_njsscan_report(input_file, output_file)
        elif tool == 'semgrep':
            generate_semgrep_report(input_file, output_file)
        elif tool == 'trivy':
            generate_trivy_report(input_file, output_file)
        elif tool == 'zap':
            generate_zap_report(input_file, output_file)
        elif tool == 'snyk-opensource':
            generate_snyk_report(input_file, output_file, "opensource", "Snyk Open Source — Dependency Vulnerabilities")
        elif tool == 'snyk-code':
            generate_snyk_report(input_file, output_file, "code", "Snyk Code — SAST Findings")
        elif tool == 'snyk-container':
            generate_snyk_report(input_file, output_file, "container", "Snyk Container — Image Vulnerabilities")
        else:
            print(f"❌ Unknown tool: {tool}")
            sys.exit(1)