# scripts/generate_dashboard.py
import requests
import os
import json
from datetime import datetime

# Configuration - Get variables from environment
GH_TOKEN = os.getenv('GH_TOKEN')
REPO = os.getenv('GH_REPOSITORY') # e.g., 'my-username/my-security-project'
OUTPUT_FILE = 'security-dashboard.html'

# Headers for GitHub API authentication
headers = {
    'Authorization': f'token {GH_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

def fetch_github_alerts():
    """Fetches Dependabot and CodeQL alerts from the GitHub API"""
    alerts_url = f'https://api.github.com/repos/{REPO}/code-scanning/alerts'
    dependabot_url = f'https://api.github.com/repos/{REPO}/dependabot/alerts'

    all_alerts = []

    # Fetch Code Scanning (CodeQL) alerts
    print("Fetching CodeQL alerts...")
    response = requests.get(alerts_url, headers=headers)
    if response.status_code == 200:
        codeql_alerts = response.json()
        for alert in codeql_alerts:
            # Only count 'open' or 'fixed' alerts, ignore 'dismissed'
            if alert.get('state') in ['open', 'fixed']:
                all_alerts.append({
                    'type': 'CodeQL',
                    'created_at': alert['created_at'],
                    'state': alert['state'],
                    'rule': alert['rule']['id'],
                    'severity': alert['rule']['severity'].lower(),
                    'html_url': alert['html_url']
                })
    else:
        print(f"Error fetching CodeQL alerts: {response.status_code}")

    # Fetch Dependabot alerts
    print("Fetching Dependabot alerts...")
    response = requests.get(dependabot_url, headers=headers)
    if response.status_code == 200:
        dependabot_alerts = response.json()
        for alert in dependabot_alerts:
            # Only process 'open' alerts
            if alert.get('state') == 'open':
                all_alerts.append({
                    'type': 'Dependabot',
                    'created_at': alert['created_at'],
                    'state': alert['state'],
                    'rule': alert['security_advisory']['summary'],
                    'severity': alert['security_vulnerability']['severity'].lower(),
                    'html_url': alert['html_url']
                })
    else:
        print(f"Error fetching Dependabot alerts: {response.status_code}")

    return all_alerts

def generate_html_dashboard(alerts):
    """Generates the HTML dashboard from the alerts data"""
    print("Generating HTML dashboard...")
    # Count alerts by type and severity
    severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'warning': 0, 'note': 0, 'error': 0}
    for alert in alerts:
        sev = alert['severity']
        severity_count[sev] = severity_count.get(sev, 0) + 1

    total_alerts = len(alerts)

    # HTML Template
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Dashboard - {REPO}</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .card {{ border: 1px solid #ddd; border-radius: 5px; padding: 20px; margin: 10px 0; }}
            .severity-critical {{ color: #ff2c2c; font-weight: bold; }}
            .severity-high {{ color: #ff6e6e; }}
            .severity-medium {{ color: #ffbf00; }}
            .severity-low {{ color: #6ecbff; }}
        </style>
    </head>
    <body>
        <h1>Security Dashboard</h1>
        <p>Repository: <strong>{REPO}</strong></p>
        <p>Last updated: <strong>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</strong></p>

        <div class="card">
            <h2>Summary</h2>
            <p>Total Alerts: <strong>{total_alerts}</strong></p>
            <canvas id="severityChart" width="400" height="200"></canvas>
        </div>

        <div class="card">
            <h2>Recent Alerts</h2>
            <ul>
    """
    # Add the 10 most recent alerts to the list
    sorted_alerts = sorted(alerts, key=lambda x: x['created_at'], reverse=True)[:10]
    for alert in sorted_alerts:
        html_content += f"""
                <li>
                    <span class="severity-{alert['severity']}">[{alert['severity'].upper()}]</span>
                    <strong>{alert['type']}</strong>: {alert['rule']}
                    (<a href="{alert['html_url']}" target="_blank">View</a>)
                </li>
        """

    html_content += """
            </ul>
        </div>

        <script>
            const ctx = document.getElementById('severityChart').getContext('2d');
            const severityChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Warning', 'Note'],
                    datasets: [{
                        label: '# of Alerts by Severity',
                        data: [
                            """ + str(severity_count['critical']) + """,
                            """ + str(severity_count['high']) + """,
                            """ + str(severity_count['medium']) + """,
                            """ + str(severity_count['low']) + """,
                            """ + str(severity_count['warning']) + """,
                            """ + str(severity_count['note']) + """
                        ],
                        backgroundColor: [
                            '#ff2c2c', '#ff6e6e', '#ffbf00', '#6ecbff', '#aaaaaa', '#dddddd'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        </script>
    </body>
    </html>
    """

    # Write the HTML to a file
    with open(OUTPUT_FILE, 'w') as f:
        f.write(html_content)
    print(f"Dashboard generated: {OUTPUT_FILE}")

if __name__ == '__main__':
    print("Starting dashboard generation...")
    alerts_data = fetch_github_alerts()
    generate_html_dashboard(alerts_data)
