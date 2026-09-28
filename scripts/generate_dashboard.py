# scripts/generate_dashboard.py
import requests
import os
import json
from datetime import datetime

# Configuration - Get variables from environment
GH_TOKEN = os.getenv('GH_TOKEN')
REPO = os.getenv('GH_REPOSITORY')  # e.g., 'nidhijhaaa/Security-monitoring-dashboard'
OUTPUT_FILE = 'index.html'  # Changed to index.html for GitHub Pages

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
    try:
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
            print(f"Found {len(codeql_alerts)} CodeQL alerts")
        else:
            print(f"Error fetching CodeQL alerts: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Exception fetching CodeQL alerts: {str(e)}")

    # Fetch Dependabot alerts
    print("Fetching Dependabot alerts...")
    try:
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
            print(f"Found {len(dependabot_alerts)} Dependabot alerts")
        else:
            print(f"Error fetching Dependabot alerts: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Exception fetching Dependabot alerts: {str(e)}")

    print(f"Total alerts found: {len(all_alerts)}")
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
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
            body {{ 
                font-family: Arial, sans-serif; 
                margin: 40px; 
                line-height: 1.6;
                color: #333;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
            }}
            .header {{
                background: #f5f5f5;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 20px;
            }}
            .card {{ 
                border: 1px solid #ddd; 
                border-radius: 8px; 
                padding: 20px; 
                margin: 10px 0; 
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .severity-critical {{ color: #ff2c2c; font-weight: bold; }}
            .severity-high {{ color: #ff6e6e; }}
            .severity-medium {{ color: #ffbf00; }}
            .severity-low {{ color: #6ecbff; }}
            .alert-list {{
                list-style-type: none;
                padding: 0;
            }}
            .alert-list li {{
                padding: 8px;
                border-bottom: 1px solid #eee;
            }}
            .alert-list li:last-child {{
                border-bottom: none;
            }}
            .chart-container {{
                height: 300px;
                margin: 20px 0;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Security Dashboard</h1>
                <p>Repository: <strong>{REPO}</strong></p>
                <p>Last updated: <strong>{current_time}</strong></p>
                <p>Total Alerts: <strong>{total_alerts}</strong></p>
            </div>

            <div class="card">
                <h2>Security Summary</h2>
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>

            <div class="card">
                <h2>Recent Alerts (Top 10)</h2>
                <ul class="alert-list">
    """
    
    # Add the 10 most recent alerts to the list
    sorted_alerts = sorted(alerts, key=lambda x: x['created_at'], reverse=True)[:10]
    if sorted_alerts:
        for alert in sorted_alerts:
            html_content += f"""
                    <li>
                        <span class="severity-{alert['severity']}">[{alert['severity'].upper()}]</span>
                        <strong>{alert['type']}</strong>: {alert['rule']}
                        <br>
                        <small>Created: {alert['created_at'].replace('T', ' ').replace('Z', '')}</small>
                        <a href="{alert['html_url']}" target="_blank" style="float: right;">View Details</a>
                    </li>
            """
    else:
        html_content += "<li>No security alerts found. Good job! 🎉</li>"

    html_content += """
                </ul>
            </div>
        </div>

        <script>
            const ctx = document.getElementById('severityChart').getContext('2d');
            const severityChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Warning', 'Note', 'Error'],
                    datasets: [{
                        label: '# of Alerts by Severity',
                        data: [
                            """ + str(severity_count['critical']) + """,
                            """ + str(severity_count['high']) + """,
                            """ + str(severity_count['medium']) + """,
                            """ + str(severity_count['low']) + """,
                            """ + str(severity_count['warning']) + """,
                            """ + str(severity_count['note']) + """,
                            """ + str(severity_count['error']) + """
                        ],
                        backgroundColor: [
                            '#ff2c2c', '#ff6e6e', '#ffbf00', '#6ecbff', '#aaaaaa', '#dddddd', '#ff2c2c'
                        ],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Number of Alerts'
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'Severity Level'
                            }
                        }
                    },
                    plugins: {
                        title: {
                            display: true,
                            text: 'Security Alerts by Severity'
                        }
                    }
                }
            });
        </script>
    </body>
    </html>
    """

    # Write the HTML to a file
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"Dashboard generated: {OUTPUT_FILE}")

if __name__ == '__main__':
    print("Starting dashboard generation...")
    print(f"Repository: {REPO}")
    alerts_data = fetch_github_alerts()
    generate_html_dashboard(alerts_data)
    print("Dashboard generation completed!")
