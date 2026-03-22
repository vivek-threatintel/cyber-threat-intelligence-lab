import json
import re
import pandas as pd

def parse_log_line(line):
    pattern = r'^(\S+) - - \[.*?\] "(\S+) (\S+)" (\d+)'
    match = re.match(pattern, line)
    if match:
        ip, method, endpoint, status = match.groups()
        return {
            "ip": ip,
            "method": method,
            "endpoint": endpoint,
            "status": int(status)
        }
    return None

with open("data/apache_access.log", "r") as f:
    lines = f.readlines()

parsed_events = []
for line in lines:
    parsed = parse_log_line(line.strip())
    if parsed:
        parsed_events.append(parsed)
        print(parsed)

print(f"Total Parsed Events: {len(parsed_events)}")

if parsed_events:
    df = pd.DataFrame(parsed_events)
    print("\nAll Parsed Logs:")
    print(df)

    print("\nRequests per IP:")
    print(df.groupby('ip').size())

    print("\nFailed Logins (401) per IP:")
    failed = df[df['status'] == 401].groupby('ip').size()
    print(failed)

    print("\nSuspicious IPs (failed > 1):")
    suspicious = failed[failed > 1]
    print(suspicious)
else:
    print("No events parsed — check log file.")

from sklearn.ensemble import IsolationForest

# Group by IP
grouped = df.groupby('ip').agg(
    failed_logins=('status', lambda x: (x == 401).sum()),
    requests=('ip', 'count')
)

print("Per-IP Features:")
print(grouped)

X = grouped[['failed_logins', 'requests']]

model = IsolationForest(contamination=0.1, random_state=42)
model.fit(X)

grouped['anomaly'] = model.predict(X)
grouped['anomaly'] = grouped['anomaly'].map({1: 'normal', -1: 'anomaly'})

print("\nAnomaly Detection Result:")
print(grouped)
