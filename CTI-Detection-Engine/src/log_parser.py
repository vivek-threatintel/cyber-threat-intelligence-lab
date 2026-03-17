import re

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
