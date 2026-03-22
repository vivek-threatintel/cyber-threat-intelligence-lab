# Reads authentication log file
def parse_log(filename):

    file = open(filename, "r")
    lines = file.readlines()
    file.close()

    return lines

# Counts FAILED and SUCCESS attempts per IP
def count_attempts(lines):

    log_data = {}

    for line in lines:

        parts = line.split()
        ip = parts[0]
        status = parts[1]

        if ip not in log_data:
            log_data[ip] = {"FAILED": 0, "SUCCESS": 0}

        log_data[ip][status] += 1

    return log_data

# Detects brute force pattern
def detect_suspicious(log_data):

    suspicious_ips = []

    for ip in log_data:

        failed = log_data[ip]["FAILED"]
        success = log_data[ip]["SUCCESS"]

        if failed >= 3 and success >= 1:
            suspicious_ips.append(ip)

    return suspicious_ips

