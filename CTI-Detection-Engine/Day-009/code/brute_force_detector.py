suspicious_ips = []

for ip in log_data:

    failed = log_data[ip]["FAILED"]
    success = log_data[ip]["SUCCESS"]

    if failed >= 3 and success >= 1:
        suspicious_ips.append(ip)

print("\nSuspicious IPs:\n")

for ip in suspicious_ips:
    print(ip)
