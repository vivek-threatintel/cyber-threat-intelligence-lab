file = open("auth.log", "r")

log_data = {}

for line in file:

    parts = line.split()
    ip = parts[0]
    status = parts[1]

    if ip not in log_data:
        log_data[ip] = {"FAILED": 0, "SUCCESS": 0}

    log_data[ip][status] += 1

file.close()

for ip in log_data:

    print("IP:", ip)
    print("FAILED:", log_data[ip]["FAILED"])
    print("SUCCESS:", log_data[ip]["SUCCESS"])
    print()

print("Total unique IPs:", len(log_data))
