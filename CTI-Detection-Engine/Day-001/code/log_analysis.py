file = open("access.log", "r")
lines = file.read().splitlines()
file.close()

failed_count = {}

for line in lines:
    if "LOGIN_FAILED" in line:
        parts = line.split()
        ip = parts[0]

        if ip in failed_count:
            failed_count[ip] = failed_count[ip] + 1
        else:
            failed_count[ip] = 1

print("---- FAILED LOGIN COUNT ----")

for ip in failed_count:
    print(ip, "failed", failed_count[ip], "times")
