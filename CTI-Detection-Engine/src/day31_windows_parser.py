# with open("data/windows_auth.log", "r") as file:
#     lines = file.readlines()

# for line in lines:
#     paths = line.strip().split(" ")
#     parts[0].split(":")[1]

LOG_FILE = "data/windows_auth.log"

def parse_windows_logs():
    print("--- 🛡️ Windows Log Parser Active ---")

    with open("data/windows_auth.log", "r") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue 

            parts = line.strip().split(" ")
            if len(parts) < 4:
                continue

            event_id = parts[0].split(":")[1]
            user     = parts[1].split(":")[1]
            ip       = parts[2].split(":")[1]
            status   = parts[3].split(":")[1]

            print(f"ID: {event_id} | User: {user} | IP: {ip} | Status: {status}")

if __name__ == "__main__":
    parse_windows_logs()
