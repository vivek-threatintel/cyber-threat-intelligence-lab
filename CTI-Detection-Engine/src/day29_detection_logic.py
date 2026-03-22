# Simple Behavioral Detection for Brute Force
def detect_brute_force(logs):
    failed_limit = 5
    user_tracker = {}

    print("🔍 Scanning Logs for Behavioral Anomalies...")

    for log in logs:
        user = log['user']
        status = log['status']

        if status == 'failed':
            # Har user ke liye failed attempt count karo
            user_tracker[user] = user_tracker.get(user, 0) + 1
            
            if user_tracker[user] >= failed_limit:
                print(f"🚨 ALERT: Brute Force detected for user [{user}]!")
        else:
            # Successful login hone par counter reset (Optional logic)
            user_tracker[user] = 0

# Sample Data for Testing
mock_logs = [
    {'user': 'admin', 'status': 'failed'},
    {'user': 'admin', 'status': 'failed'},
    {'user': 'admin', 'status': 'failed'},
    {'user': 'admin', 'status': 'failed'},
    {'user': 'admin', 'status': 'failed'}, # 5th Attempt
]

if __name__ == "__main__":
    detect_brute_force(mock_logs)