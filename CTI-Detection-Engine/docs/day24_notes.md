# Day 24 – Real Log Parsing + Pandas + First ML Anomaly Detection

Today was the first day we touched **real-world log analysis** and took our very first step into actual machine learning for detection.

We moved from simulated JSON events to parsing real Apache access logs using regex, loaded the parsed data into Pandas for analysis, and ran our first ML anomaly model (Isolation Forest) on per-IP features.

This is how real detection engineering starts: real logs → parsing → features → ML.

## Files Created / Updated

- `data/apache_access.log` – Realistic Apache log with simulated brute-force
- `src/log_parser.py` – Regex-based log parser
- `src/log_analysis_pandas.py` – Pandas analysis + Isolation Forest anomaly detection


## What Was Done Today (Step-by-Step)

1. **Created realistic Apache access log**  
   Simulated brute-force (multiple 401 POST /login from same IP) + normal GET requests.

2. **Built regex log parser**  
   Extracted IP, method, endpoint, status from each line.  
   Result: list of parsed dicts (`parsed_events`).

3. **Introduced Pandas**  
   Converted parsed_events → DataFrame  
   Grouped by IP:  
   - Total requests per IP  
   - Failed logins (status 401) per IP  
   - Filtered suspicious IPs (failed > 1)

4. **Ran first ML anomaly detection (Isolation Forest)**  
   Features: failed_logins count + total requests per IP  
   Model flagged IPs with unusual failed logins as anomalies (e.g., 103.45.67.89)

## Sample Output (real run)
{'ip': '192.168.1.10', 'method': 'GET', 'endpoint': '/index.html', 'status': 200}
{'ip': '103.45.67.89', 'method': 'POST', 'endpoint': '/login', 'status': 401}
{'ip': '103.45.67.89', 'method': 'POST', 'endpoint': '/login', 'status': 401}
{'ip': '103.45.67.89', 'method': 'POST', 'endpoint': '/login', 'status': 200}
{'ip': '8.8.8.8', 'method': 'GET', 'endpoint': '/home', 'status': 200}
Total Parsed Events: 5

All Parsed Logs:
             ip method     endpoint  status
0  192.168.1.10    GET  /index.html     200
1  103.45.67.89   POST       /login     401
2  103.45.67.89   POST       /login     401
3  103.45.67.89   POST       /login     200
4       8.8.8.8    GET        /home     200

Requests per IP:
ip
103.45.67.89    3
192.168.1.10    1
8.8.8.8         1
dtype: int64

Failed Logins (401) per IP:
ip
103.45.67.89    2
dtype: int64

Suspicious IPs (failed > 1):
ip
103.45.67.89    2
dtype: int64
Per-IP Features:
              failed_logins  requests
ip                                   
103.45.67.89              2         3
192.168.1.10              0         1
8.8.8.8                   0         1

Anomaly Detection Result:
              failed_logins  requests  anomaly
ip                                            
103.45.67.89              2         3  anomaly
192.168.1.10              0         1   normal
8.8.8.8                   0         1   normal



## Key Learning Points

- Regex is essential for parsing real security logs (Apache, Nginx, Syslog, etc.)
- Pandas makes log analysis fast: groupby, filtering, aggregation in 2-3 lines
- Isolation Forest is a great first ML anomaly model — unsupervised, no labels needed, detects outliers based on feature patterns
- Combining parsing + Pandas + ML gives real detection power even without threat intel

## Limitations

- Regex pattern is specific to Apache Combined format (needs adjustment for other logs)
- No time-based features (e.g., failed logins in last 5 min)
- Isolation Forest uses only 2 features (future: more like bytes, user-agent, time of day)
- Contamination parameter is guesswork (real-world: tuned on validation data)

Day 24 complete.  
Now we have real log parsing, Pandas analysis, and our first ML anomaly model — real detection engineering.

— Vivek | ThreatIntel
