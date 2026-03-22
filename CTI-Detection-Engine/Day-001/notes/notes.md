# Python File Handling + Basic Log Analysis

## What I Did

Today I practiced basic file handling using Python and applied it to a simple log analysis task.

Goal was simple:

* Read a log file
* Find only failed login attempts
* Count how many times each IP failed

---

## Log File Used

File name: `access.log`

Example data:

```
192.168.1.10 LOGIN_SUCCESS
10.0.0.5 LOGIN_FAILED
10.0.0.5 LOGIN_FAILED
8.8.8.8 LOGIN_FAILED
```

Each line has:
IP address + login status

---

## Main Things I Learned

### 1. How to Read Files in Python

Used:

* open() → to open file
* read() → to read content
* splitlines() → to convert file text into list of lines

Without splitlines(), data comes as one long string, which is not useful for logs.

---

### 2. Why Dictionary is Used

I needed counting like this:
IP → number of failed attempts

Dictionary is perfect for that.

Example:

```
10.0.0.5 → 2
8.8.8.8 → 1
```

---

## Final Working Code

```python
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
```


## Output I Got

---- FAILED LOGIN COUNT ----
10.0.0.5 failed 2 times
8.8.8.8 failed 1 times


## Problems I Faced

* Variable spelling mistakes
* Forgetting print statements
* Confusion between string vs list
* Indentation errors


## What This Can Be Used For

Basic idea is same as:

* Log monitoring
* Security event tracking
* Brute force detection basics


## Next Things I Want To Try

* Save output to new file
* Find top failed IP automatically
* Try bigger log file
* Try real-time log reading
