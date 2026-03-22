# IOC Raw data
iocs = [
    "milicious.com",
    "bad-domain.net",
    "milicious.com",
    "192.168.1.5"
]

# step 1 - Remove duplicates
unique_iocs = list(set(iocs))

# step 2 - sepaate lists
domains = []
ips = []

# step 3 - detect type
for item in unique_iocs:
    if item.replace(".", "").isdigit():
        ips.append(item)
    else:
        domains.append(item)

# step 4 - count 
domain_count = len(domains)
ip_count = len(ips)

# step 5 - output 
print("Unique IOCs: ", unique_iocs)
print("\nDomains:", domains)
print("IPs:", ips)

print("\nCounts:",)
print("Domains:", domain_count)
print("IPs:", ip_count)
