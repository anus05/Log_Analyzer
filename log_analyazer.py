file_path = "D:\\My Projects\\Log-Analyazer\\access.log"
report_path = "D:\\My Projects\\Log-Analyazer\\security_report.txt"

# Dictionaries
ip_count = {}
status_count = {}
url_count = {}

ip_403_count = {}
ip_404_count = {}

total_requests = 0

# Read log file
f = open(file_path, "r")

for line in f:
    parts = line.split()

    if len(parts) > 6:
        total_requests += 1

        ip = parts[0]
        date_time = parts[3].replace("[", "")
        method = parts[4].replace('"', "")
        url = parts[5]
        status = parts[-1]

        # Count IP requests
        ip_count[ip] = ip_count.get(ip, 0) + 1

        # Count status codes
        status_count[status] = status_count.get(status, 0) + 1

        # Count URLs
        url_count[url] = url_count.get(url, 0) + 1

        # Brute force detection (403)
        if status == "403":
            ip_403_count[ip] = ip_403_count.get(ip, 0) + 1

        # Scanning detection (404)
        if status == "404":
            ip_404_count[ip] = ip_404_count.get(ip, 0) + 1

f.close()

# Step 7: Top 5 IPs
sorted_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)

# Step 8: Top 5 attacked URLs
sorted_urls = sorted(url_count.items(), key=lambda x: x[1], reverse=True)

# Suspicious IPs
suspicious_ips = []

for ip, count in ip_count.items():
    if count > 20:
        suspicious_ips.append(f"[HIGH TRAFFIC] {ip} -> {count} requests")

for ip, count in ip_403_count.items():
    if count > 5:
        suspicious_ips.append(f"[BRUTE FORCE] {ip} -> {count} failed logins (403)")

for ip, count in ip_404_count.items():
    if count > 5:
        suspicious_ips.append(f"[SCANNING] {ip} -> {count} not found requests (404)")


# Step 9: Generate Report File
report = open(report_path, "w")

report.write("=========== SECURITY LOG REPORT ===========\n\n")

report.write(f"Total Requests: {total_requests}\n\n")

# Status summary
report.write("------ STATUS CODE SUMMARY ------\n")
for status, count in status_count.items():
    report.write(f"{status} -> {count}\n")

report.write("\n")

# Top 5 IPs
report.write("------ TOP 5 IP ADDRESSES ------\n")
for i in range(min(5, len(sorted_ips))):
    ip, count = sorted_ips[i]
    report.write(f"{i+1}. {ip} -> {count} requests\n")

report.write("\n")

# Top 5 URLs
report.write("------ TOP 5 ATTACKED / VISITED URLS ------\n")
for i in range(min(5, len(sorted_urls))):
    url, count = sorted_urls[i]
    report.write(f"{i+1}. {url} -> {count} hits\n")

report.write("\n")

# Suspicious activity
report.write("------ SUSPICIOUS ACTIVITY DETECTED ------\n")
if len(suspicious_ips) == 0:
    report.write("No suspicious activity detected.\n")
else:
    for alert in suspicious_ips:
        report.write(alert + "\n")

report.write("\n=========== END OF REPORT ===========\n")

report.close()

print("✅ Log Analysis Completed Successfully!")
print("📄 Report Generated:", report_path)
