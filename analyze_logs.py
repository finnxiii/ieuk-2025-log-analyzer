import re
from collections import Counter, defaultdict
from datetime import datetime

log_pattern = re.compile(
    r'(?P<ip>[\d.]+)\s-\s(?P<country>[A-Z]+)\s-\s\[(?P<time>[^\]]+)\]\s"(?P<method>GET|POST)\s(?P<path>[^ ]+).*?"\s(?P<status>\d+)\s\d+\s"-"\s"(?P<agent>[^"]+)"\s(?P<latency>\d+)'
)

def parse_log_line(line):
    match = log_pattern.match(line)
    if match:
        data = match.groupdict()
        data['datetime'] = datetime.strptime(data['time'], "%d/%m/%Y:%H:%M:%S")
        return data
    return None

def analyze_logs(file_path):
    ip_counter = Counter()
    endpoint_counter = Counter()
    bots_by_pattern = Counter()
    hourly_hits = defaultdict(int)
    suspicious_agents = set()
    api_hits = 0
    total_hits = 0

    with open(file_path, 'r') as file:
        for line in file:
            date = parse_log_line(line)
            if date:
                ip = date['ip']
                agent = date['agent']
                path = date['path']
                hour_key = date['datetime'].strftime('%Y-%m-%d %H')
                hourly_hits[hour_key] += 1
                ip_counter[ip] += 1
                endpoint_counter[path] += 1
                total_hits += 1

                if "/api/" in path:
                    api_hits += 1
                if re.search(r"bot|crawl|spider|slurp|fetch|scrap|python|wget|curl", agent, re.I):
                    suspicious_agents.add(agent)
                    bots_by_pattern[ip] += 1
                elif"/api/" in path:
                    bots_by_pattern[ip] += 1

    print("\n=== TRAFFIC SUMMARY ===")
    print(f"Total requests: {total_hits}")
    print(f"API requests: {api_hits} ({api_hits/total_hits:.2%} of all traffic)")
    print(f"Unique IPs: {len(ip_counter)}")
    print(f"Unique endpoints: {len(endpoint_counter)}")

    print("\nTop 10 IPs by request volume:")
    for ip, count in ip_counter.most_common(10):
        print(f"{ip}: {count} requests")

    print("\nSuspicious IPs (bots or heavy API use):")
    for ip, count in bots_by_pattern.most_common(10):
        print(f"{ip}: {count} suspected bot/API hits")

    print("\nMost accessed endpoints:")
    for path, count in endpoint_counter.most_common(10):
        print(f"{path}: {count} hits")

    print("\nTraffic by hour (UTC):")
    for hour, count in sorted(hourly_hits.items()):
        print(f"{hour}: {count} hits")

    print("\nSample suspicious user agents:")
    for agent in list(suspicious_agents)[:5]:
        print(agent)


if __name__ == "__main__":
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else "sample-log.log"
    analyze_logs(log_file)