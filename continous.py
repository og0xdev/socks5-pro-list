import socket
import struct
import time
import os
import concurrent.futures
import requests
import json
import re
import ipaddress
import statistics
from datetime import datetime, timedelta
import schedule
import threading

class SOCKS5Checker:
    def __init__(self, proxy: str, target: tuple, timeout: int = 5):
        self.proxy_host, self.proxy_port = proxy.split(':', 1)
        self.proxy_port = int(self.proxy_port)
        self.target_host, self.target_port = target
        self.timeout = timeout
        self.sock = None

    def check(self) -> dict:
        result = {'proxy': f"{self.proxy_host}:{self.proxy_port}", 'latency': 9999, 'error': None}
        try:
            start = time.perf_counter()
            self.sock = socket.create_connection((self.proxy_host, self.proxy_port), self.timeout)
            self.sock.sendall(struct.pack('!BBB', 0x05, 0x01, 0x00))
            if self.sock.recv(2) != b'\x05\x00':
                raise ValueError("Invalid handshake")
            host_encoded = self.target_host.encode('idna')
            request = struct.pack('!BBBB', 0x05, 0x01, 0x00, 0x03)
            request += struct.pack('!B', len(host_encoded)) + host_encoded
            request += struct.pack('!H', self.target_port)
            self.sock.sendall(request)
            response = self.sock.recv(4)
            if response[1] != 0x00:
                raise ValueError(f"[WRN] Connect failed: {response[1]}")
            result['latency'] = (time.perf_counter() - start) * 1000
        except Exception as e:
            result['error'] = str(e)
        finally:
            if self.sock:
                self.sock.close()
        return result

def single_bandwidth_test(proxy: str, test_url: str = "https://httpbin.org/stream-bytes/500000", duration: int = 3) -> float:
    """Single bandwidth test for one proxy"""
    try:
        proxies = {'http': f'socks5://{proxy}', 'https': f'socks5://{proxy}'}
        start_time = time.time()
        total_bytes = 0

        with requests.get(test_url, proxies=proxies, stream=True, timeout=10) as response:
            response.raise_for_status()
            for chunk in response.iter_content(chunk_size=8192):
                if time.time() - start_time >= duration:
                    break
                total_bytes += len(chunk)

        elapsed = max(0.1, time.time() - start_time)  # Prevent division by zero
        mbps = (total_bytes * 8) / (elapsed * 1000000)
        return mbps
    except:
        return 0.0

def run_bandwidth_tests(proxy_data: dict) -> dict:
    """Run 4 bandwidth tests for a single proxy and return average"""
    proxy = proxy_data['proxy']
    speeds = []

    for test_num in range(4):
        speed = single_bandwidth_test(proxy)
        speeds.append(speed)
        time.sleep(0.5)  # Brief pause between tests

    # Calculate average, remove outliers
    if speeds:
        avg_speed = statistics.mean(speeds)
        proxy_data['bandwidth_mbps'] = avg_speed
        proxy_data['tests'] = speeds
    else:
        proxy_data['bandwidth_mbps'] = 0.0
        proxy_data['tests'] = []

    return proxy_data

def is_valid_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        if (ip_obj.is_private or ip_obj.is_loopback or
            ip_obj.is_link_local or ip_obj.is_multicast or
            ip_obj.is_reserved or ip_obj.is_unspecified):
            return False
        bad_ranges = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                     "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
                     "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
                     "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32"]
        for bad_range in bad_ranges:
            if ip_obj in ipaddress.ip_network(bad_range, strict=False):
                return False
        return True
    except ValueError:
        return False

def is_valid_proxy_format(proxy_line: str) -> bool:
    if not proxy_line or ':' not in proxy_line:
        return False
    parts = proxy_line.split(':', 1)
    if len(parts) != 2:
        return False
    ip, port_str = parts
    port_str = port_str.strip()
    try:
        port = int(port_str)
        if port < 1 or port > 65535:
            return False
    except ValueError:
        return False
    if is_valid_ip(ip):
        return True
    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', ip):
        return True
    return False

def fetch_proxies_from_source(url: str) -> list:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        valid_proxies = []
        seen_proxies = set()
        for line in response.text.splitlines():
            line = line.strip()
            if line and not line.startswith(('#', '//', '/*', '*/', '!')):
                proxy_part = line.split()[0] if ' ' in line else line
                proxy_part = proxy_part.split('#')[0].split('//')[0].strip()
                if is_valid_proxy_format(proxy_part) and proxy_part not in seen_proxies:
                    valid_proxies.append(proxy_part)
                    seen_proxies.add(proxy_part)
        return valid_proxies
    except:
        return []

def fetch_all_proxies(misc_file: str) -> list:
    try:
        with open(misc_file, 'r') as f:
            data = json.load(f)
        all_proxies = []
        seen_proxies = set()
        print("[INFO] Fetching and filtering proxies from sources...")
        for source in data['sources']:
            print(f"[INFO] Downloading from: {source}")
            proxies = fetch_proxies_from_source(source)
            if proxies:
                new_proxies = [p for p in proxies if p not in seen_proxies]
                if new_proxies:
                    print(f"[INFO] Added {len(new_proxies)} new valid proxies")
                    all_proxies.extend(new_proxies)
                    seen_proxies.update(new_proxies)
        print(f"\n[INFO] Total unique valid proxies: {len(all_proxies)}")
        with open('all_socks5_untested.txt', 'w') as f:
            for proxy in all_proxies:
                f.write(proxy + '\n')
        return all_proxies
    except Exception as e:
        print(f"[ERR] Error: {e}")
        return []

# Cache functions
def load_cache(cache_file: str = "./etc/proxy_cache.json") -> dict:
    """Load proxy cache from file"""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_cache(cache: dict, cache_file: str = "./etc/proxy_cache.json"):
    """Save proxy cache to file"""
    with open(cache_file, 'w') as f:
        json.dump(cache, f)

def is_cache_valid(cache_entry: dict, max_age_minutes: int = 15) -> bool:
    """Check if a cache entry is still valid"""
    if 'timestamp' not in cache_entry:
        return False
        
    cache_time = datetime.fromisoformat(cache_entry['timestamp'])
    return datetime.now() - cache_time < timedelta(minutes=max_age_minutes)

def clear_old_cache(cache: dict, max_age_minutes: int = 15) -> dict:
    """Remove expired cache entries"""
    current_time = datetime.now()
    valid_cache = {}
    
    for proxy, entry in cache.items():
        if 'timestamp' in entry:
            cache_time = datetime.fromisoformat(entry['timestamp'])
            if current_time - cache_time < timedelta(minutes=max_age_minutes):
                valid_cache[proxy] = entry
                
    return valid_cache

# Top proxies tracking
def update_top_proxies(new_results: list, top_file: str = "top50_best_json.txt", max_entries: int = 50):
    """Update the list of top proxies with new results"""
    # Load existing top proxies
    if os.path.exists(top_file):
        try:
            with open(top_file, 'r') as f:
                top_proxies = json.load(f)
        except:
            top_proxies = []
    else:
        top_proxies = []
    
    # Add new results that meet the criteria (latency <= 300ms)
    for result in new_results:
        if result['latency'] <= 300 and result['error'] is None:
            # Check if this proxy is already in the list
            found = False
            for i, proxy in enumerate(top_proxies):
                if proxy['proxy'] == result['proxy']:
                    # Update existing entry
                    top_proxies[i] = result
                    found = True
                    break
            
            # Add new entry if not found
            if not found:
                top_proxies.append(result)
    
    # Sort by latency and keep only the top ones
    top_proxies.sort(key=lambda x: x['latency'])
    top_proxies = top_proxies[:max_entries]
    
    # Add timestamp
    for proxy in top_proxies:
        proxy['last_updated'] = datetime.now().isoformat()
    
    # Save to file
    with open(top_file, 'w') as f:
        json.dump(top_proxies, f, indent=2)
    
    print(f"[INFO] Updated top {len(top_proxies)} proxies with latency <= 300ms")

def scan_proxies():
    """Main scanning function to be run periodically"""
    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting proxy scan...")
    
    # Initialize cache
    cache = load_cache()
    cache = clear_old_cache(cache)  # Clear expired entries
    
    # Always fetch fresh proxies
    proxies_list = fetch_all_proxies('misc.txt')
    
    if not proxies_list:
        print("[WRN] No valid proxies found!")
        return

    target_host = "httpbin.org"
    target_port = 80
    max_workers = 100
    max_latency = 800  # For initial filtering
    
    print(f"[INFO] Testing {len(proxies_list)} valid proxies with {max_workers} threads...")
    good_proxies = []
    proxies_to_test = []

    # Check cache first
    for proxy in proxies_list:
        cache_key = f"{proxy}_{target_host}_{target_port}"
        if cache_key in cache and is_cache_valid(cache[cache_key]):
            # Use cached result
            cached_result = cache[cache_key]
            if cached_result['error'] is None and cached_result['latency'] <= max_latency:
                good_proxies.append(cached_result)
                print(f"✅ {cached_result['proxy']} - {cached_result['latency']:.0f}ms (cached)")
        else:
            # Need to test this proxy
            proxies_to_test.append(proxy)

    # Test proxies not in cache or with expired cache
    if proxies_to_test:
        print(f"[INFO] Testing {len(proxies_to_test)} proxies not in cache...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(SOCKS5Checker(proxy, (target_host, target_port)).check): proxy for proxy in proxies_to_test}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                cache_key = f"{result['proxy']}_{target_host}_{target_port}"
                
                # Store result in cache
                result['timestamp'] = datetime.now().isoformat()
                cache[cache_key] = result
                
                if result['error'] is None and result['latency'] <= max_latency:
                    good_proxies.append(result)
                    print(f"✅ {result['proxy']} - {result['latency']:.0f}ms")
    
    # Save updated cache
    save_cache(cache)

    print(f"[INFO] Results: {len(good_proxies)}/{len(proxies_list)} proxies under {max_latency}ms")

    # Update top proxies list with those having latency <= 300ms
    top_proxies = [p for p in good_proxies if p['latency'] <= 300]
    update_top_proxies(top_proxies)
    
    # Run bandwidth tests on top 10 proxies
    if top_proxies:
        top_proxies.sort(key=lambda x: x['latency'])
        top_10 = top_proxies[:10]

        print("[INFO] Running bandwidth tests on top 10 proxies...")

        # Run bandwidth tests in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            bandwidth_results = list(executor.map(run_bandwidth_tests, top_10))

        # Sort by bandwidth
        bandwidth_results.sort(key=lambda x: x['bandwidth_mbps'], reverse=True)

        # Display results
        print("\n[HIT] Top 10 Proxies by Average Bandwidth:")
        print("=" * 65)
        
        for i, result in enumerate(bandwidth_results, 1):
            test_str = "/".join(f"{s:.1f}" for s in result['tests'])
            print(f"{i:2d}. {result['proxy']} - {result['bandwidth_mbps']:.1f} Mbps " +
                  f"({test_str}) - {result['latency']:.0f}ms")

        # Save detailed results
        with open('top10_socks5.txt', 'w') as f:
            for result in bandwidth_results:
                test_str = "/".join(f"{s:.1f}" for s in result['tests'])
                f.write(f"{result['proxy']} | {result['bandwidth_mbps']:.1f} Mbps " +
                        f"({test_str}) | {result['latency']:.0f}ms\n")

        print(f"\nSaved detailed results to top10_socks5.txt")
    
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Scan completed")

def run_scheduler():
    """Run the scheduler in a separate thread"""
    while True:
        schedule.run_pending()
        time.sleep(1)

def main():
    """Main function to set up automatic scanning"""
    print("SOCKS5 Proxy Scanner - Auto Refresh Mode")
    print("=======================================")
    
    # Set up scheduling (every 5-15 minutes randomly)
    import random
    scan_interval = random.randint(5, 15)
    schedule.every(scan_interval).minutes.do(scan_proxies)
    
    print(f"[INFO] Will scan proxies every {scan_interval} minutes")
    print("[INFO] Press Ctrl+C to stop the scanner")
    
    # Run first scan immediately
    scan_proxies()
    
    # Start the scheduler in a separate thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping scanner...")

if __name__ == "__main__":
    main()
