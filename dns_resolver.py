import socket
import struct
import threading
import random
import re

class DNSResolver:
    def __init__(self, retries=3):
        # Allow up to 3 simultaneous DNS lookups
        self.semaphore = threading.Semaphore(3)
        # Store results for each domain
        self.results = {}
        # Lock for thread-safe writing to results
        self.lock = threading.Lock()
        # Number of retries for failed queries
        self.retries = retries

    def is_valid_domain(self, domain):
        """Check if the domain name is valid using regex."""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        return bool(re.match(pattern, domain))

    def build_dns_query(self, domain, record_type='A'):
        """Build DNS query for A (IPv4) or AAAA (IPv6) records."""
        # 1. Create DNS header (12 bytes total)
        header = b''
        header += struct.pack('!H', random.randint(1, 65535))  # Random Transaction ID
        header += struct.pack('!H', 0x0100)  # Flags (standard query)
        header += struct.pack('!H', 1)       # Questions count
        header += struct.pack('!H', 0)       # Answer count
        header += struct.pack('!H', 0)       # Authority count
        header += struct.pack('!H', 0)       # Additional count

        # 2. Create DNS question
        question = b''
        # Convert domain (e.g., "google.com" to "\x06google\x03com\x00")
        for part in domain.split('.'):
            question += struct.pack('!B', len(part)) + part.encode()
        question += b'\x00'  # End of domain name

        # 3. Add query type (A or AAAA) and class (IN)
        query_type = 1 if record_type == 'A' else 28  # A=1, AAAA=28
        question += struct.pack('!H', query_type)  # Type: A or AAAA
        question += struct.pack('!H', 1)           # Class: IN (Internet)

        # 4. Combine all parts
        return header + question

    def parse_dns_response(self, response, record_type='A'):
        """Parse DNS response for A (IPv4) or AAAA (IPv6) records."""
        try:
            # Skip first 12 bytes (DNS header)
            position = 12

            # Skip the question section
            while position < len(response):
                if response[position] >= 192:  # Compression marker
                    position += 2
                    break
                if response[position] == 0:    # End of domain name
                    position += 1
                    break
                position += response[position] + 1

            # Skip query type and class
            position += 4

            # Skip to the answer section
            position += 10

            # Get length of data
            rdlength = struct.unpack('!H', response[position:position+2])[0]
            position += 2

            # Extract IP address
            if record_type == 'A' and rdlength == 4 and position + 4 <= len(response):
                return '.'.join(str(b) for b in response[position:position+4])
            elif record_type == 'AAAA' and rdlength == 16 and position + 16 <= len(response):
                # Convert 16 bytes to IPv6 address (hex format)
                bytes_data = response[position:position+16]
                hex_str = ''.join(f'{b:02x}' for b in bytes_data)
                ipv6 = ':'.join(hex_str[i:i+4] for i in range(0, 32, 4))
                return ipv6
            return None
        except (struct.error, IndexError):
            return None

    def resolve_domain(self, domain):
        """Resolve domain for both IPv4 and IPv6 addresses."""
        # Validate domain
        if not self.is_valid_domain(domain):
            with self.lock:
                self.results[domain] = "Invalid domain name"
            return

        # Wait for available thread slot
        self.semaphore.acquire()
        try:
            # Try resolving both A and AAAA records
            for record_type in ['A', 'AAAA']:
                ip = None
                # Retry up to self.retries times
                for attempt in range(self.retries):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(5)  # Reduced timeout for retries

                    try:
                        # Send query to Cloudflare's DNS (1.1.1.1)
                        query = self.build_dns_query(domain, record_type)
                        sock.sendto(query, ("1.1.1.1", 53))

                        # Get response
                        response, _ = sock.recvfrom(1024)
                        ip = self.parse_dns_response(response, record_type)
                        if ip:
                            break  # Success, exit retry loop

                    except socket.timeout:
                        continue  # Retry on timeout
                    except Exception as e:
                        ip = f"Error: {str(e)}"
                        break
                    finally:
                        sock.close()

                # Store result safely
                with self.lock:
                    key = f"{domain} ({record_type})"
                    self.results[key] = ip if ip else "No response or failed to parse"

        finally:
            self.semaphore.release()

def main():
    # Create resolver with 3 retries
    resolver = DNSResolver(retries=3)
    threads = []

    # Get three domain names from user
    domains = []
    for i in range(3):
        domain = input(f"دامنه {i+1} را وارد کنید: ").strip()
        domains.append(domain)

    # Start a thread for each domain
    for domain in domains:
        thread = threading.Thread(target=resolver.resolve_domain, args=(domain,))
        threads.append(thread)
        thread.start()

    # Wait for all lookups to complete
    for thread in threads:
        thread.join()

    # Show results
    for domain in domains:
        for record_type in ['A', 'AAAA']:
            key = f"{domain} ({record_type})"
            print(f"آدرس IP برای {key}: {resolver.results.get(key, 'رفع نشد')}")

if __name__ == "__main__":
    main()
