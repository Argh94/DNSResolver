import socket
import struct
import threading
import random
import re

class DNSResolver:
    def __init__(self, retries=3):
        self.semaphore = threading.Semaphore(3)
        self.results = {}
        self.lock = threading.Lock()
        self.retries = retries

    def is_valid_domain(self, domain):
        """بررسی اعتبار دامنه"""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        return bool(re.match(pattern, domain))

    def build_dns_query(self, domain, record_type='A'):
        """ساخت بسته DNS برای A یا AAAA"""
        header = b''
        header += struct.pack('!H', random.randint(1, 65535))
        header += struct.pack('!H', 0x0100)
        header += struct.pack('!H', 1)
        header += struct.pack('!H', 0)
        header += struct.pack('!H', 0)
        header += struct.pack('!H', 0)

        question = b''
        for part in domain.split('.'):
            question += struct.pack('!B', len(part)) + part.encode()
        question += b'\x00'

        query_type = 1 if record_type == 'A' else 28
        question += struct.pack('!H', query_type)
        question += struct.pack('!H', 1)

        return header + question

    def parse_dns_response(self, response, record_type='A'):
        """تجزیه پاسخ DNS برای استخراج IP"""
        try:
            position = 12
            while position < len(response):
                if response[position] >= 192:
                    position += 2
                    break
                if response[position] == 0:
                    position += 1
                    break
                position += response[position] + 1

            position += 4
            position += 10
            rdlength = struct.unpack('!H', response[position:position+2])[0]
            position += 2

            if record_type == 'A' and rdlength == 4 and position + 4 <= len(response):
                return '.'.join(str(b) for b in response[position:position+4])
            elif record_type == 'AAAA' and rdlength == 16 and position + 16 <= len(response):
                bytes_data = response[position:position+16]
                hex_str = ''.join(f'{b:02x}' for b in bytes_data)
                ipv6 = ':'.join(hex_str[i:i+4] for i in range(0, 32, 4))
                return ipv6
            return None
        except (struct.error, IndexError):
            return None

    def resolve_domain(self, domain):
        """رفع نام دامنه برای IPv4 و IPv6"""
        if not self.is_valid_domain(domain):
            with self.lock:
                self.results[domain] = "نام دامنه نامعتبر است"
            return

        self.semaphore.acquire()
        try:
            for record_type in ['A', 'AAAA']:
                ip = None
                for attempt in range(self.retries):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(5)

                    try:
                        query = self.build_dns_query(domain, record_type)
                        sock.sendto(query, ("1.1.1.1", 53))
                        response, _ = sock.recvfrom(1024)
                        ip = self.parse_dns_response(response, record_type)
                        if ip:
                            break
                    except socket.timeout:
                        continue
                    except Exception as e:
                        ip = f"خطا: {str(e)}"
                        break
                    finally:
                        sock.close()

                with self.lock:
                    key = f"{domain} ({record_type})"
                    self.results[key] = ip if ip else "پاسخی دریافت نشد یا تجزیه نشد"

        finally:
            self.semaphore.release()

def main():
    resolver = DNSResolver(retries=3)
    threads = []
    domains = [input(f"دامنه {i+1} را وارد کنید: ").strip() for i in range(3)]

    for domain in domains:
        thread = threading.Thread(target=resolver.resolve_domain, args=(domain,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    for domain in domains:
        for record_type in ['A', 'AAAA']:
            key = f"{domain} ({record_type})"
            print(f"آدرس IP برای {key}: {resolver.results.get(key, 'رفع نشد')}")

if __name__ == "__main__":
    main()
