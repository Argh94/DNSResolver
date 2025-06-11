import dns.resolver
import re
import threading

class SimpleDNSResolver:
    def __init__(self, retries=3):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['1.1.1.1']
        self.resolver.timeout = 5
        self.resolver.lifetime = 5 * retries
        self.results = {}
        self.lock = threading.Lock()
        self.retries = retries

    def is_valid_domain(self, domain):
        """بررسی اعتبار دامنه"""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        return bool(re.match(pattern, domain))

    def resolve_domain(self, domain):
        """رفع نام دامنه برای IPv4 و IPv6"""
        if not self.is_valid_domain(domain):
            with self.lock:
                self.results[domain] = "نام دامنه نامعتبر است"
            return

        for record_type in ['A', 'AAAA']:
            key = f"{domain} ({record_type})"
            try:
                answers = self.resolver.resolve(domain, record_type)
                ip_list = [str(rdata) for rdata in answers]
                with self.lock:
                    self.results[key] = ip_list[0] if ip_list else "پاسخی دریافت نشد"
            except dns.resolver.NoAnswer:
                with self.lock:
                    self.results[key] = "پاسخی دریافت نشد"
            except dns.resolver.NXDOMAIN:
                with self.lock:
                    self.results[key] = "دامنه وجود ندارد"
            except Exception as e:
                with self.lock:
                    self.results[key] = f"خطا: {str(e)}"

def main():
    resolver = SimpleDNSResolver(retries=3)
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
