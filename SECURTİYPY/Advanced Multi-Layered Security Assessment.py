import requests
import socket
import subprocess
import logging
import ssl
from OpenSSL import crypto
from bs4 import BeautifulSoup
import nmap
import os
import json
from tqdm import tqdm
from zapv2 import ZAPv2
import time

# Günlükleme yapılandırması
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scan_ports(host):
    """Belirtilen ana bilgisayarda açık portları tarar."""
    open_ports = []
    with tqdm(total=65535, desc="Port Taraması", unit="port") as pbar:
        for port in range(1, 65536):  # Tüm port aralığını tarar
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
            pbar.update(1)
    logging.info(f"Açık portlar: {open_ports}")
    return open_ports

def check_http_headers(url):
    """HTTP başlıklarını kontrol eder ve güvenlik açıklarını raporlar."""
    try:
        response = requests.get(url)
        headers = response.headers
        
        security_headers = [
            'X-Frame-Options', 'X-XSS-Protection', 'Strict-Transport-Security', 'Content-Security-Policy', 'Referrer-Policy'
        ]
        missing_headers = [header for header in security_headers if header not in headers]
        
        if missing_headers:
            logging.warning(f"Eksik başlıklar: {', '.join(missing_headers)}")
        else:
            logging.info("Tüm güvenlik başlıkları mevcut.")
            
    except requests.RequestException as e:
        logging.error(f"HTTP başlıkları kontrolü sırasında hata oluştu: {e}")

def analyze_server_configuration():
    """Sunucu yapılandırmalarını analiz eder."""
    try:
        config_files = ['/etc/nginx/nginx.conf', '/etc/apache2/apache2.conf']
        for file in config_files:
            if os.path.exists(file):
                logging.info(f"Yapılandırma dosyası bulundu: {file}")
                with open(file, 'r') as f:
                    content = f.read()
                    if 'server_tokens' in content or 'ServerTokens' in content:
                        logging.warning(f"Sunucu sürümü bilgisi dosyada: {file}")
            else:
                logging.info(f"Yapılandırma dosyası bulunamadı: {file}")
                
    except Exception as e:
        logging.error(f"Sunucu yapılandırması analizi sırasında hata oluştu: {e}")

def check_firewall_rules():
    """Güvenlik duvarı kurallarını kontrol eder."""
    try:
        result = subprocess.run(['sudo', 'iptables', '-L'], capture_output=True, text=True)
        logging.info(f"Güvenlik duvarı kuralları:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Güvenlik duvarı kuralları kontrolü sırasında hata oluştu: {e}")

def perform_vulnerability_scan(url):
    """Otomatik güvenlik açığı taraması yapar."""
    try:
        nm = nmap.PortScanner()
        scan_result = nm.scan(hosts=url, arguments='-p-', timeout=30)
        logging.info(f"Güvenlik taraması sonucu:\n{scan_result}")
    except Exception as e:
        logging.error(f"Güvenlik açığı taraması sırasında hata oluştu: {e}")

def check_ssl_certificate(url):
    """SSL sertifikasını kontrol eder."""
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=url) as s:
            s.connect((url, 443))
            cert = s.getpeercert()
            logging.info(f"SSL Sertifikası:\n{cert}")
    except Exception as e:
        logging.error(f"SSL sertifikası kontrolü sırasında hata oluştu: {e}")

def analyze_logging_and_monitoring():
    """Günlükleme ve izleme sistemlerini kontrol eder."""
    try:
        logging.info("Günlükleme ve izleme sistemlerinin kontrolü yapılamıyor, daha fazla bilgi eklenebilir.")
        
    except Exception as e:
        logging.error(f"Günlükleme ve izleme kontrolü sırasında hata oluştu: {e}")

def perform_advanced_vulnerability_scan(url):
    """ZAP kullanarak daha kapsamlı güvenlik açığı taraması yapar."""
    try:
        api_key = 'your-api-key'
        zap = ZAPv2(apikey=api_key)

        zap.urlopen(url)
        logging.info(f"Tarama başlatıldı: {url}")

        with tqdm(total=100, desc="Spidering", unit="percent") as pbar:
            zap.spider.scan(url)
            while int(zap.spider.status()) < 100:
                pbar.update(int(zap.spider.status()) - pbar.n)
                time.sleep(5)
        
        with tqdm(total=100, desc="Active Scanning", unit="percent") as pbar:
            zap.ascan.scan(url)
            while int(zap.ascan.status()) < 100:
                pbar.update(int(zap.ascan.status()) - pbar.n)
                time.sleep(5)

        alerts = zap.core.alerts(baseurl=url)
        logging.info(f"ZAP Tarama Sonuçları:\n{json.dumps(alerts, indent=2)}")
    except Exception as e:
        logging.error(f"Gelişmiş güvenlik açığı taraması sırasında hata oluştu: {e}")

def perform_multilayered_tests(url):
    """Çok katmanlı güvenlik testleri yapar."""
    logging.info("Çok katmanlı testler başlatılıyor...")

    # 1. Port taraması
    scan_ports(url)
    
    # 2. HTTP başlıkları kontrolü
    check_http_headers(url)
    
    # 3. Sunucu yapılandırması analizi
    analyze_server_configuration()
    
    # 4. Güvenlik duvarı kuralları kontrolü
    check_firewall_rules()
    
    # 5. Güvenlik açığı taraması (Nmap)
    perform_vulnerability_scan(url)
    
    # 6. SSL sertifikası kontrolü
    check_ssl_certificate(url)
    
    # 7. Günlükleme ve izleme analizi
    analyze_logging_and_monitoring()
    
    # 8. Gelişmiş güvenlik açığı taraması (ZAP)
    perform_advanced_vulnerability_scan(url)

if __name__ == "__main__":
    url = input("Test edilecek URL'i girin: ")
    perform_multilayered_tests(url)
