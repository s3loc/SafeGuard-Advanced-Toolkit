"""
⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⡴⠋⠉⡊⢁⠀⠀⢬⠀⠉⠋⠈⠥⠤⢍⡛⠒⠶⣄⡀⠀⠀⠀
⠀⠀⠀⠀⣾⠥⠀⠀⠊⢭⣾⣿⣷⡤⠀⣠⡀⡅⢠⣶⣮⣄⠉⠢⠙⡆⠀⠀
⠀⠀⣠⡾⣁⡨⠴⠢⡤⣿⣿⣿⣿⣿⠸⡷⠙⣟⠻⣯⣿⣟⣃⣠⡁⢷⣄⠀
⠀⡼⡙⣜⡕⠻⣷⣦⡀⢙⠝⠛⡫⢵⠒⣀⡀⠳⡲⢄⣀⢰⣫⣶⡇⡂⠙⡇
⢸⡅⡇⠈⠀⠀⠹⣿⣿⣷⣷⣾⣄⣀⣬⣩⣷⠶⠧⣶⣾⣿⣿⣿⡷⠁⣇⡇
⠀⠳⣅⢀⢢⠡⠀⡜⢿⣿⣿⡏⠑⡴⠙⣤⠊⠑⡴⠁⢻⣿⣿⣿⠇⢀⡞⠀
⠀⠀⠘⢯⠀⡆⠀⠐⡨⡻⣿⣧⣤⣇⣀⣧⣀⣀⣷⣠⣼⣿⣿⣿⠀⢿⠀⠀
⠀⠀⠀⠈⢧⡐⡄⠀⠐⢌⠪⡻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⢸⠀⠀
⠀⠀⠀⠀⠀⠙⢾⣆⠠⠀⡁⠘⢌⠻⣿⣿⠻⠹⠁⢃⢹⣿⣿⣿⡇⡘⡇⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠛⠷⢴⣄⠀⢭⡊⠛⠿⠿⠵⠯⡭⠽⣛⠟⢡⠃⡇⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠲⠬⣥⣀⡀⠀⢀⠀⠀⣠⡲⢄⡼⠃⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠓⠒⠒⠒⠋⠉⠀⠀⠀


AS I AM A JUNIOR LEVEL PROGRAMMER, DO NOT TAKE MY MISTAKES TOO SERIOUSLY, PLEASE CONTACT ME WITH MY MISTAKES -s3loc_


DISCLAIMER OF LIABILITY:

The author(s) of this code accept no responsibility or liability for any damages or issues arising from the use or misuse of this code. Use this code at your own risk. By using this code, 
you agree that the author(s) are not responsible for any consequences or harm that may occur, whether direct or indirect, as a result of using this code. 

This code is provided "as is" without any warranties or guarantees. The user assumes all responsibility for ensuring the suitability of this code for their specific needs and requirements.
"""













import requests
import subprocess
import logging
import os
import re

# Günlükleme yapılandırması
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def check_default_credentials(url):
    """Varsayılan kimlik bilgilerini kontrol eder."""
    default_creds = [
        ('admin', 'admin'), 
        ('root', 'root'), 
        ('admin', 'password'), 
        ('user', 'user')
    ]
    for username, password in default_creds:
        response = requests.post(f'{url}/login', data={'username': username, 'password': password})
        if response.status_code == 200:
            logging.warning(f"Varsayılan kimlik bilgileri başarılı: {username}/{password}")
        else:
            logging.info(f"Varsayılan kimlik bilgileri geçersiz: {username}/{password}")

def check_server_headers(url):
    """Sunucu başlıklarını kontrol eder ve güvenlik açıklarını raporlar."""
    try:
        response = requests.get(url)
        headers = response.headers
        security_headers = [
            'X-Powered-By', 'Server'
        ]
        for header in security_headers:
            if header in headers:
                logging.warning(f"Güvenlik başlığı bulundu: {header}: {headers[header]}")
    except requests.RequestException as e:
        logging.error(f"Sunucu başlıkları kontrolü sırasında hata oluştu: {e}")

def check_file_permissions():
    """Dosya izinlerini kontrol eder."""
    try:
        sensitive_files = ['/etc/passwd', '/etc/shadow']
        for file in sensitive_files:
            if os.path.exists(file):
                permissions = oct(os.stat(file).st_mode)[-3:]
                if permissions != '600':
                    logging.warning(f"Dosya izinleri güvenli değil: {file} - İzinler: {permissions}")
    except Exception as e:
        logging.error(f"Dosya izinleri kontrolü sırasında hata oluştu: {e}")

def check_debug_mode(url):
    """Debug modunun açık olup olmadığını kontrol eder."""
    try:
        response = requests.get(f'{url}/debug')
        if response.status_code == 200:
            logging.warning("Debug modu açık!")
    except requests.RequestException as e:
        logging.error(f"Debug modu kontrolü sırasında hata oluştu: {e}")

def check_security_headers(url):
    """Güvenlik başlıklarının varlığını kontrol eder."""
    try:
        response = requests.get(url)
        headers = response.headers
        security_headers = [
            'X-Frame-Options', 'X-XSS-Protection', 'Strict-Transport-Security', 'Content-Security-Policy', 'Referrer-Policy', 'X-Content-Type-Options'
        ]
        missing_headers = [header for header in security_headers if header not in headers]
        if missing_headers:
            logging.warning(f"Eksik başlıklar: {', '.join(missing_headers)}")
    except requests.RequestException as e:
        logging.error(f"Güvenlik başlıkları kontrolü sırasında hata oluştu: {e}")

def check_unnecessary_services():
    """Gereksiz servisleri kontrol eder."""
    try:
        services = subprocess.check_output(['systemctl', 'list-units', '--type=service'], text=True)
        unnecessary_services = ['telnet', 'ftp', 'rsh', 'rcp']
        for service in unnecessary_services:
            if service in services:
                logging.warning(f"Gereksiz servis çalışıyor: {service}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Gereksiz servisler kontrolü sırasında hata oluştu: {e}")

def check_exposed_files(url):
    """Halka açık dosyaların varlığını kontrol eder."""
    try:
        response = requests.get(f'{url}/robots.txt')
        if response.status_code == 200:
            logging.info("robots.txt dosyası mevcut.")
        else:
            logging.warning("robots.txt dosyası bulunamadı.")
    except requests.RequestException as e:
        logging.error(f"robots.txt kontrolü sırasında hata oluştu: {e}")

def check_tls_configuration(url):
    """TLS yapılandırmasını kontrol eder."""
    try:
        response = requests.get(url, verify=False)  # Sertifikasız HTTPS isteği
        if 'TLS' in response.headers.get('X-Content-Type-Options', ''):
            logging.warning("TLS yapılandırması eksik veya yanlış!")
    except requests.RequestException as e:
        logging.error(f"TLS yapılandırması kontrolü sırasında hata oluştu: {e}")

def check_encryption_algorithms(url):
    """Şifreleme algoritmalarının doğruluğunu kontrol eder."""
    try:
        response = requests.get(f'{url}/encryption-status')
        if response.status_code == 200:
            encryption_algorithms = response.json().get('encryption_algorithms', [])
            if not encryption_algorithms:
                logging.warning("Şifreleme algoritmaları bulunamadı!")
            else:
                for algo in encryption_algorithms:
                    if algo not in ['AES-256', 'RSA-2048']:
                        logging.warning(f"Güvenli olmayan şifreleme algoritması kullanılıyor: {algo}")
    except requests.RequestException as e:
        logging.error(f"Şifreleme algoritmaları kontrolü sırasında hata oluştu: {e}")

def check_firewall_and_network_configuration():
    """Güvenlik duvarı ve ağ yapılandırmasını kontrol eder."""
    try:
        firewall_status = subprocess.check_output(['sudo', 'ufw', 'status'], text=True)
        if 'inactive' in firewall_status:
            logging.warning("Güvenlik duvarı kapalı!")
        else:
            logging.info("Güvenlik duvarı aktif.")

        # Açık portları kontrol et
        open_ports = subprocess.check_output(['sudo', 'netstat', '-tuln'], text=True)
        if '0.0.0.0' in open_ports:
            logging.warning("Açık portlar tespit edildi!")
    except subprocess.CalledProcessError as e:
        logging.error(f"Güvenlik duvarı ve ağ yapılandırması kontrolü sırasında hata oluştu: {e}")

def check_security_updates():
    """Güvenlik güncellemelerini kontrol eder."""
    try:
        updates = subprocess.check_output(['sudo', 'apt-get', 'update', '-s'], text=True)
        if 'upgradable' in updates:
            logging.warning("Güvenlik güncellemeleri mevcut!")
    except subprocess.CalledProcessError as e:
        logging.error(f"Güvenlik güncellemeleri kontrolü sırasında hata oluştu: {e}")

def check_misconfigured_redirects(url):
    """Hatalı yönlendirmeleri kontrol eder."""
    try:
        response = requests.get(url, allow_redirects=True)
        if response.history:
            for resp in response.history:
                if resp.status_code >= 300 and resp.status_code < 400:
                    logging.warning(f"Hatalı yönlendirme tespit edildi: {resp.url}")
    except requests.RequestException as e:
        logging.error(f"Hatalı yönlendirme kontrolü sırasında hata oluştu: {e}")

def check_exposed_api_endpoints(url):
    """API uç noktalarını kontrol eder."""
    try:
        endpoints = ['/api/v1/users', '/api/v1/admin', '/api/v1/data']
        for endpoint in endpoints:
            response = requests.get(f'{url}{endpoint}')
            if response.status_code == 200:
                logging.warning(f"API uç noktası açık: {endpoint}")
    except requests.RequestException as e:
        logging.error(f"API uç noktası kontrolü sırasında hata oluştu: {e}")

def perform_security_misconfiguration_tests(url):
    """Güvenlik yanlış yapılandırması testlerini yapar."""
    logging.info("Güvenlik yanlış yapılandırması testleri başlatılıyor...")

    # 1. Varsayılan kimlik bilgilerini kontrol et
    check_default_credentials(url)
    
    # 2. Sunucu başlıklarını kontrol et
    check_server_headers(url)
    
    # 3. Dosya izinlerini kontrol et
    check_file_permissions()
    
    # 4. Debug modunu kontrol et
    check_debug_mode(url)
    
    # 5. Güvenlik başlıklarını kontrol et
    check_security_headers(url)
    
    # 6. Gereksiz servisleri kontrol et
    check_unnecessary_services()
    
    # 7. Halka açık dosyaları kontrol et
    check_exposed_files(url)
    
    # 8. TLS yapılandırmasını kontrol et
    check_tls_configuration(url)
    
    # 9. Şifreleme algoritmalarını kontrol et
    check_encryption_algorithms(url)
    
    # 10. Güvenlik duvarı ve ağ yapılandırmasını kontrol et
    check_firewall_and_network_configuration()
    
    # 11. Güvenlik güncellemelerini kontrol et
    check_security_updates()
    
    # 12. Hatalı yönlendirmeleri kontrol et
    check_misconfigured_redirects(url)
    
    # 13. API uç noktalarını kontrol et
    check_exposed_api_endpoints(url)

if __name__ == "__main__":
    url = input("Test edilecek URL'i girin: ")
    perform_security_misconfiguration_tests(url)
