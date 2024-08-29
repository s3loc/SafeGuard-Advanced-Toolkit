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












import os
import subprocess
import logging
import requests

# Günlükleme yapılandırması
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def execute_command(command):
    """Komutları çalıştırır ve çıktıyı döndürür."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            logging.info("Komut çalıştırıldı: %s", command)
            logging.info("Çıktı: %s", result.stdout)
        else:
            logging.warning("Komut çalıştırılamadı: %s", command)
            logging.warning("Hata: %s", result.stderr)
    except Exception as e:
        logging.error(f"Komut çalıştırılırken hata oluştu: {e}")

def check_sudo_privileges():
    """Sudo yetkilerini kontrol eder."""
    logging.info("Sudo yetkileri kontrol ediliyor...")
    execute_command('sudo -l')

def check_suid_binaries():
    """SUID binariyalarını kontrol eder."""
    logging.info("SUID binariyaları kontrol ediliyor...")
    execute_command('find / -perm -4000 -type f 2>/dev/null')

def check_world_writable_files():
    """Dünya tarafından yazılabilir dosyaları kontrol eder."""
    logging.info("Dünya tarafından yazılabilir dosyalar kontrol ediliyor...")
    execute_command('find / -writable -type f 2>/dev/null')

def check_scheduled_tasks():
    """Planlanmış görevleri kontrol eder."""
    logging.info("Planlanmış görevler kontrol ediliyor...")
    execute_command('crontab -l 2>/dev/null')
    execute_command('ls -la /etc/cron* 2>/dev/null')

def check_for_exploitable_services(url):
    """Sistem servisleri kontrol eder ve potansiyel açıklar arar."""
    logging.info("Sistem servisleri kontrol ediliyor...")
    try:
        response = requests.get(f"{url}/services")
        if response.status_code == 200:
            services = response.json()
            logging.info("Sistem servisleri bulundu: %s", services)
            # Her servis için ayrıntılı kontrol yapılabilir
        else:
            logging.warning("Sistem servisleri kontrolü başarısız. Sunucu yanıtı: %s", response.status_code)
    except requests.RequestException as e:
        logging.error(f"Sistem servisleri kontrolü sırasında hata oluştu: {e}")

def check_security_patches():
    """Güvenlik yamalarını kontrol eder."""
    logging.info("Güvenlik yamaları kontrol ediliyor...")
    execute_command('uname -a')
    execute_command('cat /etc/os-release')
    execute_command('dpkg --list | grep -i security')  # Debian/Ubuntu tabanlı sistemler
    execute_command('yum list updates --security')  # RedHat/CentOS tabanlı sistemler

def main():
    url = input("Test edilecek URL'i girin: ")
    
    # Yetki Yükseltme Testi
    check_sudo_privileges()
    check_suid_binaries()
    check_world_writable_files()
    check_scheduled_tasks()
    check_security_patches()
    
    # Potansiyel olarak istismar edilebilecek servislerin kontrolü
    check_for_exploitable_services(url)

if __name__ == "__main__":
    main()
