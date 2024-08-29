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
from requests.auth import HTTPBasicAuth

def perform_broken_access_control_test(base_url, admin_path, username, password):
    # 1. Giriş yap ve oturum açma isteğini gönder
    login_url = f"{base_url}/login"
    admin_url = f"{base_url}{admin_path}"

    # Kimlik doğrulama ile oturum aç
    session = requests.Session()
    login_response = session.post(login_url, auth=HTTPBasicAuth(username, password))

    if login_response.status_code == 200:
        print(f"[INFO] {username} başarılı bir şekilde giriş yaptı.")
    else:
        print(f"[ERROR] Giriş başarısız oldu. Status code: {login_response.status_code}")
        return

    # 2. Yönetici paneline erişim denemesi yap
    admin_response = session.get(admin_url)

    if admin_response.status_code == 200:
        print(f"[CRITICAL] Erişim kontrolü kırıldı! {username} admin sayfasına erişti.")
    elif admin_response.status_code == 403:
        print(f"[INFO] Erişim reddedildi. {username} admin sayfasına erişim izni yok.")
    else:
        print(f"[ERROR] Beklenmeyen durum: Status code: {admin_response.status_code}")

if __name__ == "__main__":
    # Kullanıcıdan test için gerekli bilgileri al
    base_url = input("Test edilecek URL'yi girin (örnek: http://example.com): ")
    admin_path = input("Admin sayfasının yolunu girin (örnek: /admin): ")
    username = input("Kullanıcı adını girin: ")
    password = input("Şifreyi girin: ")

    # Erişim kontrolü testini gerçekleştir
    perform_broken_access_control_test(base_url, admin_path, username, password)
