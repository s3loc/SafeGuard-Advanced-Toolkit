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





from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import base64
import requests

class CryptographicFailureTester:
    def __init__(self, base_url, endpoint):
        self.base_url = base_url
        self.endpoint = endpoint

    def des_decrypt(self, key, encrypted_text):
        cipher = DES.new(key, DES.MODE_ECB)
        decrypted_text = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), DES.block_size)
        return decrypted_text.decode('utf-8')

    def aes_decrypt(self, key, iv, encrypted_text):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_text = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), AES.block_size)
        return decrypted_text.decode('utf-8')

    def perform_test(self, key, iv, encrypted_data, method='DES'):
        if method == 'DES':
            print("[INFO] DES Şifreleme Testi Başlatılıyor...")
            decrypted_data = self.des_decrypt(key, encrypted_data)
        elif method == 'AES':
            print("[INFO] AES Şifreleme Testi Başlatılıyor...")
            decrypted_data = self.aes_decrypt(key, iv, encrypted_data)
        else:
            raise ValueError("Desteklenmeyen şifreleme metodu.")

        print(f"[INFO] Decrypted Data: {decrypted_data}")

        # Decrypt edilen veriyi sunucuya gönderme
        response = self.send_to_server(decrypted_data)
        self.process_response(response)

    def send_to_server(self, decrypted_data):
        test_url = f"{self.base_url}{self.endpoint}"
        print(f"[INFO] Veri sunucuya gönderiliyor: {test_url}")
        response = requests.post(test_url, data={"data": decrypted_data})
        return response

    def process_response(self, response):
        if response.status_code == 200:
            print("[SUCCESS] Sunucuya başarıyla erişildi ve yanıt alındı.")
        elif response.status_code == 403:
            print("[INFO] Erişim reddedildi. Şifrelenmiş veri uygun şekilde korundu.")
        else:
            print(f"[ERROR] Beklenmeyen durum: Status code: {response.status_code}")

if __name__ == "__main__":
    # Kullanıcıdan URL, endpoint, şifreleme anahtarı ve şifreli veriyi al
    base_url = input("Test edilecek URL'yi girin (örnek: http://example.com): ")
    endpoint = input("Endpoint'i girin (örnek: /test): ")
    method = input("Şifreleme metodunu seçin (DES/AES): ").strip().upper()

    if method == 'DES':
        key = input("DES Şifreleme anahtarını girin (8 karakter): ").encode('utf-8')
        encrypted_data = input("DES Şifreli veriyi girin: ")
        iv = None
    elif method == 'AES':
        key = input("AES Şifreleme anahtarını girin (16, 24, 32 karakter): ").encode('utf-8')
        iv = input("AES Initialization Vector (IV) girin (16 karakter): ").encode('utf-8')
        encrypted_data = input("AES Şifreli veriyi girin: ")
    else:
        raise ValueError("Desteklenmeyen şifreleme metodu.")

    # Kriptografik hatalar testini gerçekleştir
    tester = CryptographicFailureTester(base_url, endpoint)
    tester.perform_test(key, iv, encrypted_data, method)
