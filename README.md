# Cookie Sheet
Cookie Sheet is a conglomeration of a number of post-exploitation cookie stealing techniques from across the Internet combined with a burp extension. Together these tools allow an attacker with access to another system to get the cookies from that system's users and impersonate them locally for scanning using burpsuite.

## Installing

1. Clone from this github repo that you are already at!
2. `pip install -r requirements.txt`
3. (Optional) For target Windows systems that don't have python installed, from a Windows machine that does: `pyinstaller --onefile cookie_dough.py`


## Usage

### Harvesting Cookies

After Magically uploading `cookie_dough.py` to the end user host:

`user@CookieStealingHost:$ python cookie_dough.py`

If the end user host is running macOS/OSX or Linux, upload `keychain_dump.py` and run:
 
`user@CookieStealingHost:$ python keychain_dump.py`

 Magically download the resulting `cookie_dough.zip` (and `k.zip` if macOS/OSX or Linux) to your local machine and decrypt the stolen cookies:

`user@CookieJackingHost:$ python cookie_sheet.py`

Don't forget to clean up behind you...


### Using the GNAWS Burp extension
1. Start burpsuite and load GNAWS.py as an extension
2. Click the Cookie Cloner tab and click load cookies
3. Navigate to your cookie.json file and upload it
4. When done, click "Reset Cookies" to revert to your previously saved state

## Links

* https://github.com/n8henrie/pycookiecheat
* http://securitylearn.net/wp-content/uploads/tools/iOS/BinaryCookieReader.py
* https://github.com/python/typeshed/pull/1241
* https://github.com/mnagel/gnome-keyring-dumper
