from burp import (IBurpExtender, IHttpListener, ITab, ICookie, IBurpExtenderCallbacks,ISessionHandlingAction)
from javax.swing import (GroupLayout, JPanel, JTextArea, JButton, JLabel, JSplitPane, JScrollPane, JTabbedPane, JTable, SwingUtilities, JFileChooser, BorderFactory)
from javax.swing.table import AbstractTableModel
import json



class BurpExtender(IBurpExtender, ISessionHandlingAction, IBurpExtenderCallbacks, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):

        self.callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("GNAWS")
        self.callbacks.registerSessionHandlingAction(self)
        self.out = callbacks.getStdout()

        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.cookie_file = None
        self.saved_cookies = []

        self.grpConfig = JPanel()
        self.grpConfig.setBorder(BorderFactory.createEtchedBorder())
        btnSave = JButton("Load Cookies", actionPerformed = self.loadCookies)
        self.grpConfig.add(btnSave)
        btnClear = JButton("Reset Cookies", actionPerformed = self.resetCookies)
        self.grpConfig.add(btnClear)
        self._splitpane.setLeftComponent(self.grpConfig)


        self.currentCookiePane = JPanel()
        self.savedCookiePane = JPanel()
        self.leftCookieText = JTextArea()
        self.leftCookieText.setColumns(47)
        self.leftCookieText.setRows(31)
        self.leftCookieText.setEditable(False)
        self.leftScrollText = JScrollPane()
        self.leftScrollText.add(self.leftCookieText)
        self.rightCookieText = JTextArea()
        self.rightCookieText.setColumns(47)
        self.rightCookieText.setRows(31)
        self.rightCookieText.setEditable(False)
        self.rightScrollText = JScrollPane()
        self.rightScrollText.add(self.rightCookieText)
        self.rightCookieText.setText("This is a test\ndid this work")

        self.infoPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self.infoPane.setLeftComponent(self.leftScrollText)
        self.infoPane.setRightComponent(self.rightScrollText)
        self.infoPane.setDividerLocation(0.50)
        self._splitpane.setRightComponent(self.infoPane)

        callbacks.customizeUiComponent(self._splitpane)
        callbacks.addSuiteTab(self)
        #self.preloadCookies()


    #ISessionHandlingAction functions
    def getActionName(self):
        return "Randomizer"
    
    def performAction(self, currentRequest, macroItems):
        pass

    #ITab functions

    def getTabCaption(self):
        return "GNAWS"
    def getUiComponent(self):
        return self._splitpane

    def loadCookies(self, e):
        fileChooser = JFileChooser()
        returnValue = fileChooser.showDialog(self.grpConfig,"Choose Cookie File")
        if returnValue == JFileChooser.APPROVE_OPTION:
            ## Lets get some cookies from the file and pray!
            self.cookie_file = fileChooser.getSelectedFile().getAbsolutePath()
            cookie_file_handle = open(self.cookie_file,"r")
            
            cookies_to_add = json.loads(cookie_file_handle.read())
            
            #Save the current cookies for reloading later
            cookies_in_use = self.callbacks.getCookieJarContents()
            cookies_to_save = []
            for cookie in cookies_in_use:
                cookies_to_save.append({"domain":cookie.getDomain(),"path":cookie.getPath(),"name":cookie.getName(),"value":cookie.getValue(),"expiration":cookie.getExpiration()})
                self.callbacks.updateCookieJar(IDeleter(cookie))
            self.saved_cookies = cookies_to_save
            #Load the cookies from the json results
            for domain in cookies_to_add.keys():
                for cookie in cookies_to_add[domain]:
                    t_cookie = IFaker(cookie["domain"],cookie["path"],cookie["cookie-name"],cookie["cookie-value"])
                    self.callbacks.updateCookieJar(t_cookie)
            self.loadCookieDict(cookies_to_save,self.rightCookieText)
            self.loadCookieClass(self.callbacks.getCookieJarContents(),self.leftCookieText)        

    def resetCookies(self, e):
        cookies_in_use = self.callbacks.getCookieJarContents()
        cookies_to_save = []
        #Delete current cookies in the CookieJar
        for cookie in cookies_in_use:
            self.callbacks.updateCookieJar(IDeleter(cookie))
        #Bring back the old cookies that we saved earlier
        for cookie in self.saved_cookies:
            t_cookie = IFaker(cookie["domain"],cookie["path"],cookie["name"],cookie["value"])
            self.callbacks.updateCookieJar(t_cookie)
        self.loadCookieDict(self.saved_cookies,self.rightCookieText)
        self.loadCookieClass(self.callbacks.getCookieJarContents(),self.leftCookieText)

    def loadCookieClass(self,cookies,textHandle):
        cookies_in_use = cookies
        site_based_cookies = {}
        qq = open("/Users/acooper/hate.cara","w+")
        for cookie in cookies_in_use:
            if cookie.getDomain() not in site_based_cookies.keys():
                site_based_cookies[cookie.getDomain()] = []
            site_based_cookies[cookie.getDomain()].append({"name":cookie.getName(),"value":cookie.getValue()})
        formatted_text = ""
        qq.write(formatted_text)
        for site in site_based_cookies.keys():
            formatted_text = "%s----- %s ------\n"%(formatted_text,site)
            for cookie in site_based_cookies[site]:
                formatted_text = "%s%s - %s - %s\n"%(formatted_text,site,cookie["name"],cookie["value"])
        textHandle.setText("Cookie File Loaded")


    def loadCookieDict(self,cookies,textHandle):
        cookies_in_use = cookies
        site_based_cookies = {}
        for cookie in cookies_in_use:
            if cookie["domain"] not in site_based_cookies.keys():
                site_based_cookies[cookie["domain"]] = []
            site_based_cookies[cookie["domain"]].append({"name":cookie["name"],"value":cookie["value"]})
        formatted_text = ""
        for site in site_based_cookies.keys():
            formatted_text = "%s----- %s ------\n"%(formatted_text,site)
            for cookie in site_based_cookies[site]:
                formatted_text = "%s%s - %s - %s\n"%(formatted_text,site,cookie["name"],cookie["value"])
        textHandle.setText("Cookie Values Saved")




class IFaker(ICookie):
    def __init__(self,domain,path,name,value,expiration=None):
        self.domain_value = domain
        self.path_value = path
        self.name_value = name
        self.value_value = value
        self.expiration_value = expiration

    def getDomain(self):
        return self.domain_value

    def getPath(self):
        return self.path_value        

    def getName(self):
        return self.name_value

    def getValue(self):
        return self.value_value

    def getExpiration(self):
        return self.expiration_value    

class IDeleter(ICookie):
    def __init__(self,cookie):
        self.domain_value = cookie.getDomain()
        self.path_value = cookie.getPath()
        self.name_value = cookie.getName()
        self.value_value = cookie.getValue()
        self.expiration_value = cookie.getExpiration()

    def getDomain(self):
        return self.domain_value

    def getPath(self):
        return self.path_value        

    def getName(self):
        return self.name_value

    def getValue(self):
        return None

    def getExpiration(self):
        return self.expiration_value        

