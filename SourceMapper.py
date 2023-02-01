from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
import re
import unicodedata
from os.path import exists
from jarray import array
from javax.swing import (GroupLayout, JPanel, JCheckBox, JTextField, JLabel, JButton)


class BurpExtender(IBurpExtender, IHttpListener, ITab):


    def debug(self, message, lvl=1):
        if int(self.debugLevel.text) >= lvl:
            print(message)
        return


    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # define all the options for the config tab
        self.onlyInScope = self.defineCheckBox("Only in scope resources", False)
        self.onlyInScope.setToolTipText("Check to only work within the defined scope")
        #automatically set the program to inject into header
        self.header = self.defineCheckBox("Sourcemap directive to header", True)
        self.header.setToolTipText("Check to inject sourcemap to header")
        self.body = self.defineCheckBox("Sourcemap directive to body", False)
        self.header.setToolTipText("Check to inject sourcemap to body")

        

        self.debugLevel = JTextField(str(1), 1)
        self.debugLevelLabel = JLabel("Debug level (0-3)")
        self.debugLevel.setToolTipText("Values 0-3, bigger number is more debug output, 0 is zero debug output")
        self.debugLevelGroup = JPanel()
        self.debugLevelGroup.add(self.debugLevelLabel)
        self.debugLevelGroup.add(self.debugLevel)


        self.mapInjectionFilesPath = JTextField('/home/user/mapfiles/')
        self.mapInjectionFilesPathLabel = JLabel('Location to map files on local disk')
        self.mapInjectionFilesPath.setToolTipText("Absolute paths recommended.  Files must have the same name and "
                                                  "file extension as original resource with the additional '.map' "
                                                  "file extension")
        self.mapInjectionFilesPathGroup = JPanel()
        self.mapInjectionFilesPathGroup.add(self.mapInjectionFilesPathLabel)
        self.mapInjectionFilesPathGroup.add(self.mapInjectionFilesPath)

        

        # build the settings tab
        self.tab = JPanel()
        layout = GroupLayout(self.tab)
        self.tab.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        layout.setHorizontalGroup(
            layout.createSequentialGroup()
            .addGroup(layout.createParallelGroup()
                .addComponent(self.onlyInScope, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.mapInjectionFilesPathGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.debugLevelGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.header, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.body, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                      )
        )
        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addComponent(self.onlyInScope, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.mapInjectionFilesPathGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.debugLevelGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.header, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.body, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
        )


        # start "doing" things for real
        self.debug('Loading extension...')

        callbacks.setExtensionName("SourceMapper")
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)


    def defineCheckBox(self, caption, selected=True, enabled=True):
        checkBox = JCheckBox(caption)
        checkBox.setSelected(selected)
        checkBox.setEnabled(enabled)
        return checkBox


    def getTabCaption(self):
        return ("Source Mapper")


    def getUiComponent(self):
        return self.tab


    def processHttpMessage(self, toolFlag, messageIsRequest, message):
        self.debug('Processing message...', 3)
        # we only process the responses (and get the bits of the request we need when they are responded to)
        if messageIsRequest:
            self.debug('Message is a REQ so discarding', 3)
            return

        httpService = message.getHttpService()
        request = self._helpers.analyzeRequest(httpService, message.getRequest())
        reqURL = request.getUrl()
    

        # check if the requested resource is within permitted scope
        if self.onlyInScope.isSelected() and not self._callbacks.isInScope(reqURL):
            self.debug('Not in-scope and only in-scope permitted', 2)
            return
        else:
            # ignore any query string parameters
            reqResource = str(reqURL).split('?')[0]
            self.debug('Resource in full: ' + reqResource, 3)

            # if the resource requested is either a JS file or a CSS file then mark it for processing
            isTargetResource = False
            isMapResource = False
            resourceIsJS = False
            mapIsJS = False
            resourceIsCSS = False

            # pull the headers fairly early so that we can check for MIME types as well as file extensions to identify
            # source mappable content
            resInfo = self._helpers.analyzeResponse(message.getResponse())
            resHeaderBytes = message.getResponse()[:resInfo.getBodyOffset()]
            resHeaderStr = self._helpers.bytesToString(resHeaderBytes)

            #check type of resource
            if re.search("\.js$", reqResource) or re.search('Content-Type: text/javascript', resHeaderStr,
                                                            flags=re.IGNORECASE):
                isTargetResource = True
                resourceIsJS = True
            if re.search("\.css$", reqResource):
                isTargetResource = True
                resourceIsCSS = True
            if re.search("\.map$", reqResource):
                isMapResource = True
                mapIsJS = True

            if isTargetResource or isMapResource:
                resBodyBytes = message.getResponse()[resInfo.getBodyOffset():]
                resBodyStr = self._helpers.bytesToString(resBodyBytes)
                self.debug("Res body: " + str(resBodyStr[:40]), 3)
    
                #find map directive
                sourceMapDirectiveFound = False
                if resourceIsJS or resourceIsCSS:
                    if re.search('X-SourceMap:', resHeaderStr):
                        sourceMapDirectiveFound = True
                    if re.search('//# sourceMappingURL=', resBodyStr):
                        sourceMapDirectiveFound = True
                    if sourceMapDirectiveFound:
                        self.debug('Source map directive found, no need for intervention', 2)
                        return
                    
                    #check whether either the header checkbox is selected or whether SRI is used
                    #if so inject sourcemap into header
                    #if header & body checkboxes both selected, inject into header
                    if self.header.isSelected():
                        #insert source map directive into header
                        sourcemapHeader = "\r\nX-SourceMap: " + reqResource + '.map\n\n'
                        resHeaderStr = resHeaderStr.strip()
                        newResHeaderStr = resHeaderStr + sourcemapHeader
                        newResHeaderBytes = array(bytearray(newResHeaderStr.encode('utf-8')), 'b')
                        message.setResponse(newResHeaderBytes + resBodyBytes)
                        self.debug('Sourcemap directive injected into header')
                        self.debug("New Res Header: " + str(newResHeaderStr))
                        

                    #if SRI not used and header checkbox not selected, check whether body checkbox is selected
                    #if so inject sourcemap into body
                    elif self.body.isSelected():
                        sourcemapDirectiveStr = '//# sourceMappingURL=' + reqResource + '.map' + '\n'
                        sourcemapDirectiveBytes = array(bytearray(sourcemapDirectiveStr.encode('utf-8')), 'b')
                        newResBodyBytes = sourcemapDirectiveBytes + resBodyBytes
                        newResBodyStr = self._helpers.bytesToString(newResBodyBytes)
                        sourceMapDirectiveLen = len(sourcemapDirectiveStr)
                        self.debug("New Res body: " + str(newResBodyStr[:40]), 2)

                        # body has been changed so Content-Length headers probably need changing
                        # Update the Content-Length headers, if needed
                        if re.search('Content-Length: ', resHeaderStr, re.IGNORECASE):
                            self.debug('Content-Length header needs update, sending new body with updated headers', 2)
                            # calculate the length of the body following the additional content being injected
                            # we don't want to blat the original value with a newly calculated value because
                            # we want to retain any original application behaviour
                        
                            self.debug('Full headers from request are:\n{}'.format(resHeaderStr), 3)
                            originalContentLengthHeader = re.findall(r'^Content-Length: (?:[0-9]+)', resHeaderStr,
                                                                    flags=re.IGNORECASE | re.MULTILINE)
                            self.debug('Content length header is: {}'.format(originalContentLengthHeader))
                            if len(originalContentLengthHeader) > 1:
                                self.debug('Multiple Content-Length headers found, only updated the first', 2)
                            self.debug('The whole rsplit identifying the header: {}'.
                                    format(originalContentLengthHeader[0].rsplit(' ')))
                            originalContentLengthHeaderKey = originalContentLengthHeader[0].rsplit(' ', 1)[0] + ' '
                            originalContentLengthHeaderValue = int(originalContentLengthHeader[0].split(' ')[-1])
                            newContentLengthHeaderValue = originalContentLengthHeaderValue + sourceMapDirectiveLen
                            self.debug('Original content length header is: {}'.format(originalContentLengthHeader[0]), 2)
                            self.debug('Injected header is {} bytes.  New Content-Length header should be {} bytes'.
                                    format(sourceMapDirectiveLen, newContentLengthHeaderValue), 2)
                            newResHeaderStr = re.sub(r'^Content-Length: (?:[0-9]+)', originalContentLengthHeaderKey +
                                                    str(newContentLengthHeaderValue), resHeaderStr, count=1,
                                                    flags=re.IGNORECASE | re.MULTILINE)
                            newResHeaderBytes = array(bytearray(newResHeaderStr.encode('utf-8')), 'b') 
                            
                            message.setResponse(newResHeaderBytes + newResBodyBytes)
                            self.debug('Sourcemap directive injected into body')

                        #if Content-Length headers don't need changing, inject with original headers
                        else:
                            self.debug('No Content-Length header to update, sending new body with original headers', 2)
                            message.setResponse(resHeaderBytes + newResBodyBytes)
                            self.debug('Sourcemap directive injected into body')
                    
                    #if neither checkbox is selected, prompt user to specify
                    else:
                        self.debug("Specify where to inject sourcemap")

                                        
                if isMapResource:
                    self.debug('Map resource requested: ' + reqResource, 2)
                    validMapFound = False
                    if mapIsJS:
                        if re.search('^var map = {"version"', resBodyStr):
                            validMapFound = True
                        if not validMapFound:
                            self.debug('Requested map file not valid', 2)
                            resourceFileName = str(reqResource).split('/')[-1]
                            injectableMapFile = self.mapInjectionFilesPath.text + resourceFileName
                            if exists(injectableMapFile):
                                self.debug('Injectable map file found at: ' + injectableMapFile, 1)
                                # load the file
                                injectableMapFileHandle = open(injectableMapFile, 'r')
                                injectableMapFileStr = injectableMapFileHandle.read()

                                # identify what encoding it is using if it isn't something "normal"
                                injectableMapFileStrEncoding = self.detectStringEncoding(injectableMapFileStr)
                                self.debug('Source map for injection is ' + str(injectableMapFileStrEncoding) + ' encoded', 3)

                                # flatten any undesirable characters, such "left double quotes" that just screw up the bytearray conversion
                                injectableMapFileBytes_step0 = unicodedata.normalize('NFKD', injectableMapFileStr).encode('ascii', 'ignore')

                                # finally, make sure everything is in utf-8 (as this is what the spec says it should be), probably a bit mute by this point though
                                # in any case it needs to be converted to a Python bytearray, ready to be converted into a Java array
                                if injectableMapFileStrEncoding:
                                    injectableMapFileBytes_step1 = bytearray(injectableMapFileBytes_step0.decode(injectableMapFileStrEncoding).encode('utf-8'))
                                else:
                                    self.debug('!!!Unknown charset encountered - may not be able to inject source map!!!', 0)
                                    injectableMapFileBytes_step1 = bytearray(injectableMapFileBytes_step0.encode('utf-8'))

                                # convert into a Java array (the joys of working in Jython I suppose)
                                injectableMapFileBytes_step2 = array(injectableMapFileBytes_step1, 'b')

                                # ensure that the content type is specified correctly (may not matter but good to be sure)
                                newResHeaderStr = resHeaderStr.replace('Content-Type: text/html', 'Content-Type: application/javascript; charset=utf-8')
                                self.debug('Inserted Content-Type header', 2)


                                # inject the local response!  Phew...
                                # convert the new header string back into a bytearray and then into a Java array
                                newResHeaderBytes = array(bytearray(newResHeaderStr.encode('utf-8')), 'b')
                                message.setResponse(newResHeaderBytes + injectableMapFileBytes_step2)
                                self.debug('!!!Offline source map file injected!!!', 1)
                            else:
                                self.debug('No injectable map file found (' + injectableMapFile + ' attempted)', 2)

                else:
                    self.debug('Request is not for a target resource or map', 3)

        # end of function - return!
        return


    def detectStringEncoding(self, string):
        codecs = ['ASCII', 'UTF-8', 'cp1252', 'latin-1', 'ISO 8859-1', 'ISO 8859-15', 'GBK', 'JIS', 'UCS-2', 'UCS-4', 'UTF-16', 'UTF-32', 'UTF-42']
        for i in codecs:
            try:
                string.decode(i)
                return i
            except UnicodeDecodeError:
                pass
        return False

    def extensionUnloaded(self):
        self.debug('Unloading extension...')
