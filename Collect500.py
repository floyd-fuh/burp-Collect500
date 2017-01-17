from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from java.awt.event import ActionListener
from java.io import PrintWriter
from java.util import ArrayList
from java.util import List
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing.event import DocumentListener
from javax.swing import JCheckBox
from javax.swing import SwingUtilities
from javax.swing import JTextField
from javax.swing.table import AbstractTableModel
from threading import Lock

import difflib
import time

#I would have preferred to *not* write this plugin: https://github.com/nccgroup/BurpSuiteLoggerPlusPlus/issues/23

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel, ActionListener, DocumentListener):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Collect500")
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._main_jtabedpane = JTabbedPane()
        
        # The split pane with the log and request/respponse details
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
                
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        
        #Setup the options
        self._optionsJPanel = JPanel()
        gridBagLayout = GridBagLayout()
        gbc = GridBagConstraints()
        self._optionsJPanel.setLayout(gridBagLayout)
        
        self.collect_codes = []
        self.collect_codes_checkboxes = []
        for i in xrange(1, 6):
            collect = JLabel("Collect "+ str(i*100)+"s")
            gbc.gridy=i-1
            gbc.gridx=0
            self._optionsJPanel.add(collect, gbc)
            checkbox = JCheckBox("", False)
            if i == 5:
                checkbox.setSelected(True)
                self.collect_codes.append(i)
            self.collect_codes_checkboxes.append(checkbox)
            checkbox.addActionListener(self)
            gbc.gridx=1
            self._optionsJPanel.add(checkbox, gbc)
            callbacks.customizeUiComponent(checkbox)
        
        about = "<html>"
        about += "Author: floyd, @floyd_ch, http://www.floyd.ch<br>"
        about += "<br>"
        about += "<h3>Collects request/responses by HTTP response code</h3>"
        about += "<p style=\"width:500px\">"        
        about += "This plugin collects responses that have a specified status code (default: 500s). "
        about += "I would have preferred to *not* write this plugin: https://github.com/nccgroup/BurpSuiteLoggerPlusPlus/issues/23 ."
        about += "</p>"
        about += "</html>"
        self.JLabel_about = JLabel(about)
        self.JLabel_about.setLayout(GridBagLayout())
        self._aboutJPanel = JScrollPane(self.JLabel_about)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
        # add the splitpane and options to the main jtabedpane
        self._main_jtabedpane.addTab("Collection", None, self._splitpane, None)
        self._main_jtabedpane.addTab("Options", None, self._optionsJPanel, None)		
        self._main_jtabedpane.addTab("About & README", None, self._aboutJPanel, None)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
                
    #
    # implement what happens when options are changed
    #
    
    def changedUpdate(self, document):
        pass
    
    def removeUpdate(self, document):
        self.actionPerformed(None)
    
    def insertUpdate(self, document):
        self.actionPerformed(None)
    
    def actionPerformed(self, actionEvent):
        self._lock.acquire()
        self.collect_codes = []
        for index, checkbox in enumerate(self.collect_codes_checkboxes):
            if checkbox.isSelected():
                self.collect_codes.append((index+1))
        
        print self.collect_codes
        
        self._lock.release()
    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "Collect500"
    
    def getUiComponent(self):
        return self._main_jtabedpane
        
    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
            if not self._callbacks.isInScope(url):
                #print iRequestInfo.getUrl(), "is not in scope"
                return
            iResponseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
            code = iResponseInfo.getStatusCode()
            if code < 100 or code >= 600 or code//100 in self.collect_codes:
                #print "Code and type:", code, type(code)
                # create a new log entry with the message details
                row = self._log.size()
                self._log.add(LogEntry(str(code), self._callbacks.saveBuffersToTempFiles(messageInfo), url))
                self.fireTableRowsInserted(row, row)

    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Status"
        if columnIndex == 1:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return str(logEntry._status)
        if columnIndex == 1:
            return logEntry._url.toString()
        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

#
# extend JTable to handle cell selection
#
    
class Table(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        return
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
        return
    
#
# class to hold details of each log entry
#

class LogEntry:

    def __init__(self, status, requestResponse, url):
        self._status = status
        self._requestResponse = requestResponse
        self._url = url
        return
      