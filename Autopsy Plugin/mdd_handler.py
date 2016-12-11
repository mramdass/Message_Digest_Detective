#
#   Munieshwar (Kevin) Ramdass
#   Professor Marc Budofsky
#   Message Digest Detective
#   3 December 2016
#
#   Ingest Module code in this module is modeled after the
#   in the following link:
#   https://www.osdfcon.org/presentations/2014/Python-Autopsy-OSDFCon2014.pdf
#

try:
    import jarray, inspect, os, sys, json, argparse, urllib, urllib2
    from math import ceil
    from threading import Thread
    from time import time
    from time import sleep
    from zipfile import ZipFile
    from subprocess import check_output
    from datetime import datetime
    from hashlib import sha1
    from java.lang import System
    from java.util.logging import Level
    from org.sleuthkit.datamodel import SleuthkitCase, AbstractFile, ReadContentInputStream, BlackboardArtifact, BlackboardAttribute, TskData
    from org.sleuthkit.autopsy.ingest import IngestModule, DataSourceIngestModule, FileIngestModule, IngestModuleFactoryAdapter, IngestServices
    from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
    from org.sleuthkit.autopsy.coreutils import Logger
    from org.sleuthkit.autopsy.casemodule import Case
    from org.sleuthkit.autopsy.casemodule.services import Services, FileManager
except Exception as e:
    print '\t', e
    exit()

# Autopsy local path
autopsy = 'C:/Users/mramd/AppData/Roaming/autopsy/python_modules/MDD/'

# Map of MD5 hashes to file name from desired directory
digests = {} # from Image
hashes = {} # from RDS

# Activate thread wait time in seconds
count = 0
halt = False

# VirusTotal API key which allows for 4 requests per minute
API_KEY = ''

# Extensions to look at - Note these are execuatables or may contain exectuable code that Windows treat as executable
#extensions = ('.dll', '.exe', '.pif', '.application', '.gadget', '.msi', '.com', '.scr', '.hta', '.cpl', '.msc', '.jar')
extensions = ('.com')

def load_map(name):
    with open(name) as d: return json.load(d)

def print_map(name): return json.dumps(name, sort_keys = True, indent = 4, separators = (',', ': '))

def configure():
    '''
        Checks for valid API Key
    '''
    global API_KEY
    data = load_map(autopsy + 'configure.json')
    API_KEY = data['Key']
    if API_KEY == 'None': raise Exception('\tMust have a valid VirusTotal API Key')
    
def write_map(name, hashmap):
    with open(name, 'w') as w: w.write(print_map(hashmap).encode('utf-8'))

def delay():
    global count, halt
    halt = True
    sleep(60)
    halt = False
    count = 0

def request_virustotal(digest):
    '''
        VirusTotal API Usuage:
        https://www.virustotal.com/en/documentation/public-api/
        Selected code was used from the above link to request
        if a hash is malicious or not
    '''
    global count, halt, digests
    while halt: sleep(1)
    count += 1
    if count >= 4: delay()
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    parameters = {'resource': digest, 'apikey': API_KEY}
    status = {}
    try:
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        status = json.loads(response.read())
    except Exception as e: print '\t', e

    try:
        if status['positives'] == 0:
            art = digests[digest].newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), "Message Digest Detective", "MDD: Benign by VirusTotal")
            art.addAttribute(att)
        else:
            art = digests[digest].newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), "Message Digest Detective", "MDD: Malicious by VirusTotal")
            art.addAttribute(att)
    except Exception as e: print '\t', e

###################################################################################
# Below is the Ingest Module code that is referenced in the header of this script #
###################################################################################
        
class MDDFactory(IngestModuleFactoryAdapter):
    def getModuleDisplayName(self):
        return "Message Digest Detective"
    def getModuleDescription(self):
        return "Looks for System32 directory in image and scans for malicious files"
    def getModuleVersionNumber(self):
        return "1.0"
    def isFileIngestModuleFactory(self):
        return True
    def createFileIngestModule(self, ingestOptions):
        return MDDModule()

class MDDModule(FileIngestModule):
    def startUp(self, context):
        global hashes
        configure()
        with open(autopsy + 'md5_5.txt') as h:
            for md5 in h:
                hashes[md5] = True
        
    def process(self, file):
        global digests, hashes
        if file.isFile() and file.getName().lower().endswith(extensions):
            if file.md5Hash in hashes:
                art = digests[digest].newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), "Message Digest Detective", "MDD: Benign by NSRL RDS")
                art.addAttribute(att)
            else:
                digests[file.md5Hash] = file
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), "Message Digest Detective", "MDD: Being Processed")
                art.addAttribute(att)
            #IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent("Message Digest Detective", BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));
            return IngestModule.ProcessResult.OK
        return IngestModule.ProcessResult.OK
    
    def shutDown(self):
        global digests, hashes
        for n in (1, 2, 3, 4):
            with open(autopsy + 'md5_' + str(n) + '.txt') as hash_list:
                hashes = {}
                for md5 in hash_list:
                    hashes[md5] = True
                for digest in digests:
                    if digest in hashes:
                        art = digests[digest].newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                        att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), "Message Digest Detective", "MDD: Benign by NSRL RDS")
                        art.addAttribute(att)
                        digests.pop(digest, None)
        for digest in digests:
            virustotal_thread = Thread(target = request_virustotal, args = [digest])
            virustotal_thread.start()
                    
    def createFileIngestModule(self):
        return MDD(self, ingestOptions)
