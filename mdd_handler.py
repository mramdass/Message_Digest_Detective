#
#   Munieshwar (Kevin) Ramdass
#   Professor Marc Budofsky
#   Message Digest Detective
#   3 December 2016
#
#   All code in this module is modeled after the
#   in the following link:
#   https://www.osdfcon.org/presentations/2014/Python-Autopsy-OSDFCon2014.pdf
#

import jarray, inspect
#from mdd import handler
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase, AbstractFile, ReadContentInputStream, BlackboardArtifact, BlackboardAttribute, TskData
from org.sleuthkit.autopsy.ingest import IngestModule, DataSourceIngestModule, FileIngestModule, IngestModuleFactoryAdapter, IngestServices
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services, FileManager

extensions = ('.dll', '.exe', '.pif', '.application', '.gadget', '.msi', '.com', '.scr', '.hta', '.cpl', '.msc', '.jar')
digests = {}
    

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
        pass
    def process(self, file):
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or (file.isFile() == False)):
            return IngestModule.ProcessResult.OK
        if file.getName().lower().endswith(extensions):
            digests[1] = file.getName()
            #handler(digests)
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
	    att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), "Message Digest Detective", "Analyzed in MDD")
	    art.addAttribute(att)
	    IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent("Message Digest Detective", BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));
            #return IngestModule.ProcessResult.OK
        return IngestModule.ProcessResult.OK
    def shutDown(self):
        pass
    def createFileIngestModule(self):
        return MDD(self, ingestOptions)
