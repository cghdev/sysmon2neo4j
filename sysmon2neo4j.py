from neo4j.v1 import GraphDatabase, basic_auth
import json
import sys
from time import gmtime, strftime
import logging
import ntpath

# Establish database session
driver = GraphDatabase.driver("bolt://localhost:7687", auth=basic_auth("neo4j", "password"))
session = driver.session()

logger = logging.getLogger("sysmon2neo4j")
logger.setLevel(logging.INFO)
handler = logging.FileHandler('/var/log/logstash/sysmon2neo4j.log')
formatter = logging.Formatter('[%(levelname)s] - %(name)s - %(asctime)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def handle_event(data):
    event_data = data['event_data']
    if(data['event_id'] == 1):
        # Event ID 1 - Process created
        logger.debug("Processing event_id = 1")
        # Merge process details
        query = "MERGE (p:Process {{ProcessGuid: \"{}\"}})\n".format(event_data['ProcessGuid'])
        query += "ON CREATE SET "
        query += "p.UtcTime = \"{}\"".format(event_data['UtcTime'])
        query += ", p.ProcessId = \"{}\"".format(event_data['ProcessId'])
        event_data['CommandLine'] = event_data['CommandLine'].replace('"','')
        query += ", p.CommandLine = \"{}\"".format(event_data['CommandLine'].replace("\\","\\\\"))
        query += ", p.Name = \"{}\"".format(ntpath.basename(event_data['Image']))
        #query += ", p.CurrentDirectory = \"{}\"".format(event_data['CurrentDirectory'].replace("\\","\\\\"))
        #query += ", p.IntegrityLevel = \"{}\"".format(event_data['IntegrityLevel'])

        # Merge parent details
        query += "\nMERGE (pp:Process {{ProcessGuid: \"{}\"}})\n".format(event_data['ParentProcessGuid'])
        query += "ON CREATE SET "
        query += "pp.ProcessId = \"{}\"".format(event_data['ParentProcessId'])
        query += ", p.Name = \"{}\"".format(ntpath.basename(event_data['ParentImage']))
        event_data['ParentCommandLine'] = event_data['ParentCommandLine'].replace('"','')
        query += ", pp.CommandLine = \"{}\"".format(event_data['ParentCommandLine'].replace("\\","\\\\"))

        # Merge image details
        query += "\nMERGE (i:Image {{Image: \"{}\"}})\n".format(event_data['Image'].replace("\\","\\\\"))
        query += "ON CREATE SET "
        
        # Separate hashes into individual fields
        if 'Hashes' in event_data.keys():
            hashes = event_data['Hashes'].split(',')
            c = 0
            for hash in hashes:
                c += 1
                key, val = hash.split('=')
                query += "i.{} = \"{}\"".format(key, val)
                query += "" if c == len(hashes) else ", "

        # Merge host details
        query += "\nMERGE (h:Host {{Host: \"{}\", Domain: \"{}\"}})\n".format(data['host'], data['user']['domain'])

        # Merge user details
        #query += "\nMERGE (u:User {{User: \"{}\"}})".format(event_data['User'].split('\\')[1])

        # Merge relationships
        query += "\nMERGE (p)-[r1:Used]->(i)"
        query += "\nMERGE (p)<-[r2:Ran]-(h)"
        #query += "\nMERGE (p)<-[r3:Launched]-(u)"
        query += "\nMERGE (p)<-[r4:Spawned]-(pp)"

    if(data['event_id'] == 2):
        # Event ID 2 - Process changed file creation time
        logger.debug("Processing event_id = 2")
        # Merge process details
        query = "MERGE (p:Process {{ProcessGuid: \"{}\"}})".format(event_data['ProcessGuid'])
        query += "\nON CREATE SET p.ProcessId = \"{}\"".format(event_data['ProcessId'])

        # Merge image details
        query += "\nMERGE (i:Image {{\"{}\"}})".format(event_data['Image'].replace("\\","\\\\"))

        # Merge file details
        query += "\nMERGE (f:File {{\"{}\"}})".format(event_data['TargetFilename'].replace("\\","\\\\"))
        query += "\nON CREATE SET "
        query += "f.CreationUtcTime = \"{}\"".format(event_data['CreationUtcTime'])
        query += ", f.PreviousCreationUtcTime = \"{}\"".format(event_data['PreviousCreationUtcTime'])

        # Merge relationships
        query += "\nMERGE (p)-[r1:ModifiedTime]->(f)"
        query += "\nMERGE (p)-[r2:Used]->(i)"

    if(data['event_id'] == 3):
        # Event ID 3 - Network Connection
        logger.debug("Processing event_id = 3")
        # Merge process details
        query = "MERGE (p:Process {{ProcessGuid: \"{}\"}})".format(event_data['ProcessGuid'])
        query += "\nON CREATE SET p.ProcessId = \"{}\"".format(event_data['ProcessId'])

        # Merge image details
        query += "\nMERGE (i:Image {{Image: \"{}\"}})".format(event_data['Image'].replace("\\","\\\\"))

        # Merge source details
        query += "\nMERGE (s:Source {{SourceIp: \"{}\"}})".format(event_data['SourceIp'])
        query += "\nON CREATE SET "
        query += "s.SourceIsIpv6 = \"{}\"".format(event_data['SourceIsIpv6'])
        if 'SourceHostname' in event_data.keys():
            query += ", s.SourceHostname = \"{}\"".format(event_data['SourceHostname'])
        query += ", s.SourcePort = \"{}\"".format(event_data['SourcePort'])
        if 'SourcePortName' in event_data.keys():
            query += ", s.SourcePortName = \"{}\"".format(event_data['SourcePortName'])
        query += ", s.Initiated = \"{}\"".format(event_data['Initiated'])
        query += ", s.Protocol = \"{}\"".format(event_data['Protocol'])

        # Merge destination details
        query += "\nMERGE (d:Destination {{DestinationIp: \"{}\"}})".format(event_data['DestinationIp'])
        query += "\nON CREATE SET "
        query += "d.DestinationIsIpv6 = \"{}\"".format(event_data['DestinationIsIpv6'])
        if 'DestinationHostname' in event_data.keys():
            query += ", d.DestinationHostname = \"{}\"".format(event_data['DestinationHostname'])
        query += ", d.DestinationPort = \"{}\"".format(event_data['DestinationPort'])
        if 'DestinationPortName' in event_data.keys():
            query += ", d.DestinationPortName = \"{}\"".format(event_data['DestinationPortName'])
        query += ", d.Initiated = \"{}\"".format(event_data['Initiated'])
        query += ", d.Protocol = \"{}\"".format(event_data['Protocol'])

        # Merge relationships
        query += "\nMERGE (p)-[r1:From]->(s)"
        query += "\nMERGE (p)-[r2:ConnectedTo]->(d)"
        query += "\nMERGE (p)-[r3:Used]->(i)"

    if(data['event_id'] == 4):
        # Event ID 4 - Sysmon service state changed
        # Currently Unimplimented
        return
    if(data['event_id'] == 5):
        # Event ID 5 - Process Terminated
        # Currently Unimplimented
        return
    if(data['event_id'] == 6):
        # Event ID 6 - Driver Loaded
        # Currently Unimplimented
        return
    if(data['event_id'] == 7):
        # Event ID 7 - Image Loaded
        logger.debug("Processing event_id = 7")
        # Merge process details
        query = "MERGE (p:Process {{ProcessGuid: \"{}\"}})\n".format(event_data['ProcessGuid'])
        query += "\nON CREATE SET p.ProcessId = \"{}\"".format(event_data['ProcessId'])

        # Merge image details
        query += "\nMERGE (i:Image {{Image: \"{}\"}})\n".format(event_data['Image'].replace("\\","\\\\"))
        query += "\nON CREATE SET "
        
        # Separate hashes into individual fields
        if 'Hashes' in event_data.keys():
            hashes = event_data['Hashes'].split(',')
            c = 0
            for hash in hashes:
                c += 1
                key, val = hash.split('=')
                query += "i.{} = \"{}\"".format(key, val)
                query += "" if c == len(hashes) else ", "

        query += ", i.Signed = \"{}\"".format(event_data['Signed']) if 'Signed' in event_data.keys() else ""
        query += ", i.Signature = \"{}\"".format(event_data['Signature']) if 'Signature' in event_data.keys() else ""
        query += ", i.SignatureStatus = \"{}\"".format(event_data['SignatureStatus']) if 'SignatureStatus' in event_data.keys() else ""

        # Merge relationships
        query += "\nMERGE (p)-[r1:Loaded]->(i)"

    if(data['event_id'] == 8):
        # Event ID 8 - CreateRemoteThread
        logger.debug("Processing event_id = 8")
        # Merge thread details
        query = "MERGE (t:Thread {{ThreadId: \"{}\", StartAddress: \"{}\", StartModule: \"{}\", StartFunction: \"{}\"}})".format(
            event_data['NewThreadId'],
            event_data['StartAddress'],
            event_data['StartModule'],
            event_data['StartFunction']
        )

        # Merge source process details
        query += "\nMERGE (p1:Process {{ProcessGuid: \"{}\"}})".format(event_data['SourceProcessGuid'])

        # Merge target process details
        query += "\nMERGE (p2:Process {{ProcessGuid: \"{}\"}})".format(event_data['TargetProcessGuid'])

        # Merge relationships
        query += "\nMERGE (t)<-[:CreatedIn]-(p2)"
        query += "\nMERGE (t)<-[:CreatedBy]-(p1)"
        query += "\nMERGE (p1)->[:CreatedThreadIn]-(p2)"

    if(data['event_id'] == 9):
        # Event ID 9 - Raw access read
        logger.debug("Processing event_id = 9")
        # Merge device details
        query = "MERGE (d:Device {{Device: \"{}\"}})".format(event_data['Device'].replace("\\","\\\\"))

        # Merge process details
        query += "\nMERGE (p:Process {{ProcessGuid: \"{}\"}})".format(event_data['ProcessGuid'])
        query += "\nON CREATE SET p.ProcessId = \"{}\"".format(event_data['ProcessId'])

        # Merge image details
        query += "\nMERGE (i:Image {{Image: \"{}\"}})\n".format(event_data['Image'].replace("\\","\\\\"))

        # Merge relationships
        query += "\nMERGE (d)<-[:Read]-(p)"
        query += "\nMERGE (p)-[:Used]-(i)"

    if(data['event_id'] == 10):
        # Event ID 10 - Process access
        logger.debug("Processing event_id = 10")
        # Merge source process details
        query = "MERGE (sp:Process {{ProcessGuid: \"{}\"}})".format(event_data['SourceProcessGUID'])
        query += "\nON CREATE SET sp.ProcessId = \"{}\"".format(event_data['SourceProcessId'])

        # Merge thread details
        query += "\nMERGE (t:Thread {{ThreadId: \"{}\"}})".format(event_data['SourceThreadId'])

        # Merge target process details
        query += "\nMERGE (tp:Process {{ProcessGuid: \"{}\"}})".format(event_data['TargetProcessGUID'])
        query += "\nON CREATE SET tp.ProcessId = \"{}\"".format(event_data['TargetProcessId'])

        # Merge source image details
        query += "\nMERGE (si:Image {{Image: \"{}\"}})\n".format(event_data['SourceImage'].replace("\\","\\\\"))

        # Merge target image details
        query += "\nMERGE (ti:Image {{Image: \"{}\"}})\n".format(event_data['TargetImage'].replace("\\","\\\\"))

        # Merge relationships
        query += "\nMERGE (sp)-[:Used]->(si)"
        query += "\nMERGE (sp)-[:Used]->(t)"
        query += "\nMERGE (sp)-[:Accessed {{GrantedAccess: \"{}\"}}]->(tp)".format(event_data['GrantedAccess'])
        query += "\nMERGE (tp)-[:Used]->(ti)"

    if(data['event_id'] == 11):
        # Event ID 11 - FileCreate
        logger.debug("Processing event_id = 11")
        # Merge process details
        query = "MERGE (p:Process {{ProcessGuid: \"{}\"}})".format(event_data['ProcessGuid'])
        query += "\nON CREATE SET p.ProcessId = \"{}\"".format(event_data['ProcessId'])

        # Merge image details
        query += "\nMERGE (i:Image {{Image: \"{}\"}})\n".format(event_data['Image'].replace("\\","\\\\"))

        # Merge file details
        query += "\nMERGE (f:File {{Filename: \"{}\"}})".format(event_data['TargetFilename'].replace("\\","\\\\"))
        query += "\nON CREATE SET "
        query += "f.CreationUtcTime = \"{}\"".format(event_data['CreationUtcTime'])

        # Merge relationships
        query += "\nMERGE (p)-[:Used]->(i)"
        query += "\nMERGE (p)-[:Created]->(f)"

    if(data['event_id'] in range(12,15)):
        # Event ID 12, 13, 14 - RegistryEvent

        # Just return, because this is too noisy and makes for a very messy graph
        return

        # Merge process details
        query = "MERGE (p:Process {{ProcessGuid: \"{}\"}})".format(event_data['ProcessGuid'])
        query += "\nON CREATE SET p.ProcessId = \"{}\"".format(event_data['ProcessId'])

        # Merge registry details
        query += "\nMERGE (r:RegistryObj {{TargetObject: \"{}\"}})".format(
            event_data['TargetObject'].replace("\\","\\\\")
        )
        if 'Details' in event_data.keys():
            query += "\nON CREATE SET r.Details = \"{}\"".format(event_data['Details'].replace("\\","\\\\"))
            query += "\nON MATCH SET r.Details = \"{}\"".format(event_data['Details'].replace("\\","\\\\"))
        if 'NewName' in event_data.keys():
            query += "\nON CREATE SET r.NewName = \"{}\"".format(event_data['NewName'].replace("\\","\\\\"))
            query += "\nON MATCH SET r.NewName = \"{}\"".format(event_data['NewName'].replace("\\","\\\\"))

        # Merge image details
        query += "\nMERGE (i:Image {{Image: \"{}\"}})".format(
            event_data['Image'].replace("\\","\\\\")
        )

        # Merge relationships
        query += "\nMERGE (p)-[:Used]->(i)"
        query += "\nMERGE (p)-[:Manipulated]->(r)"

    if(data['event_id'] == 15):
        # Event ID 15 - Filestream created
        return

    if(data['event_id'] == 16):
        # Event ID - Sysmon config change
        return

    if(data['event_id'] == 17 or data['event_id'] == 18):
        # Event ID 17 - Pipe created
        # Event ID 18 - Pipe connected
        logger.debug("Processing event_id = 17/18")
        # Merge process details
        query = "MERGE (p:Process {{ProcessGuid: \"{}\"}})".format(event_data['ProcessGuid'])
        query += "\nON CREATE SET p.ProcessId = \"{}\"".format(event_data['ProcessId'])

        # Merge image details
        query += "\nMERGE (i:Image {{Image: \"{}\"}})\n".format(event_data['Image'].replace("\\","\\\\"))

        # Merge pipe details
        query += "\nMERGE (pi:Pipe {{PipeName: \"{}\"}})".format(event_data['PipeName'].replace("\\","\\\\"))

        # Merge relationships
        query += "\nMERGE (p)-[:Used]->(i)"
        if data['event_id'] == 17:
            query += "\nMERGE (p)-[:Created]->(pi)"
        else:
            query += "\nMERGE (p)-[:Connected]->(pi)"
    logger.debug(query)
    session.run(query)

# Continue reading stdin until no more data
# Necessary because logstash does not close the pipe after sending data
while True:
    try:
        line = sys.stdin.readline()
        if not line:
            break
        #logger.debug(line)
        event = json.loads(line)
        handle_event(event)
    except Exception as err:
        logger.error("There was an error", exc_info=True)
