'''
    Munieshwar (Kevin) Ramdass
    Professor
    CS-GY 6963
    26 October 2016

    Final Project - Message Digest Detective
'''

try:
    import os, sys, json, argparse, urllib, urllib2
    from math import ceil
    from threading import Thread
    from time import time
    from datetime import datetime
    from time import sleep
    from zipfile import ZipFile
    from hashlib import sha1
    from subprocess import check_output
except Exception as e:
    print '\t', e
    exit()

# File paths
A_path = 'RDS_Split/A/'
B_path = 'RDS_Split/B/'
C_path = 'RDS_Split/C/'
D_path = 'RDS_Split/D/'
U_path = 'RDS_Unified/'

# File paths to zipped files
A = 'RDS_Split/A/RDS_253_A.zip' # NOT USED
B = 'RDS_Split/B/RDS_253_B.zip' # NOT USED
C = 'RDS_Split/C/RDS_253_C.zip' # NOT USED
D = 'RDS_Split/D/RDS_253_D.zip' # NOT USED
U = 'RDS_Unified/NSRLFile.txt.zip'

# File/record names in zipped files
File    = 'NSRLFile.txt'
Mfg     = 'NSRLMfg.txt'
OS      = 'NSRLOS.txt'
Prod    = 'NSRLProd.txt'

# Message digest bounds per disk sections or zipped files
A_min = 0
A_max = int('3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16)
B_min = int('4000000000000000000000000000000000000000', 16)
B_max = int('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16)
C_min = int('8000000000000000000000000000000000000000', 16)
C_max = int('BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16)
D_min = int('C000000000000000000000000000000000000000', 16)
D_max = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 16)

# File line constraints - NOT USED
A_lines = 42828193
B_lines = 43010229
C_lines = 42763547
D_lines = 43506769

# Map of SHA-1 hashes to file name from desired directory
digests = {}

# Map of data provided by NSLR; uses 'NSRLMfg.txt', 'NSRLOS.txt', and 'NSRLProd.txt'
rds_metadata = {}

# Result of analysis goes here for all message digests
status = {}

# Malicious message digests
malicious = {}

# Metadata to search the correct NSLR text files in constant time; uses 'metadata.json'
split_metadata = {}

# List to join VirusTotal threads
virustotal_threads = []

# Activate thread wait time in seconds
count = 0
halt = False

# VirusTotal API key which allows for 4 requests per minute
API_KEY = ''
try:
    with open('key.txt', 'r') as k: API_KEY = k.read().rstrip()
except Exception as e:
    print '\tCannot obtain VirusTotal API key'
    print '\t', e
    exit()

def load_map(name):
    with open(name) as d: return json.load(d)

def print_map(name): return json.dumps(name, sort_keys = True, indent = 4, separators = (',', ': '))

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
        Selected code was used from the above link to request if a hash is malicious or not
    '''
    global status, count, halt
    while halt: sleep(1)
    count += 1
    if count >= 4: delay()
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    parameters = {'resource': digest, 'apikey': API_KEY}
    try:
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        status[digest] = json.loads(response.read())
    except Exception as e:
        print '\t', e

def unzip_split(path, keys, read = False):
    '''
        Linear search for key/digest in a desired zipped repord
        If read is true, this function returns the entire record
            'keys' becomes filename
        Uses the split RDS
    '''
    if read:
        with ZipFile(path) as zf:
            with zf.open(keys) as f: return map(str.rstrip, f.readlines())
    letter = path.split('/')[1]
    full_path = path + letter + '.zip'
    with ZipFile(full_path) as zf:
        record = ''
        for digest in keys:
            for name in split_metadata[letter]:
                if int(split_metadata[letter][name]['min'], 16) <= int(digest, 16) and int(digest, 16) <= int(split_metadata[letter][name]['max'], 16): record = 'RDS_' + str(name) + '.txt'
                else: continue
                with zf.open(record, mode = 'r') as f:
                    for line in f:
                        if digest == line[1:41]:
                            if digest not in status:
                                status[digest] = []
                                status[digest].append(line.rstrip())
                            else: status[digest].append(line.rstrip())
            if digest not in status:
                status[digest] = 'Unknown' # Temporarily mark 'Unknown'
                virustotal_thread = Thread(target = request_virustotal, args = [digest])
                virustotal_threads.append(virustotal_thread)
                virustotal_thread.start()

def unzip_unified(path, keys = None, read = False):
    '''
        Linear search for key/digest in a desired zipped repord
        If read is true, this function returns the entire record
        Uses the unified RDS
    '''
    if read and keys == None:
        with open(path, 'r') as f: return map(str.rstrip, f.readlines())
    if len(keys) == 0: return
    with ZipFile(path) as zf:
        with zf.open(File, mode = 'r') as f:
            next(f)
            for line in f:
                if keys[0] == line[1:41]:
                    if keys[0] not in status:
                        status[keys[0]] = []
                        status[keys[0]].append(line.rstrip())
                        keys.pop(0)
                    else:
                        status[digest].append(line.rstrip())
                        keys.pop(0)
                if len(keys) == 0: break
                while int(keys[0], 16) < int(line[1:41], 16):
                    status[keys[0]] = 'Unknown' # Temporarily mark 'Unknown'
                    virustotal_thread = Thread(target = request_virustotal, args = [keys[0]])
                    virustotal_threads.append(virustotal_thread)
                    virustotal_thread.start()
                    keys.pop(0)
                    if len(keys) == 0: break
            
    
def get_mfg(unified = False):
    metadata = {}
    if unified:
        for line in unzip_unified(U_path + Mfg, read = True): metadata[line.split(',')[0].strip('"')] = line.split(',')[1].strip('"')
    else:
        for zipped in [A, B, C, D]:
            for line in unzip_split(zipped, Mfg, read = True): metadata[line.split(',')[0].strip('"')] = line.split(',')[1].strip('"')
    return metadata

def get_os(unified = False):
    metadata = {}
    if unified:
        for line in unzip_unified(U_path + OS, read = True):
            metadata[line.split(',')[0].strip('"')] = { 'sysname': '', 'sysversion': '', 'mfg': '' }
            metadata[line.split(',')[0].strip('"')]['sysname'] = line.split(',')[1].strip('"')
            metadata[line.split(',')[0].strip('"')]['sysversion'] = line.split(',')[2].strip('"')
            metadata[line.split(',')[0].strip('"')]['mfg'] = line.split(',')[3].strip('"')
    else:
        for zipped in [A, B, C, D]:
            for line in unzip_split(zipped, OS, read = True):
                metadata[line.split(',')[0].strip('"')] = { 'sysname': '', 'sysversion': '', 'mfg': '' }
                metadata[line.split(',')[0].strip('"')]['sysname'] = line.split(',')[1].strip('"')
                metadata[line.split(',')[0].strip('"')]['sysversion'] = line.split(',')[2].strip('"')
                metadata[line.split(',')[0].strip('"')]['mfg'] = line.split(',')[3].strip('"')
    return metadata

def get_prod(unified = False):
    metadata = {}
    if unified:
        for line in unzip_unified(U_path + Prod, read = True):
            if line.split(',')[0].strip('"') not in metadata:
                metadata[line.split(',')[0].strip('"')] = []
            metadata[line.split(',')[0].strip('"')].append((line.split(',')[1].strip('"'), line.split(',')[2].strip('"'), line.split(',')[3].strip('"'), line.split(',')[4].strip('"'), line.split(',')[5].strip('"'), line.split(',')[6].strip('"')))
    else:
        for zipped in [A, B, C, D]:
            for line in unzip_split(zipped, Prod, read = True):
                if line.split(',')[0].strip('"') not in metadata:
                    metadata[line.split(',')[0].strip('"')] = []
                metadata[line.split(',')[0].strip('"')].append((line.split(',')[1].strip('"'), line.split(',')[2].strip('"'), line.split(',')[3].strip('"'), line.split(',')[4].strip('"'), line.split(',')[5].strip('"'), line.split(',')[6].strip('"')))
    return metadata

def get_rds_metadata(unified = False):
    global rds_metadata
    if unified:
        rds_metadata['mfg'] = get_mfg(True)
        rds_metadata['os'] = get_os(True)
        rds_metadata['prod'] = get_prod(True)
    else:
        rds_metadata['mfg'] = get_mfg()
        rds_metadata['os'] = get_os()
        rds_metadata['prod'] = get_prod()

def get_digest(path):
    '''
        Computes the sha1 message digest of a file 32KB at a time
    '''
    digest = sha1()
    with open(path, 'rb') as f:
        while True:
            data_32 = f.read(32768) # 32KB segment reads (for large files)
            if not data_32: break
            digest.update(data_32)
    return digest.hexdigest().upper()

def split_search(message_digests):
    '''
        Compares SHA1 hashes to determine which split directory to look in
    '''
    a, b, c, d = ([], [], [], [])
    for digest in message_digests:
        int_digest = int(digest, 16)
        if A_min <= int_digest and int_digest <= A_max: a.append(digest)
        elif B_min <= int_digest and int_digest <= B_max: b.append(digest)
        elif C_min <= int_digest and int_digest <= C_max: c.append(digest)
        elif D_min <= int_digest and int_digest <= D_max: d.append(digest)

    ta = Thread(target = unzip_split, args = (A_path, a))
    tb = Thread(target = unzip_split, args = (B_path, b))
    tc = Thread(target = unzip_split, args = (C_path, c))
    td = Thread(target = unzip_split, args = (D_path, d))
    for thread in [ta, tb, tc, td]: thread.start()
    for thread in [ta, tb, tc, td]: thread.join()

def unified_search(message_digests): unzip_unified(U, message_digests)

def segment_read(file_handle, segment_size = 4096 * 2): # NOT USED
    while True:
        data = file_handle.read(segment_size)
        if not data: break
        yield data

def segment_search(segment, key): # NOT USED
    for line in segment.splitlines():
        if key == line[1:41]: return line

def get_digests(path):
    '''
        For all files in the specified directory path, find all sha1 hashes
    '''
    global digests
    for root, dirs, files in os.walk(path):
        for f in files:
            if f.endswith('.exe') or f.endswith('.dll'):
                digest = get_digest(os.path.join(root, f))
                if digest not in digests:
                    digests[digest] = []
                    digests[digest].append(os.path.join(root, f))
                else: digests[get_digest(os.path.join(root, f))].append(os.path.join(root, f))

def gather_metadata():
    global status, rds_metadata
    for digest in status:
        if 'response_code' not in status[digest] and status[digest] != 'Unknown':
            temp = {'os': {}, 'prod': {}, 'mfg': {}}
            # The RDS has multiple lines with digest information for the same sha1 hash; look at all of them
            entry = 1
            for line in status[digest]:
                entry += 1
                temp['os'][entry] = rds_metadata['os'][line.split(',')[6].strip('"')]
                temp['prod'][entry] = rds_metadata['prod'][line.split(',')[5]]
                temp['mfg'][entry] = []
                for product in rds_metadata['prod'][line.split(',')[5]]:
                    temp['mfg'][entry].append(rds_metadata['mfg'][product[3]])
                temp['mfg'][entry] = list(set(temp['mfg'][entry]))
                temp['prod'][entry] = list(set(temp['prod'][entry]))
            status[digest] = temp

def main():
    global split_metadata, digests, rds_metadata, status, malicious
    start = time()
    start_time = datetime.now()
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", help = "Desired directory to analyze", required = True)
    args = parser.parse_args()
    print 'START:', start_time

    directory = args.directory
    
    get_digests(directory)
    print 'Length of digests: ', len(digests)

    if len(digests) <= 50:
        split_metadata = load_map('metadata.json')
        get_rds_metadata()
        split_search(digests)
    else:
        get_rds_metadata(True)
        unified_search(sorted(digests.keys()))

    output_file = 'output/status_' + str(start_time).replace(' ', '-').replace(':', '-').replace('.', '-') + '.json'
    gather_metadata()
    write_map(output_file, status)
    print 'END:', datetime.now(), '\tTIME ELAPSED:', str((time() - start)/60), 'minutes'
    print '\tLocal scan completed\n\tNow waiting on VirusTotal response\n\t' + output_file + ' will be rewritten shortly'
    print 'Max waiting time:', str(ceil(len(virustotal_threads) / float(4))), 'minutes'
    for thread in virustotal_threads: thread.join()
    write_map(output_file, status)

    # Copying malicious message digests
    for digest in status:
        if 'positives' in status[digest]:
            if status[digest]['positives'] != 0:
                malicious[digest] = status[digest]
    write_map(output_file[:-5] + '_malicious.json', malicious)
    print '\t' + str(len(malicious)) + ' message digest(s) detected'
    print 'END:', datetime.now(), '\tTIME ELAPSED:', str((time() - start)/60), 'minutes'

main()
