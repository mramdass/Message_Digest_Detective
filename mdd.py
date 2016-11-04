'''
    Munieshwar (Kevin) Ramdass
    Professor
    CS-GY 6963
    26 October 2016

    Final Project - Message Digest Detective
'''

try:
    import os, sys, json, argparse
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

# All the SHA-1 hashes that were found in the desired directory
status = {}

# Metadata to search the correct NSLR text files in constant time; uses 'metadata.json'
split_metadata = {}

# List to join VirusTotal threads
virustotal_threads = []

def load_map(name):
    with open(name) as d:
        return json.load(d)

def print_map(name): return json.dumps(name, sort_keys = True, indent = 4, separators=(',', ': '))

def write_map(name, hashmap):
    with open(name, 'w') as w: w.write(print_map(hashmap))

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
                    #CALL VIRUSTOTAL
                    print 'virustotal'
                    status[keys[0]] = 'UNKNOWN'
                    keys.pop(0)
                    if len(keys) == 0: break
            
    
def get_mfg(unified = False):
    metadata = {}
    if unified:
        for line in unzip_unified(U_path + Mfg, read = True): metadata[line.split(',')[0].strip('"')] = line.split(',')[1].strip('"')
    else:
        for zipped in [A, B, C, D]:
            for line in unzip(zipped, Mfg, read = True): metadata[line.split(',')[0].strip('"')] = line.split(',')[1].strip('"')
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
            for line in unzip(zipped, OS, read = True):
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
            for line in unzip(zipped, Prod, read = True):
                if line.split(',')[0].strip('"') not in metadata:
                    metadata[line.split(',')[0].strip('"')] = []
                metadata[line.split(',')[0].strip('"')].append((line.split(',')[1].strip('"'), line.split(',')[2].strip('"'), line.split(',')[3].strip('"'), line.split(',')[4].strip('"'), line.split(',')[5].strip('"'), line.split(',')[6].strip('"')))
    return metadata

def get_rds_metadata(unified = False):
    global rds_metadata
    if unified:
        rds_metadata['mfg'] = get_mfg(True)
        rds_metadata['os'] = get_mfg(True)
        rds_metadata['prod'] = get_mfg(True)
    else:
        rds_metadata['mfg'] = get_mfg()
        rds_metadata['os'] = get_mfg()
        rds_metadata['prod'] = get_mfg()

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
    for thread in [ta, tb, tc, td]:
        thread.start()
    for thread in [ta, tb, tc, td]:
        thread.join()

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

def main():
    global split_metadata, digests, rds_metadata, status
    start = time()
    start_time = datetime.now()
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", help = "Desired directory to analyze", required = True)
    args = parser.parse_args()
    print 'START:', start_time

    directory = args.directory
    dir_list = directory.split('/')
    lowest_dir = dir_list[len(dir_list) - 1]
    
    get_digests(directory)
    print 'Length of digests: ', len(digests)

    if len(digests) <= 50:
        split_metadata = load_map('metadata.json')
        get_rds_metadata()
        split_search(digests)
    else:
        get_rds_metadata(True)
        unified_search(sorted(digests.keys()))
    
    write_map('output/found_' + lowest_dir + '.json', status)

    print str(len(digests)) + ' out of ' + str(len(status)) + ' found in RDS'
    print 'END:', datetime.now(), '\tTIME ELAPSED:', time() - start

main()
