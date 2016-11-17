'''
    Munieshwar (Kevin) Ramdass
    Professor
    CS-GY 6963
    26 October 2016

    Final Project - Message Digest Detective

    Functions presented here are all threaded and works
    best if hash lists are on separate drives. This scipt
    is meant to be run only once during the set up phase.
'''

try:
    import os, sys, threading, tempfile, json
    from itertools import chain, islice, izip_longest
    from threading import Thread
    from zipfile import ZipFile, ZIP_DEFLATED
except Exception as e:
    print '\t', e

A = 'RDS_Split/A/RDS_253_A.zip'
B = 'RDS_Split/B/RDS_253_B.zip'
C = 'RDS_Split/C/RDS_253_C.zip'
D = 'RDS_Split/D/RDS_253_D.zip'

# File/record names in zipped files
File = 'NSRLFile.txt'
Mfg = 'NSRLMfg.txt'
OS = 'NSRLOS.txt'
Prod = 'NSRLProd.txt'

metadata = {'A': {}, 'B': {}, 'C': {}, 'D': {}}

def unzip_metadata(zipped, out):
    c = 1
    current = 100000
    with ZipFile(zipped) as zf:
        with zf.open(File) as f:
            #next(f)
            #with open(out, 'w') as w:
            for line in f:
                if current not in metadata[out]: metadata[out][current] = {'max': '', 'min': ''}
                metadata[out][current]['max'] = line[1:41]
                if c % 100000 == 0: current += 100000
                elif c % 100000 == 1 and c != 1: metadata[out][current]['min'] = line[1:41]
                elif c == 2: metadata[out][current]['min'] = line[1:41]
                c += 1
            metadata[out][c - 1] = metadata[out][current]
            del metadata[out][current]
# _______________________________________________________________________________
# The following two functions are referenced and altered from the following link:
# http://stackoverflow.com/questions/16289859/splitting-large-text-file-into-smaller-text-files-by-line-numbers-using-python

def grouper(n, iterable, fillvalue=None):
    args = [iter(iterable)] * n
    return izip_longest(fillvalue=fillvalue, *args)

n = 100000
def split_files(zipped, out_dir):
    with ZipFile(zipped) as zf:
        with zf.open(File) as f:
            for i, g in enumerate(grouper(n, f, fillvalue=None)):
                with tempfile.NamedTemporaryFile('w', delete=False) as fout:
                    for j, line in enumerate(g, 1): # count number of lines in group
                        if line is None:
                            j -= 1 # don't count this line
                            break
                        fout.write(line.rstrip() + '\n')
                os.rename(fout.name, out_dir + 'RDS_{0}.txt'.format(i * n + j))
# _______________________________________________________________________________

def zip_files(path, handle):
    for root, dirs, files in os.walk(path):
        for f in files:
            if f.startswith('RDS_') and f.endswith('.txt'): handle.write(os.path.join(path, f), os.path.relpath(os.path.join(root, f), os.path.join(path, '.')))

def zip_files_handler():
    zip_files('RDS_Split/A/', ZipFile('RDS_Split/A/A.zip', 'w', ZIP_DEFLATED))
    zip_files('RDS_Split/B/', ZipFile('RDS_Split/B/B.zip', 'w', ZIP_DEFLATED))
    zip_files('RDS_Split/C/', ZipFile('RDS_Split/C/C.zip', 'w', ZIP_DEFLATED))
    zip_files('RDS_Split/D/', ZipFile('RDS_Split/D/D.zip', 'w', ZIP_DEFLATED))
    
def split_threaded():
    t1 = Thread(target=split_files, args=('RDS_Split/A/RDS_253_A.zip', 'RDS_Split/A/'))
    t2 = Thread(target=split_files, args=('RDS_Split/B/RDS_253_B.zip', 'RDS_Split/B/'))
    t3 = Thread(target=split_files, args=('RDS_Split/C/RDS_253_C.zip', 'RDS_Split/C/'))
    t4 = Thread(target=split_files, args=('RDS_Split/D/RDS_253_D.zip', 'RDS_Split/D/'))
    for thread in [t1, t2, t3, t4]: thread.start()
    for thread in [t1, t2, t3, t4]: thread.join()
    print 'Finished'

def unzip_threaded():
    u1 = Thread(target=unzip_metadata, args=(A, 'A'))
    u2 = Thread(target=unzip_metadata, args=(B, 'B'))
    u3 = Thread(target=unzip_metadata, args=(C, 'C'))
    u4 = Thread(target=unzip_metadata, args=(D, 'D'))
    for thread in [u1, u2, u3, u4]: thread.start()
    for thread in [u1, u2, u3, u4]: thread.join()
    with open('metadata.json', 'w') as j: j.write(json.dumps(metadata, indent=4, sort_keys=True))
    print 'Finished'

split_threaded() # Split the given zipped hash file into several files
unzip_threaded() # Creates the metadata mapping for file names to hash numbers
zip_files_handler() # Zips all split hash files together
