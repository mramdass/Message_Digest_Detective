# Message Digest Detective
## Munieshwar (Kevin) Ramdass
## CS-GY 6963
## Fall 2016
##

## Sypnosis/Getting Started

Use the following instructions to get started with Message Digest Detective  
The intuition behind Message Digest Detective is to be able to scan an entire directory of sub-directories and files which may include thousands of files in less than an hour - a Windows 7 System32 scan of 3,357 files returned results in 20.5 minutes. Previous attempts to create an effective tool would check a file of hashes one by one which was very time consuming. Furthermore, Message Digest Detective was initially intended to scan the Windows System32 directory; the intuition here is to discover any malicious executables that are running or have been placed there to run. Windows applications use this folder extensively. Since the hash files are so large, the split hash files can accually be placed in separate disks and run. It will be much faster to do hash look ups this way. Message Digest Detective will get the hashes for all of the executables in the folder you pass in via command line. It will then search the NSRL Hash list. This hash list is a list of all benign programs. If a hash exists in this file, it is safe to assume it is not malicious. The majority (98%+) of the hashes obtain by Message Digest Detective will be found in the hash list. This leaves only about 2% of files to be concerned about. These remaining files will then be processed through the VirusTotal API to determine whether they are malicious or not. It is better to filter out all/most of the benign files before analyzing the questioned/unknown file since the VirusTotal API only takes four requests per minute for a free account. While an unknown file is discovered through Message Digest Detective, it is queued to run as soon as time permits. In general, it is best to filter benign files locally before using an API as it will be faster to reduce the bulk of the processing.  
split.py is a formatter for the RDS files found in the zipped file. split.py will create text files, and will zip into A.zip, B.zip, C.zip, and D.zip from RDS_253_A.zip, RDS_253_B.zip, RDS_253_C.zip, and RDS_253_D.zip. This script is meant to be run once when you first download the Combo DVD.  
To actually search for malicious or unknown files, you will run mdd.py by specifing the directory to analyze. Windows System32, Program Files and Program Files (x86) are the directories this script is meant to run on.

### Methodology
```
Input directory
    |
     --> Discover all files
            |
             --> Compute Hashes
                    |
                     --> if list of hashes exceeds 50 (this number changes to sys.maxint if files on on different drives)
                            |
                             --> Unified Search: open NSRL Unified RDS zip file and search for hashes in order (linearly)
                                    |
                                     --> Spawn a VirusTotal thread for each hash that does not exist where it should be
                         else
                            |
                             --> Split Search: Compute if hash should be in sub directory A, B, C, or D
                                    |
                                     --> Compute which bucket file the hash should be in and search there
                                            |
                                             --> Spawn a VirusTotal hread for each hash that does not exist where it should be

    |
     --> Output Data
```

### Prerequisities

Python 2.7.11

```
https://www.python.org/downloads/
```
NSRL RDS - Combo DVD

```
http://www.nsrl.nist.gov/Downloads.htm
```

### Setting Up

Clone/Download this respository. Note that the '.zip' files in this repository are placeholders as it is very large. From the Combo DVD, place the appropriate named '.zip' file in the appropriate directory. Then run split.py to generate the remaining '.zip' files as mentioned in 'Getting Started'. NOTE: split.py should only be run once.  
There is a configure.json which allows you to specific the zipped file paths if you choose to locate them on separate drives. The split_search algorithm is threaded and so read accesses will be efficiently run if the files are opened from separate disks/devices.  
You must have a VirusTotal API Key. <https://www.virustotal.com/>

### To Run
```
python split.py
python mdd.py -d <path>
```

### Examples
```
python split.py
python mdd.py -d C:/Windows/System32
python mdd.py -d "C:/Program Files (x86)"
```

### Output

#### status_[execution-time].json  
General output format will include both benign and malicious results.
```
{
    "<sha1>": "Unknown",
    "0251964C4A50FE4D4847BD329CB12EA732D53587": {
        "md5": "01c861d4fe98dc201c4799dccf331b58",
        "permalink": "https://www.virustotal.com/file/5ef4af3f7a2d0da7391beaf06029c20fdf48ebcf2c9e9130567576c2d19f30db/analysis/1477679332/",
        "positives": 0,
        "resource": "0251964C4A50FE4D4847BD329CB12EA732D53587",
        "response_code": 1,
        "scan_date": "2016-10-28 18:28:52",
        "scan_id": "5ef4af3f7a2d0da7391beaf06029c20fdf48ebcf2c9e9130567576c2d19f30db-1477679332",
        "scans": {
            "ALYac": {
                "detected": false,
                "result": null,
                "update": "20161028",
                "version": "1.0.1.9"
            },
            "AVG": {
                "detected": false,
                "result": null,
                "update": "20161028",
                "version": "16.0.0.4664"
            },
            ...
            "nProtect": {
                "detected": false,
                "result": null,
                "update": "20161028",
                "version": "2016-10-28.01"
            }
        },
        "sha1": "0251964c4a50fe4d4847bd329cb12ea732d53587",
        "sha256": "5ef4af3f7a2d0da7391beaf06029c20fdf48ebcf2c9e9130567576c2d19f30db",
        "total": 57,
        "verbose_msg": "Scan finished, information embedded"
    },
    "3DE026EAD09443B90E951AFDAF150C6D4A3E288C": {
        "mfg": {
            "2": [
                "Microsoft"
            ],
            ...
            "8": [
                "Dell"
            ],
            ...
            "14": [
                "Microsoft"
            ]
        },
        "os": {
            "2": {
                "mfg": "1006",
                "sysname": "TBD",
                "sysversion": "none"
            },
            ...
            "14": {
                "mfg": "1006",
                "sysname": "TBD",
                "sysversion": "none"
            }
        },
        "prod": {
            "2": [
                [
                    "Windows 7 Home Premium",
                    "c.2009",
                    "360",
                    "609",
                    "English",
                    "Operating System"
                ]
            ],
            ...
            "14": [
                [
                    "MSDN Disc 5085",
                    "November 2012",
                    "189",
                    "609",
                    "English",
                    "MSDN Library"
                ]
            ]
        }
    },
    ...
}
```

#### status_[execution-time]_malicious.json  
Note that "positives" will be a none-zero value. Virus scanner will return true for "detected". The following malicious results will all come from VirusTotal.
```
{
    "<sha1>": {
        "md5": "<md5>",
        "permalink": "https://www.virustotal.com/file/<value>/analysis/<value>/",
        "positives": 40,
        "resource": "#",
        "response_code": 1,
        "scan_date": "<datetime>",
        "scan_id": "<id>",
        "scans": {
            "ALYac": {
                "detected": true,
                "result": <value>,
                "update": "<value>",
                "version": "<value>"
            },
            "AVG": {
                "detected": true,
                "result": <value>,
                "update": "<value>",
                "version": "<value>"
            },
            ...
            "nProtect": {
                "detected": true,
                "result": <value>,
                "update": "<value>",
                "version": "<value>"
            }
        },
        "sha1": "<sha1>",
        "sha256": "<sha256>",
        "total": 57,
        "verbose_msg": "<message>"
    }
}
```
### References

"National Software Reference Library." National Software Reference Library. N.p., n.d. Web.  
26 Oct. 2016. <http://www.nsrl.nist.gov/>.  
"VirusTotal - Free Online Virus, Malware and URL Scanner." VirusTotal - Free Online Virus, Malware and URL Scanner. N.p., n.d. Web. 08 Dec. 2016. <https://www.virustotal.com/>.
