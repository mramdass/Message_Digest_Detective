# Message Digest Detective

## CS-GY 6963
## Fall 2016
##

## Getting Started

Use the following instructions to get started with Message Digest Detective  
The intuition behind Message Digest Detective is to be able to scan an entire directory of sub-directories and files which may include thousands of files in less than an hour. Previous attempts to create an effective tool would check a file of hashes one by one which was very time consuming. Furthermore, Message Digest Detective was intended to scan the Windows System32 directory; the intuition here is discover any malicious executables that are running or have been placed there to run. Other applications use this folder to extensively.  
split.py is a formatter for the RDS files found in the zipped file. split.py will create text files, and will zip into A.zip, B.zip, C.zip, and D.zip from RDS_253_A.zip, RDS_253_B.zip, RDS_253_C.zip, and RDS_253_D.zip. This script is meant to be run once when you first download the Combo DVD.  
To actually search for malicious or unknown files, you will run mdd.py by specifing the directory to analyze. Windows System32, Program Files and Program Files (x86) are the directories this script is meant to run on.

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
