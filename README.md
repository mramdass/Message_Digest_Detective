# Message Digest Detective

## CS-GY 6963
## Fall 2016
##

## Getting Started

Use these instructions to get started with Message Digest Detective  
split.py is a formatter for the RDS files found in the zipped file. split.py will create A.zip, B.zip, C.zip, and D.zip from RDS_253_A.zip, RDS_253_B.zip, RDS_253_C.zip, and RDS_253_D.zip. this script is meant to be run once when you first download the Combo DVD.  
To actually search for malicious or unknown files, you will run mdd.py by specifing the directory to analyze. Windows System32, Program Files and Program Files (x86) are the directories this script is meant to run on.  
The RDS_Unified directory is redundant and not necessary.

### Prerequisities

Python 2.7.11

```
https://www.python.org/downloads/
```
NSRL RDS - Combo DVD

```
http://www.nsrl.nist.gov/Downloads.htm
```

### Installing

Clone/Download this respository. Note that the '.zip' files in this repository are placeholders as it is very large. From the Combo DVD, place the appropriate named '.zip' file in the appropriate directory. Then run split.py to generate the remaining '.zip' files as mentioned in 'Getting Started'.

### To Run
```
python mdd.py -d <path>
python split.py
```
