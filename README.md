# scripts
# Memory & Disk Forensics Analyzer

A modular Bash script that automates forensic analysis on single files or whole directories.  
It integrates common tools (binwalk, strings, foremost, bulk_extractor) and supports memory analysis using both Volatility 2 and Volatility 3.

## Features
- Automatic tool checks & installation  
- HDD analysis (binwalk, strings, foremost, bulk_extractor)  
- Memory analysis with Volatility 2 (profiles, processes, network, registry)  
- Memory analysis with Volatility 3 (Win10+)  
- Auto-report generation + ZIP packaging  

## Usage
Run the script as root and follow the interactive menu.

## Integrity Verification (SHA-256)
to verify that the script has not been altered compare the SHA-256 hash below with the hash of your downloaded version:
**SHA-256**
FE863A43B10F529D5089D0F0E01C0DCF2AB62555C783D72EB6E164C609D3B1BE

You can verify using:
get-filehash '.\Memory_&_Disk_Forensics_Analyzer.sh' -Algorithm sha256

