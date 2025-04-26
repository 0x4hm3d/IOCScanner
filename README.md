# IOCScanner

IOCScanner is an efficient multi-threading script that utilizes the AbuseIPDB and VirusTotal APIs to retrieve crucial information from a vast number of IP addresses. The script will quickly generate an Excel file with a table of the IP addresses and their corresponding information from both websites.

Security analysts regularly review and analyze a large number of IP addresses to identify potential security threats. It is crucial for them to identify the level of maliciousness, the geographic location, the domain name, and other relevant information associated with the IP addresses. By having this information readily available, analysts can expedite the analysis process and identify potential threats more efficiently.

# Installation

IOCScanner requires the usage of python3. Furthermore, there are libraries are required to be installed prior to using the script. 
```bash
python3 -m pip install -r requirements.txt
```
# Requirement

IOCScanner needs at least a valid API key for either AbuseIPDB or VirusTotal to run successfully. The API keys have to be within a text file and follow the format found api keys.txt file. Each Website and API in a separate line. 

```
VirusTotal api_key 
AbuseIPDB api_key
```
# Usage
The script offers multiple options, which can be viewed by supplying the '-h' flag to see the available options.
 * -f: The path to the input file containing IP addresses.
 * -k --api-key : API keys text file with the same format of api keys.txt.
 * -l: a path to save the generated excel file. [optional]
 * -a: Use AbuseIPDB only to scan IP addresses. [optional]
 * -v: Use VirusTotal only to scan IP addresses.[optional]

<<<<<<< HEAD
usage: python3 ioc_scanner.py [-f] IP_File -api API_Key_File | optional -l -a -v
=======
usage: python3 ioc_scanner.py [-f] IP_File -k API_Key_File | optional -l -a -v
>>>>>>> cf289425b8178193e040388a5e4e077d73e37463

Accepts: -f or --file for csv, xlsx or txt files only. Additionally, accepts a text file containing API keys.

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  The path to the input file containing IP addresses.
  -l LOCATION, --location LOCATION
                        Location to save the generated Excel file. By default, it will be created in the same directory
  -a, --AbuseIPDB       Use AbuseIPDB only to scan IP addresses. If neither -a nor -v is specified, both AbuseIPDB and VirusTotal will be used.
  -v, --VirusTotal      Use VirusTotal only to scan IP addresses. If neither -a nor -v is specified, both AbuseIPDB and VirusTotal will be used.
  -k API_KEYS, --api-keys API_KEYS   Path to API key text file.

IP requirement:
  The list of IP addresses can be provided as:
    - A single IP address (e.g., 8.8.8.8)
    - Multiple IP addresses separated by space (e.g., 8.8.8.8 8.8.4.4)
    - Sanitized IP address (e.g., 8[.]8[.]8[.]8)
```
