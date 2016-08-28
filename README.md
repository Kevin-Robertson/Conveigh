# Conveigh  
Conveigh is a Windows PowerShell LLMNR/NBNS spoofer detection tool.  

## Function  
### Invoke-Conveigh  
* The main Conveigh LLMNR/NBNS spoofer detection function.  

##### Privilege Requirements:  
* Elevated Administrator shell  

##### Features:  
* Generates and sends IPv4 LLMNR/NBNS requests with random or set hostnames  
* Detects responses to sent IPv4 LLMNR/NBNS requests using a packet sniffer  
* Optionally displays all received IPv4 LLMNR/NBNS requests using a packet sniffer  
* File output  
* Run time control  

##### Parameters:  
* __CaptureRequests__ - Default = Disabled: (Y/N) Enable/Disable displaying and logging all received LLMNR/NBNS requests.  
* __IP__ - Specify a specific local IP address for listening. This IP address will also be used for LLMNR/NBNS spoofing if the 'SpooferIP' parameter is not set.  
* __Hostnames__ - Array of hostnames that will be randomly selected for LLMNR/NBNS requests. Hostnames must meet NBNS hostname requirements. If this parameter is not used, hostnames will be randomly generated.  
* __MaxSendRequestTime__ - Default = 30 Minutes: Set the maximum random time in minutes for sending LLMNR/NBNS requests.  
* __FileOutput__ - Default = Disabled: (Y/N) Enable/Disable real time file output.  
* __OutputDir__ - Default = Working Directory: Set a valid path to an output directory for log and capture files. FileOutput must also be enabled.   
* __RunTime__ - Default = Unlimited: (Integer) Set the run time duration in minutes.  
  
## System Requirements  
* Tested minimums are PowerShell 2.0 and .NET 3.5  

## Usage  
* To import with Import-Module:   
	Import-Module ./Conveigh.ps1  

* To import using dot source method:  
	. ./Conveigh.ps1  

## Examples  
* To execute with default settings:  
	Invoke-Conveigh  

* To import and execute with one line:  
	Import-Module ./Conveigh.ps1;Invoke-Conveigh  

* To execute with parameters:  
	Invoke-Conveigh -Hostnames host1,host2,host3 -RunTime 8  
