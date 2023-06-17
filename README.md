# Auto install Elastic 8.x on Kali-Purple  

## Requirements  
RAM - 8 GB  
CPU - 4 vCores  
Elastic advise at least 8 GB for Elasticsearch, however you can reduce the VM to 6 GB if needed  

## Note  
This has been tested for Elastic 8.8.0 on Kali-Purple 2023.2a  
This is not for production!  
Please use as a guide only, I do things like placing the `elastic` user password in a file  
This should never be done in prod!   

## Instructions  
Use `get clone` to download this script  
Run with `sudo bash Kali-Purple-Elastic-Install.sh` to install  
Take note of the password and tokens at the end  
**The script has been updated so now conforms with my other script structure.**

## DNS settings  
Replace Kali_Purple_IP with the IP of the VM (If you have the right network settings, you can always access Kibana from within Kali)  
### Windows Powershell  
`Add-Content 'C:\Windows\System32\Drivers\etc\hosts' "Kali_Purple_IP kali-purple.kali.purple"`  
### Linux Bash  
`echo "Kali_Purple_IP kali-purple.kali.purple" >> /etc/hosts`  

## Improvements  
