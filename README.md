# Auto install Elastic 8.x on Kali-Purple  

## Requirements  
RAM - 8 GB  
CPU - 4 vCores  
Elastic advise at least 8 GB for Elasticsearch, however you can reduce the VM to 6 GB if needed  

## Note  
This has been tested for Elastic 8.6.1 on Kali-Purple 2023.1a  
This is not for production!  
Please use as a guide only, I do things like placing the `elastic` user password in a file  
This should never be done in prod!  
Also certificate management (PKI) should be used  

## Instructions  
Use `get clone` to download this script  
Run with `sudo bash Kali-Purple-Elastic-Install.sh` to install  
Take note of the password and tokens at the end  

## DNS settings  
Replace Kali_Purple_IP with the IP of the VM (If you have the right network settings, you can always access Kibana from within Kali)  
### Windows Powershell  
Add-Content 'C:\Windows\System32\Drivers\etc\hosts' "Kali_Purple_IP kali-purple.kali.purple"  
### Linux Bash  
echo "Kali_-_Purple_IP kali-purple.kali.purple" >> /etc/hosts  

## Improvements  
Change `echo` to `printf`  
Normalize all the `curl` calls  
Place all `--data` sections into their own .json files like in https://github.com/ScioShield/Elastic-Cloud-Agent  
Think about replacing funky `greps` with `jq`  