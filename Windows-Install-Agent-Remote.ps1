# This will only work on Windows (it has not been tested on other platforms)
$VER="8.8.0"

# Add the DNS name and IP. Change to whatever your Kali Purple host IP is
Add-Content 'C:\Windows\System32\Drivers\etc\hosts' "192.168.56.129 kali-purple.kali.purple"

# Make Elastic opt dir
New-Item -ItemType Directory -Force -Path C:\opt\elastic\

# Download all needed items
$global:progressPreference = 'silentlyContinue'
Invoke-WebRequest -Uri ("http://kali-purple.kali.purple:8000/apps/elastic-agent-"+$VER+"-windows-x86_64.zip") -OutFile ("C:\opt\elastic\elastic-agent-"+$VER+"-windows-x86_64.zip") -UseBasicParsing
Invoke-WebRequest -Uri "http://kali-purple.kali.purple:8000/certs/ca.crt" -OutFile "C:\opt\elastic\ca.crt" -UseBasicParsing
Invoke-WebRequest -Uri "http://kali-purple.kali.purple:8000/tokens/WAEtoken.txt" -OutFile "C:\opt\elastic\WAEtoken.txt" -UseBasicParsing

# Unpack the agent
Expand-Archive -Path ("C:\opt\elastic\elastic-agent-"+$VER+"-windows-x86_64.zip") -DestinationPath 'C:\Program Files\'

# Install the agent
& "C:\Program Files\elastic-agent-$VER-windows-x86_64\elastic-agent.exe" install -f --url=https://kali-purple.kali.purple:8220 --certificate-authorities='C:\opt\elastic\ca.crt' --enrollment-token=$(Get-Content C:\opt\elastic\WAEtoken.txt)
