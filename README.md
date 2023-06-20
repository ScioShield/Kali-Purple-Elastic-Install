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
### Install an Elastic Agent on remote systems  
**Linux**  
On the Kali-Purple host  
Run a Python HTTP server in the directory you ran the `Kali-Purple-Elastic-Install.sh` script from.  
`python3 -m http.server`  
On the remote Linux host  
Copy the `Linux-Install-Agent-Remote.sh` script (Remember to change the [ES_IP_ADDR](https://github.com/ScioShield/Kali-Purple-Elastic-Install/blob/151df3a1bba02f26b6255df120feb150a676b367/Linux-Install-Agent-Remote.sh#LL6C33-L6C33 also make sure the IP address [here](https://github.com/ScioShield/Kali-Purple-Elastic-Install/blob/4a669573592adf723e7afa8e2dcb623f27733f5a/Kali-Purple-Elastic-Install.sh#L24) is the interface you expect Agents to connect back to) to the correct address for you) you can use `curl`, `wget` or a good old copy paste. Note the script expects `wget` to be present on the remote host, install with `sudo apt install wget` or `sudo yum install wget`.  
Now run the script with `sudo bash Linux-Install-Agent-Remote.sh`, the script downloads all required items; the agent, the enrollment token, and the CA certificate from the Kali-Purple host. It has sanity checks to make sure Kibana is reachable from where it's running from.  
On the Kali-Purple host  
It is now safe to stop the Python HTTP server `Ctrl+c` in the window you ran it from to stop the server.  


## Explanation
The script installs ElasticSearch, Kibana, and Fleet in a "non-development" mode (main security settings like TLS, and Kibana sec keys, etc).  
### Downloads
The download_and_verify bash function downloads all the required applications at the specified version and checks the SHA-512 hashes automatically.  
### Certificates
We make use of the ElasticSearch certutil built in to generate certificates for ElasticSearch, Kibana and Fleet. The Fleet certificates are needed for it to be setup in a manageable state. The certs are then moved to where they are needed in each apps /etc/ dir (Except Fleet where we make a place for them in /etc/pki/fleet/). The root CA cert is placed in /opt/Elastic for ease of access, no file-level permissions are taken into account.  
### ElasticSearch
A single node setup is all we need for our purposes. All certificate paths are then provisioned. The Systemd timeout is also changed from the default 75 seconds to ~8 minutes, this is to account for the fact that there may be CPU prioritization challenges as we are in a smaller VM. The service is then started and enabled (needed to account for restarts). You can check the status with `sudo systemctl status elasticsearch`. We use the `elastic` user/pass for API authentications, I am planning to change this to an API user in the future. The authentication mechanism in place at the moment means we save the Elastic super users password to a file and a variable.  
### Kibana
We are using password based authentication between Kibana and ElasticSearch so the password is created and later added to the Kibana key store (Not to store it in plain text in the .yml file). The Kibana configuration .yml sets all required values `server.publicUrl` is set to prevent a popup, and the `xpack.*encryptionKey` are set to use as encryption keys for different parts of the Kibana platform. The service is then started and enabled. You can check the status with `sudo systemctl status kibana`.  
### Fleet
Most of the `curl` calls are related to Fleet. We setup the Fleet token for enrollment, then create the policy, then add the integration. Once the policy is in place we update the settings as required. You will notice I am using `curl`'s `@` operator, this is to read the unchanging sections like the headers and body from files, so we only need to change them once. All required keys (I call them keys but they're the value section of the key:value JSON pairs) are placed in ./keys. `jq` is used to replace my old `grep` methods to extract and modify all required values.  
#### Fleet Policies
Some background Fleet Policies house the integrations we enable, I've separated this deployment into three main sections; 
- Fleet (Used to be a default policy but now we need to create it)  
- Windows  
- Linux  

This separation allows for targeted integrations to apply to only one major platform at a time, this can be subdivided further so a "Linux - Apache", "Linux - SQLite", "Windows - IIS" etc. but for our purposes this division allows enough segregation.  
#### Fleet Integrations
The integrations we enable are as follows;  
**Windows**  
- Windows integration, this is used to gather logs from the Windows hosts, like the event viewer logs.  
- Windows integration custom, this is used to get the custom logs produced by Windows Defender.  
- Windows Elastic Defender integration, the Elastic Defender is cross platform, but I've decided to instead to enable each major platform to have it's own Elastic Defender instance. For our testing purposes the Defender integration is enabled in "detect" mode, to change this on windows change these [lines](https://github.com/ScioShield/Kali-Purple-Elastic-Install/blob/9e2428cb451c329994051df593c8859fcb913b53/Kali-Purple-Elastic-Install.sh#LL288C1-L288C1) to "protect", also to not register the Elastic Defender as an AV change this section to "false" ".inputs[0].config.policy.value.windows.antivirus_registration.enabled = "true"" this [line](https://github.com/ScioShield/Kali-Purple-Elastic-Install/blob/9e2428cb451c329994051df593c8859fcb913b53/Kali-Purple-Elastic-Install.sh#L291).  
- Windows System integration, this is provisioned by default for all policies, it gathers system metrics like CPU & RAM usage.  

**Linux**  
- Linux integration, like the Windows integration this allows for logs from Linux to be gathered.  
- Linux Elastic Defender integration, like the Windows counter part this enables the Elastic Defender in detect mode. To change the integration from "detect" to "protect" mode change these [lines](https://github.com/ScioShield/Kali-Purple-Elastic-Install/blob/9e2428cb451c329994051df593c8859fcb913b53/Kali-Purple-Elastic-Install.sh#L325) to "protect".  
- Linux system integration, this is provisioned by default for all policies, it gathers system metrics like CPU & RAM usage.  
### Alerts
We automatically enable all alerts for the Windows and Linux platforms (or at least if they are tagged with either platform) in this [line](https://github.com/ScioShield/Kali-Purple-Elastic-Install/blob/9e2428cb451c329994051df593c8859fcb913b53/Kali-Purple-Elastic-Install.sh#L336). If there are any more tags you'd like enabled add an `OR alert.attributes.tags: \"CHANGEME\"` to the end of the query section.
#### Fleet Server
The fleet server is then enabled by installing the Elastic Agent with specific settings.
#### Enrollment Tokens
We place them in the ./tokens dir and print them. You will also need the CA cert located in the /opt/Elastic/ or ./certs/ dir to enroll new agents. Here is an example for [Windows](https://github.com/ScioShield/AtomicFireFly/blob/2ecbd6d6ee7754539ac2419af1a557e14a51c8ec/AWBootstrap.ps1#L16) here is an example for [Linux](https://github.com/ScioShield/AtomicFireFly/blob/2ecbd6d6ee7754539ac2419af1a557e14a51c8ec/ALBootstrap.sh#L16).  


## DNS settings  
Replace Kali_Purple_IP with the IP of the VM (If you have the right network settings, you can always access Kibana from within Kali)  
### Windows Powershell  
`Add-Content 'C:\Windows\System32\Drivers\etc\hosts' "Kali_Purple_IP kali-purple.kali.purple"`  
### Linux Bash  
`echo "Kali_Purple_IP kali-purple.kali.purple" >> /etc/hosts`  

## Improvements  
Write examples to install the Agent on Windows and Linux with a python server