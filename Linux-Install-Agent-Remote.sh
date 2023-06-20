#!/usr/bin/env bash
# This will only work on Centos 7 / Rocky (it has not been tested on other distros)
export VER=8.8.0
export DNS=kali-purple.kali.purple
# Replace the IP address with the one for your Kali-Purple instance
export ES_IP_ADDR=192.168.56.129

echo "$ES_IP_ADDR $DNS" >> /etc/hosts

# Make Elastic opt dir
mkdir /opt/elastic/

# Donwload all needed items
wget $DNS:8000/apps/elastic-agent-$VER-linux-x86_64.tar.gz -P /opt/elastic/
wget $DNS:8000/certs/ca.crt -P /opt/elastic/
wget $DNS:8000/tokens/LAEtoken.txt -P /opt/elastic/

# unpack the agent
tar -xf /opt/elastic/elastic-agent-$VER-linux-x86_64.tar.gz -C /opt/elastic/

# Check if Kibana is reachable 
kcheck=$(curl -L --silent --output /dev/null --cacert /opt/elastic/ca.crt -XGET "https://$DNS:5601" --write-out %{http_code})
until [ $kcheck -eq 200 ]
do
  echo "Checking if Kibana is reachable, retrying..."
  sleep 5
done
echo "Kibana is reachable"

# Install the agent
sudo /opt/elastic/elastic-agent-$VER-linux-x86_64/elastic-agent install -f \
  --url=https://$DNS:8220 \
  --enrollment-token=$(cat /opt/elastic/LAEtoken.txt) \
  --certificate-authorities=/opt/elastic/ca.crt