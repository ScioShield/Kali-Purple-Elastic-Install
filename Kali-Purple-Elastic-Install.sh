#!/usr/bin/env bash
# This will only work on Kali Purple Linux (it has not been tested on other distros!)

# Test if the VM can reach the internet to download packages
until ping -c 1 google.com | grep -q "bytes from"
do
    echo "Offline, still waiting..."
    sleep 5
done
echo "Online!"

# RPM ONLY (THINK HOW TO MAKE FOR MAINLINE DISTROS WITH UNAME?)
# Get the GPG key temp work around is to reenable SHA1 support for GPG keys, will update when Elastic move to 256/512
# Run this when done
# update-crypto-policies --set DEFAULT
# update-crypto-policies --set DEFAULT:SHA1
# rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch

# Add Elastic and Kibana and the Elastic Agents
# Download and install Ealsticsearch and Kibana change ver to whatever you want
# For me 8.6.1 is the latest we put it in /opt/Elastic to not download it again
# The -q flag is need to not spam stdout on the host machine
# We also pull the SHA512 hashes for you to check

# var settings
VER=8.6.1
IP_ADDR=10.0.2.15
K_PORT=5601
ES_PORT=9200
F_PORT=8220
DNS=kali-purple.kali.purple

echo "$IP_ADDR $DNS" >> /etc/hosts

mkdir /opt/Elastic/

wget -nc -q https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$VER-amd64.deb -P /opt/Elastic/
wget -nc -q https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$VER-amd64.deb.sha512 -P /opt/Elastic/

wget -nc -q https://artifacts.elastic.co/downloads/kibana/kibana-$VER-amd64.deb -P /opt/Elastic/
wget -nc -q https://artifacts.elastic.co/downloads/kibana/kibana-$VER-amd64.deb.sha512 -P /opt/Elastic/

wget -nc -q https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$VER-linux-x86_64.tar.gz -P /opt/Elastic/
wget -nc -q https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$VER-linux-x86_64.tar.gz.sha512 -P /opt/Elastic/

# Used for Vagrant multi deployment with a Windows host
# wget -nc -q https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$VER-windows-x86_64.zip -P /opt/Elastic/
# wget -nc -q https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$VER-windows-x86_64.zip.sha512 -P /opt/Elastic/
# wget -nc -q https://download.sysinternals.com/files/Sysmon.zip -P /opt/Elastic/
# wget -nc -q https://github.com/git-for-windows/git/releases/download/v2.39.2.windows.1/Git-2.39.2-64-bit.exe -P /opt/Elastic/

# We output to a temp password file allowing auto config later on
tar -xf /opt/Elastic/elastic-agent-$VER-linux-x86_64.tar.gz -C /opt/
dpkg --install /opt/Elastic/elasticsearch-$VER-amd64.deb 2>&1 | tee /root/ESUpass.txt

echo "Kibana takes a while to unpack, it is not frozen!"
dpkg --install /opt/Elastic/kibana-$VER-amd64.deb

# Make the cert dir to prevent pop-up later
mkdir /tmp/certs/

# Config the instances file for cert gen the ip is $IP_ADDR
cat > /tmp/certs/instance.yml << EOF
instances:
  - name: 'elasticsearch'
    dns: ['$DNS']
    ip: ['$IP_ADDR']
  - name: 'kibana'
    dns: ['$DNS']
  - name: 'fleet'
    dns: ['$DNS']
    ip: ['$IP_ADDR']
EOF

# Make the certs and move them where they are needed
/usr/share/elasticsearch/bin/elasticsearch-certutil ca --pem --pass secret --out /tmp/certs/elastic-stack-ca.zip
unzip /tmp/certs/elastic-stack-ca.zip -d /tmp/certs/
/usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca-cert /tmp/certs/ca/ca.crt -ca-key /tmp/certs/ca/ca.key --ca-pass secret --pem --in /tmp/certs/instance.yml --out /tmp/certs/certs.zip
unzip /tmp/certs/certs.zip -d /tmp/certs/

mkdir -p /etc/kibana/certs
mkdir -p /etc/pki/fleet

cp /tmp/certs/ca/ca.crt /tmp/certs/elasticsearch/* /etc/elasticsearch/certs
cp /tmp/certs/ca/ca.crt /tmp/certs/kibana/* /etc/kibana/certs
cp /tmp/certs/ca/ca.crt /tmp/certs/fleet/* /etc/pki/fleet
cp -r /tmp/certs/* /root/

# This cp should be an unaliased cp to replace the ca.crt if it exists in the shared /opt/Elastic dir
cp -u /tmp/certs/ca/ca.crt /opt/Elastic

# Config and start Elasticsearch (we are also increasing the timeout for systemd to 500)
mv /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.bak

cat > /etc/elasticsearch/elasticsearch.yml << EOF
# ======================== Elasticsearch Configuration =========================
#
# ----------------------------------- Paths ------------------------------------
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
# ---------------------------------- Network -----------------------------------
network.host: $IP_ADDR
http.port: $ES_PORT
# --------------------------------- Discovery ----------------------------------
discovery.type: single-node
# ----------------------------------- X-Pack -----------------------------------
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
xpack.security.transport.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt
xpack.security.transport.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca.crt" ]
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt
xpack.security.http.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca.crt" ]
xpack.security.authc.api_key.enabled: true
EOF

sed -i 's/TimeoutStartSec=75/TimeoutStartSec=500/g' /lib/systemd/system/elasticsearch.service
systemctl daemon-reload
systemctl start elasticsearch
systemctl enable elasticsearch

# Gen the users and paste the output for later use
/usr/share/elasticsearch/bin/elasticsearch-reset-password -b -u kibana_system -a > /root/Kibpass.txt
# /usr/share/elasticsearch/bin/elasticsearch-reset-password -b -u elastic -a > /root/ESUpass.txt

# Add the Kibana password to the keystore
grep "New value:" /root/Kibpass.txt | awk '{print $3}' | sudo /usr/share/kibana/bin/kibana-keystore add --stdin elasticsearch.password

# Configure and start Kibana adding in the unique kibana_system keystore pass and generating the sec keys
cat > /etc/kibana/kibana.yml << EOF
# =========================== Kibana Configuration ============================
# -------------------------------- Network ------------------------------------
server.host: 0.0.0.0
server.port: $K_PORT
# ------------------------------ Elasticsearch --------------------------------
elasticsearch.hosts: ["https://$IP_ADDR:$ES_PORT"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "\${elasticsearch.password}"
# ---------------------------------- Various -----------------------------------
server.publicBaseUrl: "https://kali-purple.kali.purple:5601"
server.ssl.enabled: true
server.ssl.certificate: "/etc/kibana/certs/kibana.crt"
server.ssl.key: "/etc/kibana/certs/kibana.key"
elasticsearch.ssl.certificateAuthorities: [ "/etc/kibana/certs/ca.crt" ]
elasticsearch.ssl.verificationMode: "none"
# ---------------------------------- X-Pack ------------------------------------
xpack.security.encryptionKey: "$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32 ; echo '')"
xpack.encryptedSavedObjects.encryptionKey: "$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32 ; echo '')"
xpack.reporting.encryptionKey: "$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32 ; echo '')"
EOF

systemctl start kibana
systemctl enable kibana

# Var settings (has to happen after Elastic is installed)
E_PASS=$(sudo grep "generated password for the elastic" /root/ESUpass.txt | awk '{print $11}')
grep "generated password for the elastic" /root/ESUpass.txt | awk '{print $11}' > /opt/Elastic/Password.txt

# Test if Kibana is running
echo "Testing if Kibana is online, could take some time, no more than 5 mins"
until curl --silent --cacert /tmp/certs/ca/ca.crt -XGET "https://$DNS:$K_PORT/api/fleet/agent_policies" -H 'accept: application/json' -u elastic:$E_PASS | grep -q '"items":\[\]'
do
    echo "Kibana starting, still waiting..."
    sleep 5
done
echo "Kibana online!"

# Make the Fleet token
curl --silent -XPUT "https://$IP_ADDR:$ES_PORT/_security/service/elastic/fleet-server/credential/token/fleet-token-1" \
 --cacert /tmp/certs/ca/ca.crt \
 -u elastic:$E_PASS > /root/Ftoken.txt

cat /root/Ftoken.txt | sed "s/\,/'\n'/g" | grep -oP '[^"name"][a-zA-Z0-9]{50,}' > /opt/Elastic/Ftoken.txt

# Add Fleet Policy
curl --silent --cacert /tmp/certs/ca/ca.crt -XPOST \
  -u elastic:$E_PASS \
  -o /root/FPid.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/agent_policies?sys_monitoring=true" \
  --header "Accept: */*" \
  --header "Cache-Control: no-cache" \
  --header "Connection: keep-alive" \
  --header "Content-Type: application/json" \
  --header "kbn-xsrf: reporting" \
  --data '{
  "name": "Fleet Policy",
  "description": "",
  "namespace": "default",
  "monitoring_enabled": [
    "logs",
    "metrics"
  ]
}'

# Get the policy key
#curl --silent --cacert /tmp/certs/ca/ca.crt -XGET "https://$DNS:$K_PORT/api/fleet/agent_policies" -H 'accept: application/json' -u elastic:$E_PASS > /root/Pid.txt
cat /root/FPid.txt | sed "s/\},{/'\n'/g" | grep "Fleet Policy" | grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}' > /opt/Elastic/FPid.txt

# Add Fleet Integration
curl --silent --cacert /tmp/certs/ca/ca.crt -XPOST \
  -u elastic:$E_PASS \
  -o /root/FIid.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header "Accept: */*" \
  --header "Cache-Control: no-cache" \
  --header "Connection: keep-alive" \
  --header "Content-Type: application/json" \
  --header "kbn-xsrf: reporting" \
  --data '{
  "policy_id": "'$(cat /opt/Elastic/FPid.txt)'",
  "package": {
    "name": "fleet_server",
    "version": "1.2.0"
  },
  "name": "fleet_server-1",
  "description": "",
  "namespace": "default",
  "inputs": {
    "fleet_server-fleet-server": {
      "enabled": true,
      "vars": {
        "host": [
          "0.0.0.0"
        ],
        "port": [
          8220
        ],
        "custom": ""
      },
      "streams": {}
    }
  }
}'


cat /root/FIid.txt | sed "s/\},{/'\n'/g" | awk 'BEGIN{ RS = "," ; FS = "\n" }{print $1}' | grep \"id\" | grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}' > /opt/Elastic/FIid.txt

# Add host IP and yaml settings to Fleet API
curl --silent --cacert /tmp/certs/ca/ca.crt -XPUT "https://$DNS:$K_PORT/api/fleet/package_policies/$(cat /opt/Elastic/FIid.txt)" \
 -u elastic:$E_PASS \
 -H "accept: application/json" \
 -H "kbn-xsrf: reporting" \
 -H "Content-Type: application/json" -d'{
  "package": {
    "name": "fleet_server",
    "version": "1.2.0"
  },
  "name": "fleet_server-1",
  "namespace": "default",
  "description": "",
  "policy_id": "'$(cat /opt/Elastic/FPid.txt)'",
  "inputs": {
    "fleet_server-fleet-server": {
      "enabled": true,
      "vars": {
        "host": "'$IP_ADDR'",
        "port": [
          8220
        ],
        "custom": "ssl.certificate_authorities: [\"/opt/Elastic/ca.crt\"]"
      },
      "streams": {}
    }
  }
}'

# Add host IP and yaml settings to Fleet API
 curl --silent --cacert /tmp/certs/ca/ca.crt -XPUT "https://$DNS:$K_PORT/api/fleet/outputs/fleet-default-output" \
 -u elastic:$E_PASS \
 -H "accept: application/json" \
 -H "kbn-xsrf: reporting" \
 -H "Content-Type: application/json" -d'{
"name": "default",
"type": "elasticsearch",
"is_default": true,
"is_default_monitoring": true,
"hosts": [
  "https://'$IP_ADDR:$ES_PORT'"
  ],
"ca_sha256": "",
"ca_trusted_fingerprint": "",
"config_yaml": "ssl.certificate_authorities: [\"/opt/Elastic/ca.crt\"]"
}'


# Create the Windows Policy
curl --silent --cacert /tmp/certs/ca/ca.crt -XPOST \
  -u elastic:$E_PASS \
  -o /root/WPid.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/agent_policies?sys_monitoring=true" \
  --header "Accept: */*" \
  --header "Cache-Control: no-cache" \
  --header "Connection: keep-alive" \
  --header "Content-Type: application/json" \
  --header "kbn-xsrf: reporting" \
  --data '{
  "name": "Windows",
  "description": "",
  "namespace": "default",
  "monitoring_enabled": [
    "logs",
    "metrics"
  ]
}'

cat /root/WPid.txt | sed "s/\},{/'\n'/g" | grep "Windows" | grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}' > /opt/Elastic/WPid.txt


# Create the Linux Policy
curl --silent --cacert /tmp/certs/ca/ca.crt -XPOST \
  -u elastic:$E_PASS \
  -o /root/LPid.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/agent_policies?sys_monitoring=true" \
  --header "Accept: */*" \
  --header "Cache-Control: no-cache" \
  --header "Connection: keep-alive" \
  --header "Content-Type: application/json" \
  --header "kbn-xsrf: reporting" \
  --data '{
  "name": "Linux",
  "description": "",
  "namespace": "default",
  "monitoring_enabled": [
    "logs",
    "metrics"
  ]
}'

cat /root/LPid.txt | sed "s/\},{/'\n'/g" | grep "Linux" | grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}' > /opt/Elastic/LPid.txt

# Add Windows Integration
curl --silent --cacert /tmp/certs/ca/ca.crt -XPOST \
  -u elastic:$E_PASS \
  -o /root/WIid.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header "Accept: */*" \
  --header "Cache-Control: no-cache" \
  --header "Connection: keep-alive" \
  --header "Content-Type: application/json" \
  --header "kbn-xsrf: reporting" \
  --data '{
    "policy_id": "'$(cat /opt/Elastic/WPid.txt)'",
    "package": {
      "name": "windows",
      "version": "1.17.0"
    },
    "name": "windows-1",
    "description": "",
    "namespace": "default",
    "inputs": {
      "windows-winlog": {
        "enabled": true,
        "streams": {
          "windows.forwarded": {
            "enabled": true,
            "vars": {
              "preserve_original_event": false,
              "ignore_older": "72h",
              "language": 0,
              "tags": [
                "forwarded"
              ]
            }
          },
          "windows.powershell": {
            "enabled": true,
            "vars": {
              "preserve_original_event": false,
              "event_id": "400, 403, 600, 800",
              "ignore_older": "72h",
              "language": 0,
              "tags": []
            }
          },
          "windows.powershell_operational": {
            "enabled": true,
            "vars": {
              "preserve_original_event": false,
              "event_id": "4103, 4104, 4105, 4106",
              "ignore_older": "72h",
              "language": 0,
              "tags": []
            }
          },
          "windows.sysmon_operational": {
            "enabled": true,
            "vars": {
              "preserve_original_event": false,
              "ignore_older": "72h",
              "language": 0,
              "tags": []
            }
          }
        }
      },
      "windows-windows/metrics": {
        "enabled": true,
        "streams": {
          "windows.perfmon": {
            "enabled": true,
            "vars": {
              "perfmon.group_measurements_by_instance": false,
              "perfmon.ignore_non_existent_counters": false,
              "perfmon.queries": "- object: \"Process\"\n  instance: [\"*\"]\n  counters:\n   - name: \"% Processor Time\"\n     field: cpu_perc\n     format: \"float\"\n   - name: \"Working Set\"\n",
              "period": "10s"
            }
          },
          "windows.service": {
            "enabled": true,
            "vars": {
              "period": "60s"
            }
          }
        }
      },
      "windows-httpjson": {
        "enabled": false,
        "vars": {
          "url": "https://server.example.com:8089",
          "ssl": ""
        },
        "streams": {
          "windows.forwarded": {
            "enabled": false,
            "vars": {
              "interval": "10s",
              "search": "search sourcetype=\"XmlWinEventLog:ForwardedEvents\"",
              "tags": [
                "forwarded"
              ],
              "preserve_original_event": false
            }
          },
          "windows.powershell": {
            "enabled": false,
            "vars": {
              "interval": "10s",
              "search": "search sourcetype=\"XmlWinEventLog:Windows PowerShell\"",
              "tags": [
                "forwarded"
              ],
              "preserve_original_event": false
            }
          },
          "windows.powershell_operational": {
            "enabled": false,
            "vars": {
              "interval": "10s",
              "search": "search sourcetype=\"XmlWinEventLog:Microsoft-Windows-Powershell/Operational\"",
              "tags": [
                "forwarded"
              ],
              "preserve_original_event": false
            }
          },
          "windows.sysmon_operational": {
            "enabled": false,
            "vars": {
              "interval": "10s",
              "search": "search sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\"",
              "tags": [
                "forwarded"
              ],
              "preserve_original_event": false
            }
          }
        }
      }
    }
  }'

cat /root/WIid.txt | sed "s/\},{/'\n'/g" | awk 'BEGIN{ RS = "," ; FS = "\n" }{print $1}' | grep \"item\" | grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}' > /opt/Elastic/WIid.txt

# Add Custom Windows Event Logs - Windows Defender Logs
curl --silent --cacert /tmp/certs/ca/ca.crt -XPOST \
  -u elastic:$E_PASS \
  -o /root/CWIid.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header "Accept: */*" \
  --header "Cache-Control: no-cache" \
  --header "Connection: keep-alive" \
  --header "Content-Type: application/json" \
  --header "kbn-xsrf: reporting" \
  --data '{
  "package": {
    "name": "winlog",
    "version": "1.12.2"
  },
  "name": "winlog-1",
  "namespace": "default",
  "description": "",
  "policy_id": "'$(cat /opt/Elastic/WPid.txt)'",
  "inputs": {
    "winlogs-winlog": {
      "enabled": true,
      "streams": {
        "winlog.winlog": {
          "enabled": true,
          "vars": {
            "channel": "Microsoft-Windows-Windows Defender/Operational",
            "data_stream.dataset": "winlog.winlog",
            "preserve_original_event": false,
            "providers": [],
            "ignore_older": "72h",
            "language": 0,
            "tags": [],
            "custom": "# REMOVED"
          }
        }
      }
    },
    "winlogs-httpjson": {
      "enabled": false,
      "vars": {
        "url": "https://server.example.com:8089",
        "ssl": "#certificate_authorities:\n#  - |\n#    -----BEGIN CERTIFICATE-----\n#    MIIDCjCCAfKgAwIBAgITJ706Mu2wJlKckpIvkWxEHvEyijANBgkqhkiG9w0BAQsF\n#    ADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwIBcNMTkwNzIyMTkyOTA0WhgPMjExOTA2\n#    MjgxOTI5MDRaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEB\n#    BQADggEPADCCAQoCggEBANce58Y/JykI58iyOXpxGfw0/gMvF0hUQAcUrSMxEO6n\n#    fZRA49b4OV4SwWmA3395uL2eB2NB8y8qdQ9muXUdPBWE4l9rMZ6gmfu90N5B5uEl\n#    94NcfBfYOKi1fJQ9i7WKhTjlRkMCgBkWPkUokvBZFRt8RtF7zI77BSEorHGQCk9t\n#    /D7BS0GJyfVEhftbWcFEAG3VRcoMhF7kUzYwp+qESoriFRYLeDWv68ZOvG7eoWnP\n#    PsvZStEVEimjvK5NSESEQa9xWyJOmlOKXhkdymtcUd/nXnx6UTCFgnkgzSdTWV41\n#    CI6B6aJ9svCTI2QuoIq2HxX/ix7OvW1huVmcyHVxyUECAwEAAaNTMFEwHQYDVR0O\n#    BBYEFPwN1OceFGm9v6ux8G+DZ3TUDYxqMB8GA1UdIwQYMBaAFPwN1OceFGm9v6ux\n#    8G+DZ3TUDYxqMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAG5D\n#    874A4YI7YUwOVsVAdbWtgp1d0zKcPRR+r2OdSbTAV5/gcS3jgBJ3i1BN34JuDVFw\n#    3DeJSYT3nxy2Y56lLnxDeF8CUTUtVQx3CuGkRg1ouGAHpO/6OqOhwLLorEmxi7tA\n#    H2O8mtT0poX5AnOAhzVy7QW0D/k4WaoLyckM5hUa6RtvgvLxOwA0U+VGurCDoctu\n#    8F4QOgTAWyh8EZIwaKCliFRSynDpv3JTUwtfZkxo6K6nce1RhCWFAsMvDZL8Dgc0\n#    yvgJ38BRsFOtkRuAGSf6ZUwTO8JJRRIFnpUzXflAnGivK9M13D5GEQMmIl6U9Pvk\n#    sxSmbIUfc2SGJGCJD4I=\n#    -----END CERTIFICATE-----\n"
      },
      "streams": {
        "winlog.winlog": {
          "enabled": false,
          "vars": {
            "interval": "10s",
            "search": "search sourcetype=\"XmlWinEventLog:ChannelName\"",
            "data_stream.dataset": "winlog.winlog",
            "tags": [
              "forwarded"
            ]
          }
        }
      }
    }
  }
}'

# Add Linux Integration
curl --silent --cacert /tmp/certs/ca/ca.crt -XPOST \
  -u elastic:$E_PASS \
  -o /root/LIid.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header "Accept: */*" \
  --header "Cache-Control: no-cache" \
  --header "Connection: keep-alive" \
  --header "Content-Type: application/json" \
  --header "kbn-xsrf: reporting" \
  --data '{
  "policy_id": "'$(cat /opt/Elastic/LPid.txt)'",
  "package": {
    "name": "auditd",
    "version": "3.5.0"
  },
  "name": "auditd-1",
  "description": "",
  "namespace": "default",
  "inputs": {
    "auditd-logfile": {
      "enabled": true,
      "streams": {
        "auditd.log": {
          "enabled": true,
          "vars": {
            "paths": [
              "/var/log/audit/audit.log*"
            ],
            "tags": [
              "auditd-log"
            ],
            "preserve_original_event": false
          }
        }
      }
    }
  }
}'

cat /root/LIid.txt | sed "s/\},{/'\n'/g" | awk 'BEGIN{ RS = "," ; FS = "\n" }{print $1}' | grep \"item\" | grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}' > /opt/Elastic/LIid.txt

# Install the fleet server
sudo /opt/elastic-agent-$VER-linux-x86_64/elastic-agent install -f --url=https://$DNS:$F_PORT \
 --fleet-server-es=https://$DNS:$ES_PORT \
 --fleet-server-service-token=$(cat /opt/Elastic/Ftoken.txt) \
 --fleet-server-policy=$(cat /opt/Elastic/FPid.txt) \
 --certificate-authorities=/opt/Elastic/ca.crt \
 --fleet-server-es-ca=/etc/pki/fleet/ca.crt \
 --fleet-server-cert=/etc/pki/fleet/fleet.crt \
 --fleet-server-cert-key=/etc/pki/fleet/fleet.key

# Get the Windows policy id
curl --silent --cacert /tmp/certs/ca/ca.crt -XGET "https://$DNS:$K_PORT/api/fleet/enrollment_api_keys" -H 'accept: application/json' -u elastic:$E_PASS | sed -e "s/\},{/'\n'/g" -e "s/items/'\n'/g" | grep -E -m1 $(cat /opt/Elastic/WPid.txt) | grep -oP '[a-zA-Z0-9\=]{40,}' > /opt/Elastic/WAEtoken.txt
# Get the Linux policy id
curl --silent --cacert /tmp/certs/ca/ca.crt -XGET "https://$DNS:$K_PORT/api/fleet/enrollment_api_keys" -H 'accept: application/json' -u elastic:$E_PASS | sed -e "s/\},{/'\n'/g" -e "s/items/'\n'/g" | grep -E -m1 $(cat /opt/Elastic/LPid.txt) | grep -oP '[a-zA-Z0-9\=]{40,}' > /opt/Elastic/LAEtoken.txt

echo "To log into KLibana go to https://$DNS:$K_PORT"
echo "Username: elastic"
echo "Password: $(cat /opt/Elastic/Password.txt)"
echo "Tokens are saved in /opt/Elastic/"
echo "To enroll Linux agents use this token: $(cat /opt/Elastic/LAEtoken.txt)"
echo "To enroll Windows agents use this token: $(cat /opt/Elastic/WAEtoken.txt)"
