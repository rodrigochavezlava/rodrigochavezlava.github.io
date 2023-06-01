#!/bin/bash

# Solicitar al usuario que ingrese un valor
echo "Ingresa el nombre de la tarjeta de red que desees analizar:"
read tarjetaRed

echo "Escoge la contraseña de tu encriptación de red | min: 32 caracteres"
read claveEncriptacionRed

longitud=${#claveEncriptacionRed}
echo "La longitud de la contraseña es: $longitud caracteres."

if [ $longitud -ge 32 ]; then
    echo "La contraseña tiene 32 caracteres."
else
    echo "La contraseña no tiene 32 caracteres, SALIENDO."
    exit
fi


#Inicio
sudo apt-get update -y
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io 
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
#Creacion docker compose
cat <<EOF > docker-compose.yml
version: '3.7'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.15.2
    container_name: elasticsearch
    environment:
      - node.name=elasticsearch
      - cluster.name=es-docker-cluster
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
      - "discovery.type=single-node"
      - "xpack.security.enabled=false"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - esdata:/usr/share/elasticsearch/data
    ports:
      - 9200:9200

  kibana:
    image: docker.elastic.co/kibana/kibana:7.15.2
    container_name: kibana
    ports:
      - 5601:5601
    environment:
      ELASTICSEARCH_URL: <http://elasticsearch:9200/>  # URL de Elasticsearch
    volumes:
      - ./kibana.yml:/usr/share/kibana/config/kibana.yml
    depends_on:
      - elasticsearch

  filebeat:
    image: docker.elastic.co/beats/filebeat:7.15.2
    container_name: filebeat
    user: root
    volumes:
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /var/log:/var/log:ro
    depends_on:
      - elasticsearch

  logstash:
    image: docker.elastic.co/logstash/logstash:7.15.2
    container_name: logstash
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro
    ports:
      - 5044:5044
    depends_on:
      - elasticsearch

  suricata:
    image: jasonish/suricata:latest
    user: root
    privileged: true
    volumes:
      - /var/log/suricata:/var/log/suricata
      - ./suricata.yaml:/etc/suricata/suricata.yaml:ro
      - /var/lib/suricata/rules:/var/lib/suricata/rules
      - /etc/suricata/classification.config:/etc/suricata/classification.config
    network_mode: "host"
    command: -c /etc/suricata/suricata.yaml -i $tarjetaRed

volumes:
  esdata:
    driver: local
networks:
  default:
    external:
      name: encriptadisimo
EOF
cat <<EOF > filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/*.log
    - /var/log/syslog
    - /var/log/nginx/*.log
    - /var/log/apache2/*.log
    - /var/log/mysql/error.log
    - /var/log/postgresql/*.log
    - /var/log/suricata/eve.json
    - /var/log/packetbeat/*

filebeat.modules:
- module: system
  syslog:
    enabled: false
  auth:
    enabled: true
    var.paths: ["/var/log/auth.log"]

output.logstash:
  hosts: ["logstash:5044"]

setup.kibana:
  host: "kibana:5601"

fields:
  event.dataset: keyword
EOF
cat <<EOF > logstash.conf
input {
  beats {
    port => 5044
  }
}

filter {
  if [fileset][module] == "system" {
    if [fileset][name] == "auth" {
      grok {
        match => {
          "message" => [
            "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][ssh][event]} %{DATA:[system][auth][ssh][method]} %{DATA:[system][auth][ssh][username]} %{DATA:[system][auth][ssh][ip]}(?: %{GREEDYDATA:[system][auth][ssh][data]})?",
            "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sudo(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][user]} %{DATA:[system][auth][sudo][tty]}=%{DATA:[system][auth][sudo][user]}(?:\(%{DATA:[system][auth][sudo][runas]}\))?: %{GREEDYDATA:[system][auth][sudo][command]}"
          ]
        }
        pattern_definitions => {
          "GREEDYDATA" => ".*"
        }
        remove_field => "message"
      }
      mutate {
        rename => { "@timestamp" => "read_timestamp" }
      }
      date {
        match => [ "[system][auth][timestamp]", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
      }
      geoip {
        source => "[system][auth][ssh][ip]"
        target => "[system][auth][ssh][geoip]"
      }
      if [system][auth][sudo][command] {
        grok {
          match => { "[system][auth][sudo][command]" => "^ %{USER:[system][auth][sudo][run_as_user]} : TTY=%{DATA:[system][auth][sudo][tty]} ; PWD=%{DATA:[system][auth][sudo][pwd]} ; USER=%{USER:[system][auth][sudo][user]} ; COMMAND=%{GREEDYDATA:[system][auth][sudo][command]}" }
        }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    manage_template => false
    index => "filebeat"
  }
}
EOF
cat <<EOF > suricata.yaml
%YAML 1.1
---
# Configuración de Suricata
default-log-dir: /var/log/suricata/

# Definición de las reglas
rule-files:
  - /var/lib/suricata/rules/*.rules

# Configuración de los registros
outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      append: yes
  - syslog:
      enabled: yes
# Configuración de la detección de anomalías
anomaly:
  detection-ports:
    - 21  # FTP
    - 22  # SSH
    - 23  # Telnet
    - 25  # SMTP
    - 80  # HTTP

# Configuración de los protocolos de capa de aplicación
# Configuración de los protocolos de capa de aplicación
app-layer:
  protocols:
    dcerpc:
      enabled: yes
    smb:
      enabled: yes
    ftp:
      enabled: yes
    ssh:
      enabled: yes
    smtp:
      enabled: yes
    dns:
      enabled: yes
    modbus:
      enabled: no
    http:
      enabled: yes
    tls:
      enabled: yes
    enip:
      enabled: yes
    dnp3:
      enabled: yes
    nfs:
      enabled: yes
    ntp:
      enabled: yes
    tftp:
      enabled: yes
    ikev2:
      enabled: no
    krb5:
      enabled: yes
    dhcp:
      enabled: yes
    snmp:
      enabled: yes
    sip:
      enabled: yes
    rfb:
      enabled: yes
    mqtt:
      enabled: yes
    rdp:
      enabled: yes
    http2:
      enabled: yes
    imap:
      enabled: yes

# Configuración de las interfaces
af-packet:
  - interface: $tarjetaRed
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

# Configuración de la preprocesamiento
prelude:
  enabled: yes
  log-dir: /var/log/suricata/

# Configuración de la extracción de archivos
file-extraction:
  enabled: yes
  # Directorio donde se almacenan los archivos extraídos
  directory: /var/log/suricata/files
  # Establecer en 'yes' para habilitar el cálculo automático del hash MD5 del archivo
  # md5: yes

# Configuración de los registros HTTP
http-log:
  enabled: yes
  filetype: regular
  filename: http.log
  append: yes
  extended: yes

# Configuración de los registros TLS
tls-log:
  enabled: yes
  filetype: regular
  filename: tls.log
  append: yes
  extended: yes
EOF
cat <<EOF > kibana.yml
elasticsearch.hosts: ["http://elasticsearch:9200/"]

xpack.encryptedSavedObjects.encryptionKey: "andreqwerqwerqwerqwerqwerqwerqwerqwerqwer"

server.name: kibana
server.host: "0"
EOF
#Permisos
sudo chown root:root filebeat.yml
sudo chmod a+r filebeat.yml
sudo chmod go-w filebeat.yml
#Git clone
git clone https://github.com/OISF/suricata.git
# Rules Suricata
sudo mkdir /var/lib/suricata
sudo mkdir /var/lib/suricata/rules
sudo mkdir /etc/suricata
sudo mv suricata/etc/reference.config /etc/suricata/
sudo mv suricata/etc/classification.config /etc/suricata/
sudo chmod 777 -R /etc/suricata/
sudo mv suricata/rules/* /var/lib/suricata/rules/
sudo chmod 777 -R /var/lib/suricata/
# Red Encriptada
sudo docker swarm init
sudo docker network create --opt encrypted --attachable --driver overlay encriptadisimo
sudo docker-compose up -d
