# Como instalar a stack ELK (Elasticsearch, Logstash e Kibana)

### Instalação:
```
Logstash
Elasticsearch
Kibana
Filebeat
```

### Pre-requisitos
```
OS Ubuntu 16.04
RAM 4GB
CPU 2
```
## Instalação do JAVA
```
$ sudo add-apt-repository -y ppa:webupd8team/java
$ sudo apt-get update
$ sudo apt-get -y install oracle-java8-installer
```
## Instalação do ElasticSearch
```
$ wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -

$ echo "deb http://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list

$ sudo apt-get update

$ sudo apt-get -y install elasticsearch

```
### Configuração do ElasticSearch
- Caso queira restringir acesso externo a sua instancia do Elasticsearch(porta 9200), para que pessoas de fora não acessem seus dados ou desliguem seu cluster através api HTTP, localizar no arquivo: 

```
$ sudo vi /etc/elasticsearch/elasticsearch.yml
```
descomente então a linha ```network.host``` deixando assim:

```
network.host: localhost
```

e depois reinicialize
```
$ sudo service elasticsearch restart
```

configurar o startup do Elasticsearch junto com o "boot" do sistema:
```
$ sudo update-rc.d elasticsearch defaults 95 10
```

## Instalação do Kibana

```
$ echo "deb http://packages.elastic.co/kibana/4.5/debian stable main" | sudo tee -a /etc/apt/sources.list.d/kibana-4.5.x.list

$ sudo apt-get update 

$ sudo apt-get -y install kibana

```
### Configuração do Kibana
- No kibana vamos alterar o arquivo que especifica o host: 

```
$ sudo vi /opt/kibana/config/kibana.yml
```
descomente então a linha ```server.host``` deixando assim:

```
server.host: localhost
```
configurar o startup do Kibana junto com o "boot" do sistema e em seguinda iniciar o serviço:
```
$ sudo update-rc.d kibana defaults 96 9
$ sudo service kibana start
```

## Instalar o NGINX

anteriormente configuramos o Kibana para escutar apenas no "localhost" vamos instalar o Nginx para que tenhamos acesso externo através do proxy reverso

```
sudo apt-get install nginx apache2-utils -yq
```
utilize o recurso do htpasswd para criar um usuário admin, com nome de "kibanaadmin"(pode escolher outro nome se quiser), para ter acesso a interface do Kibana.

```
$ sudo htpasswd -c /etc/nginx/htpasswd.users kibanaadmin
```
Digite a senha de sua preferencia no prompt do terminal

neste passo vamos realizar as configurações "server" iremos editar um arquivo chamado  "default"
```
$ sudo vi /etc/nginx/sites-available/default
```

delete qualquer informação que tenha no arquivo e insira o seguinte conteudo:
```
server {
    listen 80;

    server_name example.com;

    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/htpasswd.users;

    location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;        
    }
}
```
Basicamente as configurações que inserimos, direciona o trafego para ```http://localhost:5601``` dos acesso permitidos pelo ```htpasswd.users``` que foi criado para a autenticação.

por fim reinicializar o NGINX

```
$ sudo service nginx restart
```
O Kibana agora pode ser acessado pelo seu FQDN ou pelo endereço IP público do seu servidor ELK, ou seja, http://elk-server-public-ip/.
Se você for lá em um navegador, depois de inserir as credenciais do "kibanaadmin", deverá ver uma página de boas-vindas do Kibana que solicitará que você configure um padrão de índice. Vamos voltar a isso mais tarde, depois de instalarmos todos os outros componentes.


# Instalar Logstash

```
$ echo 'deb http://packages.elastic.co/logstash/2.2/debian stable main' | sudo tee /etc/apt/sources.list.d/logstash-2.2.x.list

$ sudo apt-get update

$ sudo apt-get install logstash
```
O logstash esta instalado mas não configurado

# Gerar certificados SSL

Como vamos usar o Filebeat para enviar logs de nossos servidores de clientes para o nosso servidor ELK, precisamos criar um certificado SSL e um par de chaves. O certificado é usado pelo Filebeat para verificar a identidade do ELK Server. Crie os diretórios que armazenarão o certificado e a chave privada com os seguintes comandos:
```
$ sudo mkdir -p /etc/pki/tls/certs
$ sudo mkdir /etc/pki/tls/private
```

Agora você tem duas opções para gerar seus certificados SSL. Se você tiver uma configuração de DNS que permitirá que os servidores clientes resolvam o endereço IP do servidor ELK, use a opção 2. Caso contrário, a opção 1 permitirá que você use endereços IP.

### Opção 1: endereço IP
Se você não tiver uma configuração de DNS - isso permitiria que seus servidores, dos quais você coletará logs, resolvessem o endereço IP do seu servidor ELK - você teria que adicionar o endereço IP privado do seu servidor ELK ao ```subjectAltName``` (SAN) campo do certificado SSL que estamos prestes a gerar. Para fazer isso, abra o arquivo de configuração do OpenSSL:

```
$ sudo vi /etc/ssl/openssl.cnf
```

Localize a sessão ```[ v3_ca ]``` e adicione a linha abaixo:
```
subjectAltName = IP: your_ELK_server_private_IP
```
salve e sai da edição de arquivo, segue para o diretório:
```
$ cd /etc/pki/tls/
```
Neste passo vamos gerar o par de chaves com o comando:
```
$ sudo openssl req -config /etc/ssl/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt
```
O arquivo logstash-forwarder.crt será copiado para todos os servidores que enviarão logs para o Logstash, mas faremos isso um pouco mais tarde. Vamos completar nossa configuração do Logstash. Se você foi com esta opção, pule a opção 2 e vá em Configurar Logstash.

## Opcção 2: FQDN (DNS)

Se você tiver uma configuração de DNS com sua rede privada, deverá criar um registro que contenha o endereço IP privado do servidor ELK - esse nome de domínio será usado no próximo comando para gerar o certificado SSL. Como alternativa, você pode usar um registro que aponte para o endereço IP público do servidor. Apenas certifique-se de que seus servidores (aqueles dos quais você coletará logs) poderão resolver o nome do domínio para o seu servidor ELK.

Agora gere o certificado SSL e a chave privada, nos locais apropriados (/etc/pki/tls/...), com o seguinte comando (substitua no FQDN do Servidor ELK):

```
cd /etc/pki/tls; sudo openssl req -subj '/CN=ELK_server_fqdn/' -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt
```

O arquivo logstash-forwarder.crt será copiado para todos os servidores que enviarão logs para o Logstash, mas faremos isso um pouco mais tarde. Vamos completar nossa configuração do Logstash.

# Configuração do Logstash

- Os arquivos de configuração do Logstash estão no formato JSON e estão em /etc/logstash/conf.d. A configuração consiste em três seções: entradas, filtros e saídas.

Vamos criar um arquivo de configuração chamado 02-beats-input.conf e configurar nossa entrada "filebeat":

### Entrada
```
$ sudo vi /etc/logstash/conf.d/02-beats-input.conf
```
- Inserir as seguintes configurações no arquivo:
```
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/pki/tls/certs/logstash-forwarder.crt"
    ssl_key => "/etc/pki/tls/private/logstash-forwarder.key"
  }
}
```
Salve e saia. 

Isso especifica uma entrada de beats que irá escutar na porta tcp 5044, e usará o certificado SSL e a chave privada que criamos anteriormente.

Agora vamos criar um arquivo de configuração chamado 10-syslog-filter.conf, onde vamos adicionar um filtro para mensagens syslog:


### Filtro
```
$ sudo vi /etc/logstash/conf.d/10-syslog-filter.conf
```

```
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}
```
Salve e saia. 

Esse filtro procura logs que são rotulados como tipo "syslog" (por Filebeat), e tentará usar grok para analisar logs de syslog recebidos para torná-los estruturados e com capacidade de consulta.

Por fim, criaremos um arquivo de configuração chamado 30-elasticsearch-output.conf:

### Saída
```
$ sudo vi /etc/logstash/conf.d/30-elasticsearch-output.conf
```
```
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    sniffing => true
    manage_template => false
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
    document_type => "%{[@metadata][type]}"
  }
}
```
Salvar e sair. 

Esta saída basicamente configura o Logstash para armazenar os dados de beats no Elasticsearch que está sendo executado no localhost: 9200, em um índice com o nome usando (filebeat, no nosso caso).

Se você quiser adicionar filtros para outros aplicativos que usam a entrada Filebeat, certifique-se de nomear os arquivos para que eles classifiquem entre a entrada e a configuração de saída (ou seja, entre 02 e 30).

Teste sua configuração do Logstash com este comando:

Testar as configurações do logstash com o comando:

```
$ sudo service logstash configtest
```
Ele deve exibir a ```Configuration OK```, se não houver erros de sintaxe. Caso contrário, tente ler a saída de erro para ver o que há de errado com sua configuração do Logstash

```
$ sudo service logstash restart
```
```
$ sudo update-rc.d logstash defaults 96 9
```
# Dashboard para o Kibana

Elastic fornece vários painéis de amostra Kibana e padrões de índice Beats que podem ajudar você a começar a usar o Kibana. Embora não usemos os painéis neste tutorial, vamos carregá-los assim mesmo para que possamos usar o padrão de índice do Filebeat que ele inclui.

Primeiro, faça o download do archive de painéis de amostra em seu diretório inicial:

cd ~
curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.1.0.zip

sudo apt-get -y install unzip

unzip beats-dashboards-*.zip

cd beats-dashboards-*
./load.sh

# Carregar template Filebeat de indice no Elasticsearch

cd ~
curl -O https://gist.githubusercontent.com/thisismitch/3429023e8438cc25b86c/raw/d8c479e2a1adcea8b1fe86570e42abab0f10f364/filebeat-index-template.json

curl -XPUT 'http://localhost:9200/_template/filebeat?pretty' -d@filebeat-index-template.json

# Set Up Filebeat (Add Client Servers)

### Copy SSL Certificate
scp /etc/pki/tls/certs/logstash-forwarder.crt user@client_server_private_address:/tmp

### Instalar o pacote Filebeat

echo "deb https://packages.elastic.co/beats/apt stable main" |  sudo tee -a /etc/apt/sources.list.d/beats.list

wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -

sudo apt-get update
sudo apt-get install filebeat

### Configure Filebeat

sudo vi /etc/filebeat/filebeat.yml
