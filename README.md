# elk

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



