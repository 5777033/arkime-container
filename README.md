# Arkime (Moloch) Container Image and supervisor

> NOTE: Now that Arkime (v5.5+) has an official Docker release, This project is no longer maintained. Please use the official Docker image instead.
Arkime is a large scale, open source, indexed packet capture and search tool ([website](https://arkime.com))
```bash
mkdir -p data/{etc,raw}
chmod -R 777 data
```
```sh
cat <<EOF> data/etc/config.ini
[default]
elasticsearch=http://localhost:9200
rotateIndex=daily
passwordSecret=Passw0rd
httpRealm=Arkime
webBasePath=/
interface=any
bpf=not port 9200
yara=/dev/null
pcapDir=/opt/arkime/raw
pcapDirAlgorithm=round-robin
maxFileSizeG=12
maxFileTimeM=0
tcpTimeout=600
tcpSaveTimeout=720
tcpClosingTimeout=5
udpTimeout=30
icmpTimeout=10
maxStreams=1000000
maxPackets=10000
freeSpaceG=5%
viewPort=8005
viewHost=0.0.0.0
viewUrl=https://HOSTNAME:8005
geoLite2Country=/opt/arkime/etc/GeoLite2-Country.mmdb
geoLite2ASN=/opt/arkime/etc/GeoLite2-ASN.mmdb
rirFile=/opt/arkime/etc/ipv4-address-space.csv
ouiFile=/opt/arkime/etc/oui.txt
dropUser=nobody
dropGroup=daemon
localPcapIndex=false
userNameHeader=arkime_user
parseSMTP=true
parseSMB=true
parseQSValue=false
supportSha256=false
maxReqBody=64
reqBodyOnlyUtf8=true
smtpIpHeaders=X-Originating-IP:;X-Barracuda-Apparent-Source-IP:
parsersDir=/opt/arkime/parsers
pluginsDir=/opt/arkime/plugins
netflowSNMPInput=1
netflowSNMPOutput=2
netflowVersion=1
offlineDispatchAfter=2500
spiDataMaxIndices=4
uploadCommand=/opt/arkime/bin/capture --copy -n {NODE} -r {TMPFILE} -c {CONFIG} {TAGS}
titleTemplate=_cluster_ - _page_ _-view_ _-expression_
packetThreads=2
pcapReadMethod=libpcap
pcapWriteMethod=simple
pcapWriteSize=262143
simpleCompression=none
dbBulkSize=300000
compressES=false
maxESConns=30
maxESRequests=500
packetsPerPoll=50000
antiSynDrop=true
logEveryXPackets=100000
logUnknownProtocols=false
logESRequests=true
logFileCreation=true
userAuthIps=10.0.0.0/8,::1
EOF
```

## Run build with a configuration images file

```sh
docker build -t arkime-container:v5.4 .
```

*IMPORTANT NOTE*: current implementation does not support anything otuside the `[default]` section for the `.ini` file and will throw an error if there's anything else other than the `[default]` section is present. 

## Run with command line arguments

`arkime-supervisor` also supports command line arguments as well as Environment variables to set most common commands into an Arkime-compatible `.ini` file on container's startup, so the user won't have to deal with managing an extra `ini` file dynamically.

```sh
docker run -d \
  --net host \
  --name arkime \
  --volume ./data/raw:/opt/arkime/raw \
  --volume ./data/etc/config.ini:/opt/arkime/etc/config.ini:ro \
  arkime-container:v5.4 \
  --passwordSecret=admin12345 \
  --elasticsearch=http://localhost:9200 \
  --interface=any \
  --viewPort=8005 \
  --viewHost=0.0.0.0 \
  --createAdminUser=true
```


by default, `arkime-supervisor` will download 4 files on startup: `ipv4-address-space.csv`, `manuf`, `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb`. `ipv4-address-space.csv`, `manuf` are considered static and not subject to many changes, so `arkime-supervisor` will not try to keep them up to date automatically, but `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb` can be re-fetched by setting geoLiteRefreshInterval to any positive time duration. Default is 1 week (168 hours). 

##initial DB  && Add User
```sh
/opt/arkime/db/db.pl http://localhost:9200 init
/opt/arkime/bin/arkime_add_user.sh jensen "Jensen User" Jensen@2030 --admin

#Docker Compose Deploy
mkdir -p data/{etc,raw}
touch data/etc/config.ini
chmod -R 777 data

```sh
version: '3.8'
services:
  elasticsearch:
    image: opensearchproject/opensearch:2.18.0
    volumes:
      - esdata:/usr/share/opensearch/data
    environment:
      - bootstrap.memory_lock=true
      - discovery.type=single-node
      - plugins.security.disabled=true
      - thread_pool.search.queue_size=5000
      - OPENSEARCH_INITIAL_ADMIN_PASSWORD=${OPENSEARCH_INITIAL_ADMIN_PASSWORD}
      - "OPENSEARCH_JAVA_OPTS=-Xms${ELASTIC_MEMORY_SIZE} -Xmx${ELASTIC_MEMORY_SIZE}"
    restart: always
    ports:
      - 9200:9200
        #- 127.0.0.1:9200:9200
    healthcheck:
      test: curl --write-out 'HTTP %{http_code}' --fail --silent --output /dev/null http://localhost:9200/ || exit 1
      retries: 5
      timeout: 10s
      start_interval: 30s
      start_period: 5m
      interval: 10s
  arkime:
    image: arkime-container:v5.4
    container_name: arkime
    network_mode: "host"
    volumes:
      - ./data/raw:/opt/arkime/raw
      - ./data/etc/config.ini:/opt/arkime/etc/config.ini:ro
    command:
      - --passwordSecret=admin12345
      - --elasticsearch=http://localhost:9200
      - --interface=any
      - --viewPort=8005
      - --viewHost=0.0.0.0
      - --createAdminUser=true
    depends_on:
      - elasticsearch
volumes:
  esdata:
```




`arkime-supervisor` will check on viewer and capture process every 5 seconds to see if they're still running and if they've exited, it tries to restart them. 

initial DB  && Add User
```sh
/opt/arkime/db/db.pl http://localhost:9200 init
/opt/arkime/bin/arkime_add_user.sh jensen "Jensen User" Jensen@2030 --admin
```
**1️⃣ 检查 Arkime 索引是否初始化成功**
---------------------------

Arkime 初始化成功后，会在 OpenSearch 中创建一系列索引（例如 `arkime_sessions3-*`、`arkime_stats-*`、`arkime_users_v1` 等）。

在宿主机执行：

curl -u admin:CHANGEMee123! http://127.0.0.1:9200/_cat/indices?v`

如果输出中包含 `arkime_*` 开头的索引，说明初始化成功。
1️⃣ 确认已有用户
----------

尝试查询 `arkime_users_v30` 索引：

`curl -u admin:CHANGEMee123! "http://127.0.0.1:9200/arkime_users_v30/_search?pretty"`

如果返回内容中含有：

json


`{   "_source" : {     "userId" : "admin",     "userName" : "Administrator",     "roles" : ["admin"]   } }`

说明账户已创建




#full list of options:


[//]: <> (start of command line options)
```
  ARKIME

default:
      --elasticsearch=               Comma seperated list of elasticsearch
                                     host:port combinations.  If not using a
                                     ; elasticsearch VIP, a different
                                     elasticsearch node in the cluster can be
                                     specified
                                     ; for each Arkime node to help spread load
                                     on high volume clusters (default:
                                     http://127.0.0.1:9200)
                                     [$ARKIME_ELASTICSEARCH]
      --rotateIndex=                 How often to create a new elasticsearch
                                     index. hourly,hourly6,daily,weekly,monthly
                                     ; Changing the value will cause previous
                                     sessions to be unreachable (default:
                                     daily) [$ARKIME_ROTATEINDEX]
      --certFile=                    Cert file to use, comment out to use http
                                     instead [$ARKIME_CERTFILE]
      --caTrustFile=                 File with trusted roots/certs. WARNING!
                                     this replaces default roots
                                     ; Useful with self signed certs and can be
                                     set per node. [$ARKIME_CATRUSTFILE]
      --keyFile=                     Private key file to use, comment out to
                                     use http instead [$ARKIME_KEYFILE]
      --passwordSecret=              Password Hash and S2S secret - Must be in
                                     default section. Since elasticsearch
                                     ; is wide open by default, we encrypt the
                                     stored password hashes with this
                                     ; so a malicous person can't insert a
                                     working new account.  It is also used
                                     ; for secure S2S communication. Comment
                                     out for no user authentication.
                                     ; Changing the value will make all
                                     previously stored passwords no longer work.
                                     ; Make this RANDOM, you never need to type
                                     in (default: password)
                                     [$ARKIME_PASSWORDSECRET]
      --serverSecret=                Use a different password for S2S
                                     communication then passwordSecret.
                                     ; Must be in default section.  Make this
                                     RANDOM, you never need to type in
                                     [$ARKIME_SERVERSECRET]
      --httpRealm=                   HTTP Digest Realm - Must be in default
                                     section.  Changing the value
                                     ; will make all previously stored
                                     passwords no longer work (default: Arkime)
                                     [$ARKIME_HTTPREALM]
      --webBasePath=                 The base path for Arkime web access.  Must
                                     end with a / or bad things will happen
                                     (default: /) [$ARKIME_ WEBBASEPATH]
      --interface=                   Semicolon ';' seperated list of interfaces
                                     to listen on for traffic (default: lo)
                                     [$ARKIME_INTERFACE]
      --bpf=                         The bpf filter of traffic to ignore
                                     (default: not port 9200) [$ARKIME_BPF]
      --yara=                        The yara file name (default: /dev/null)
                                     [$ARKIME_YARA]
      --wiseHost=                    Host to connect to for wiseService
                                     [$ARKIME_WISEHOST]
      --accessLogFile=               Log viewer access requests to a different
                                     log file [$ARKIME_ACCESSLOGFILE]
      --pcapDir=                     The directory to save raw pcap files to
                                     (default: /opt/arkime/raw)
                                     [$ARKIME_PCAPDIR]
      --pcapDirAlgorithm=            When pcapDir is a list of directories,
                                     this determines how Arkime chooses which
                                     directory to use for each new pcap file.
                                     Possible values: round-robin (rotate
                                     sequentially), max-free-percent (choose
                                     the directory on the filesystem with the
                                     highest percentage of available space),
                                     max-free-bytes (choose the directory on
                                     the filesystem with the highest number of
                                     available bytes). (default: round-robin)
                                     [$ARKIME_PCAPDIRALGORITHM]
      --pcapDirTemplate=             When set, this strftime template is
                                     appended to pcapDir and allows multiple
                                     directories to be created based on time.
                                     [$ARKIME_PCAPDIRTEMPLATE]
      --maxFileSizeG=                The max raw pcap file size in gigabytes,
                                     with a max value of 36G.
                                     ; The disk should have room for at least
                                     10*maxFileSizeG (default: 12)
                                     [$ARKIME_MAXFILESIZEG]
      --maxFileTimeM=                The max time in minutes between rotating
                                     pcap files.  Default is 0, which means
                                     ; only rotate based on current file size
                                     and the maxFileSizeG variable (default: 0)
                                     [$ARKIME_MAXFILETIMEM]
      --tcpTimeout=                  TCP timeout value.  Arkime writes a
                                     session record after this many seconds
                                     ; of inactivity. (default: 600)
                                     [$ARKIME_TCPTIMEOUT]
      --tcpSaveTimeout=              Arkime writes a session record after this
                                     many seconds, no matter if
                                     ; active or inactive (default: 720)
                                     [$ARKIME_TCPSAVETIMEOUT]
      --tcpClosingTimeout=           Delay before saving tcp sessions after
                                     close (default: 5)
                                     [$ARKIME_TCPCLOSINGTIMEOUT]
      --udpTimeout=                  UDP timeout value.  Arkime assumes the UDP
                                     session is ended after this
                                     ; many seconds of inactivity. (default:
                                     30) [$ARKIME_UDPTIMEOUT]
      --icmpTimeout=                 ICMP timeout value.  Arkime assumes the
                                     ICMP session is ended after this
                                     ; many seconds of inactivity. (default:
                                     10) [$ARKIME_ICMPTIMEOUT]
      --maxStreams=                  An aproximiate maximum number of active
                                     sessions Arkime/libnids will try
                                     ; and monitor (default: 1000000)
                                     [$ARKIME_MAXSTREAMS]
      --maxPackets=                  Arkime writes a session record after this
                                     many packets (default: 10000)
                                     [$ARKIME_MAXPACKETS]
      --freeSpaceG=                  Delete pcap files when free space is lower
                                     then this in gigabytes OR it can be
                                     ; expressed as a percentage (ex: 5%).
                                     This does NOT delete the session records in
                                     ; the database. It is recommended this
                                     value is between 5% and 10% of the disk.
                                     ; Database deletes are done by the db.pl
                                     expire script (default: 5%)
                                     [$ARKIME_FREESPACEG]
      --viewPort=                    The port to listen on, by default 8005
                                     (default: 8005) [$ARKIME_VIEWPORT]
      --viewHost=                    The host/ip to listen on, by default
                                     0.0.0.0 which is ALL (default: localhost)
                                     [$ARKIME_VIEWHOST]
      --viewUrl=                     By default the viewer process is
                                     https://hostname:<viewPort> for each node.
                                     (default: https://HOSTNAME:8005)
                                     [$ARKIME_VIEWURL]
      --geoLite2Country=             Path of the maxmind geoip country file.
                                     Download free version from:
                                     ;
                                     https://updates.maxmind.com/app/update_sec-

                                     ure?edition_id=GeoLite2-Country (default:
                                     /opt/arkime/etc/GeoLite2-Country.mmdb)
                                     [$ARKIME_GEOLITE2COUNTRY]
      --geoLite2ASN=                 Path of the maxmind geoip ASN file.
                                     Download free version from:
                                     ;
                                     https://updates.maxmind.com/app/update_sec-

                                     ure?edition_id=GeoLite2-ASN (default:
                                     /opt/arkime/etc/GeoLite2-ASN.mmdb)
                                     [$ARKIME_GEOLITE2ASN]
      --rirFile=                     Path of the rir assignments file
                                     ;
                                     https://www.iana.org/assignments/ipv4-addr-

                                     ess-space/ipv4-address-space.csv (default:
                                     /opt/arkime/etc/ipv4-address-space.csv)
                                     [$ARKIME_RIRFILE]
      --ouiFile=                     Path of the OUI file from whareshark
                                     ;
                                     https://raw.githubusercontent.com/wireshar-

                                     k/wireshark/master/manuf (default:
                                     /opt/arkime/etc/oui.txt) [$ARKIME_OUIFILE]
      --dropUser=                    User to drop privileges to. The pcapDir
                                     must be writable by this user or group
                                     below (default: nobody) [$ARKIME_DROPUSER]
      --dropGroup=                   Group to drop privileges to. The pcapDir
                                     must be writable by this group or user
                                     above (default: daemon) [$ARKIME_DROPGROUP]
      --localPcapIndex=[true|false]  enable pcap index on capture node instead
                                     of ES (default: false)
                                     [$ARKIME_LOCALPCAPINDEX]
      --dontSaveTags=                Semicolon ';' seperated list of tags which
                                     once capture sets for a session causes the
                                     ; remaining pcap from being saved for the
                                     session.  It is likely that the initial
                                     packets
                                     ; WILL be saved for the session since tags
                                     usually aren't set until after several
                                     packets
                                     ; Each tag can choiceally be followed by a
                                     :<num> which specifies how many total
                                     packets to save [$ARKIME_DONTSAVETAGS]
      --userNameHeader=              Header to use for determining the username
                                     to check in the database for instead of
                                     ; using http digest.  Use this if apache
                                     or something else is doing the auth.
                                     ; Set viewHost to localhost or use iptables
                                     ; Might need something like this in the
                                     httpd.conf
                                     ; RewriteRule .* -
                                     [E=ENV_RU:%{REMOTE_USER}]
                                     ; RequestHeader set ARKIME_USER %{ENV_RU}e
                                     (default: arkime_user)
                                     [$ARKIME_USERNAMEHEADER]
      --parseSMTP=[true|false]       Should we parse extra smtp traffic info
                                     (default: true) [$ARKIME_PARSESMTP]
      --parseSMB=[true|false]        Should we parse extra smb traffic info
                                     (default: true) [$ARKIME_PARSESMB]
      --parseQSValue=[true|false]    Should we parse HTTP QS Values (default:
                                     false) [$ARKIME_PARSEQSVALUE]
      --supportSha256=[true|false]   Should we calculate sha256 for bodies
                                     (default: false) [$ARKIME_SUPPORTSHA256]
      --maxReqBody=                  Only index HTTP request bodies less than
                                     this number of bytes */ (default: 64)
                                     [$ARKIME_MAXREQBODY]
      --reqBodyOnlyUtf8=[true|false] Only store request bodies that Utf-8?
                                     (default: true) [$ARKIME_REQBODYONLYUTF8]
      --smtpIpHeaders=               Semicolon ';' seperated list of SMTP
                                     Headers that have ips, need to have the
                                     terminating colon ':' (default:
                                     X-Originating-IP:;X-Barracuda-Apparent-Sou-

                                     rce-IP:) [$ARKIME_SMTPIPHEADERS]
      --parsersDir=                  Semicolon ';' seperated list of
                                     directories to load parsers from (default:
                                     /opt/arkime/parsers) [$ARKIME_PARSERSDIR]
      --pluginsDir=                  Semicolon ';' seperated list of
                                     directories to load plugins from (default:
                                     /opt/arkime/plugins) [$ARKIME_PLUGINSDIR]
      --plugins=                     Semicolon ';' seperated list of plugins to
                                     load and the order to load in
                                     [$ARKIME_PLUGINS]
      --rootPlugins=                 Plugins to load as root, usually just
                                     readers [$ARKIME_ROOTPLUGINS]
      --viewerPlugins=               Semicolon ';' seperated list of viewer
                                     plugins to load and the order to load in
                                     [$ARKIME_VIEWERPLUGINS]
      --netflowSNMPInput=            NetFlowPlugin
                                     ; Input device id, 0 by default (default:
                                     1) [$ARKIME_NETFLOWSNMPINPUT]
      --netflowSNMPOutput=           Outout device id, 0 by default (default:
                                     2) [$ARKIME_NETFLOWSNMPOUTPUT]
      --netflowVersion=              Netflow version 1,5,7 supported, 7 by
                                     default (default: 1)
                                     [$ARKIME_NETFLOWVERSION]
      --netflowDestinations=         Semicolon ';' seperated list of netflow
                                     destinations [$ARKIME_NETFLOWDESTINATIONS]
      --offlineDispatchAfter=        How many packets to read from offline pcap
                                     files at once. (default: 2500)
                                     [$ARKIME_OFFLINEDISPATCHAFTER]
      --spiDataMaxIndices=           Specify the max number of indices we
                                     calculate spidata for.
                                     ; ES will blow up if we allow the spiData
                                     to search too many indices. (default: 4)
                                     [$ARKIME_SPIDATAMAXINDICES]
      --uploadCommand=               Uncomment the following to allow direct
                                     uploads.  This is experimental (default:
                                     /opt/arkime/bin/capture --copy -n {NODE}
                                     -r {TMPFILE} -c {CONFIG} {TAGS})
                                     [$ARKIME_UPLOADCOMMAND]
      --titleTemplate=               Title Template
                                     ;  _cluster_=ES cluster name
                                     ;  _userId_=logged in User Id
                                     ;  _userName_=logged in User Name
                                     ;  _page_=internal page name
                                     ;  _expression_=current search expression
                                     if set, otherwise blank
                                     ;  _-expression_=" - " + current search
                                     expression if set, otherwise blank, prior
                                     spaces removed
                                     ;  _view_=current view if set, otherwise
                                     blank
                                     ;  _-view_=" - " + current view if set,
                                     otherwise blank, prior spaces removed
                                     (default: _cluster_ - _page_ _-view_
                                     _-expression_) [$ARKIME_TITLETEMPLATE]
      --packetThreads=               Number of threads processing packets
                                     (default: 2) [$ARKIME_PACKETTHREADS]
      --includes=                    ADVANCED - Semicolon ';' seperated list of
                                     files to load for config.  Files are loaded
                                     ; in order and can replace values set in
                                     this file or previous files.
                                     [$ARKIME_INCLUDES]
      --pcapReadMethod=              ADVANCED - Specify how packets are read
                                     from network cards: (default: libpcap)
                                     [$ARKIME_PCAPREADMETHOD]
      --pcapWriteMethod=             ADVANCED - How is pcap written to disk
                                     ;  simple=use O_DIRECT if available,
                                     writes in pcapWriteSize chunks,
                                     ;                    a file per packet
                                     thread.
                                     ;  simple-nodirect=don't use O_DIRECT.
                                     Required for zfs and others (default:
                                     simple) [$ARKIME_PCAPWRITEMETHOD]
      --pcapWriteSize=               ADVANCED - Buffer size when writing pcap
                                     files.  Should be a multiple of the raid 5
                                     or xfs
                                     ; stripe size.  Defaults to 256k (default:
                                     262143) [$ARKIME_PCAPWRITESIZE]
      --simpleCompression=           The type of seekable compression to use on
                                     pcap files. Zstd (don't use before 4.5.1)
                                     will has better compression for less cpu
                                     than glib. Valid values are: none, gzip,
                                     zstd (>= 4.5.1) (default: none)
                                     [$ARKIME_SIMPLECOMPRESSION]
      --dbBulkSize=                  ADVANCED - Number of bytes to bulk index
                                     at a time (default: 300000)
                                     [$ARKIME_DBBULKSIZE]
      --compressES=[true|false]      ADVANCED - Compress requests to ES,
                                     reduces ES bandwidth by ~80% at the cost
                                     ; of increased CPU. MUST have
                                     "http.compression: true" in
                                     elasticsearch.yml file (default: false)
                                     [$ARKIME_COMPRESSES]
      --maxESConns=                  ADVANCED - Max number of connections to
                                     elastic search (default: 30)
                                     [$ARKIME_MAXESCONNS]
      --maxESRequests=               ADVANCED - Max number of es requests
                                     outstanding in q (default: 500)
                                     [$ARKIME_MAXESREQUESTS]
      --packetsPerPoll=              ADVANCED - Number of packets to ask
                                     libnids/libpcap to read per poll/spin
                                     ; Increasing may hurt stats and ES
                                     performance
                                     ; Decreasing may cause more dropped
                                     packets (default: 50000)
                                     [$ARKIME_PACKETSPERPOLL]
      --antiSynDrop=[true|false]     ADVANCED - Arkime will try to compensate
                                     for SYN packet drops by swapping
                                     ; the source and destination addresses
                                     when a SYN-acK packet was captured first.
                                     ; Probably useful to set it false, when
                                     running Arkime in wild due to SYN floods.
                                     (default: true) [$ARKIME_ANTISYNDROP]
      --logEveryXPackets=            DEBUG - Write to stdout info every X
                                     packets.
                                     ; Set to -1 to never log status (default:
                                     100000) [$ARKIME_LOGEVERYXPACKETS]
      --logUnknownProtocols=         DEBUG - Write to stdout unknown protocols
                                     (default: false)
                                     [$ARKIME_LOGUNKNOWNPROTOCOLS]
      --logESRequests=               DEBUG - Write to stdout elastic search
                                     requests (default: true)
                                     [$ARKIME_LOGESREQUESTS]
      --logFileCreation=             DEBUG - Write to stdout file creation
                                     information (default: true)
                                     [$ARKIME_LOGFILECREATION]
      --userAuthIps=                 IPs allow to be used for authenticated
                                     calls (default: 127.0.0.1,::1)
                                     [$ARKIME_USERAUTHIPS]
      --userAutoCreateTmpl=          When using requiredAuthHeader to
                                     externalize provisioning of users to a
                                     system like LDAP/AD, this configuration
                                     parameter is used to define the JSON
                                     structure used to automatically create a
                                     arkime user in the arkime users database
                                     if one does not exist. The user will only
                                     be created if the requiredAuthHeader
                                     includes the expected value in
                                     requiredAuthHeaderVal, and is not
                                     automatically deleted if the auth headers
                                     are not present. Values can be populated
                                     into the creation JSON to dynamically
                                     populate fields into the user database,
                                     which are passed in as HTTP headers along
                                     with the user and auth headers. The
                                     example value below creates a user with a
                                     userId pulled from the http_auth_http_user
                                     HTTP header with a name pulled from the
                                     http_auth_mail user header. It is expected
                                     that these headers are passed in from an
                                     apache (or similar) instance that fronts
                                     the arkime viewer as described in the
                                     documentation supporting userNameHeader
                                     [$ARKIME_USERAUTOCREATETMPL]
      --authClientId=                The OIDC client id [$ARKIME_AUTHCLIENTID]
      --authClientSecret=            The OIDC Client Secret
                                     [$ARKIME_AUTHCLIENTSECRET]
      --authDiscoveryUrl=            The OIDC discover wellknown URL.
                                     [$ARKIME_AUTHDISCOVERYURL]
      --authRedirectURL=             Comma separated list of redirect URLs.
                                     Maybe should end with /auth/login/callback
                                     [$ARKIME_AUTHREDIRECTURL]
      --authUserIdField=             The field to use in the response from OIDC
                                     that contains the userId
                                     [$ARKIME_AUTHUSERIDFIELD]

general:
  -h, --help                         Print this help to stdout
      --dumpConfig                   generate an Arkime config file based on
                                     current inputs (flags, input config file
                                     and environment variables) and write to
                                     stdout. [$ARKIME_DUMPCONFIG]
      --skipTlsVerifiction           Skip TLS verification for Elasticsearch
                                     and Viewer [$ARKIME_SKIPTLSVERIFICTION]
      --noConf=[true|false]          Do not use any of the provided flags to
                                     generate a Config file, used when config
                                     file is directly mounted inside the
                                     container (default: false) [$ARKIME_NOCONF]
      --configPath=                  path to look for Arkime Config file
                                     (default: /opt/arkime/etc/config.ini)
                                     [$ARKIME_CONFIGPATH]
      --version=[true|false]         print version and exit (default: false)
                                     [$ARKIME_VERSION]
      --autoInit=[true|false]        atuomatically initialize Elastic indices
                                     if sequence_v2 and sequence_v1 were not
                                     present (default: true) [$ARKIME_AUTOINIT]
      --forceInit=[true|false]       force initialization of Arkime Elastic
                                     indices from scratch (default: false)
                                     [$ARKIME_FORCEINIT]
      --createAdminUser=[true|false] create admin user at startup (default:
                                     true) [$ARKIME_CREATEADMINUSER]
      --adminCreds=                  Administrator Credentials (default:
                                     admin:arkime) [$ARKIME_ADMINCREDS]
      --captureHost=                 the --host passed to capture (default:
                                     localhost) [$ARKIME_CAPTUREHOST]
      --esHealthcheckInterval=       Interval to check Elastic avalability
                                     (default: 60s)
                                     [$ARKIME_ESHEALTHCHECKINTERVAL]
      --viewerCheckInterval=         Interval to check Viewer avalability
                                     (default: 60s)
                                     [$ARKIME_VIEWERCHECKINTERVAL]
      --capturerCheckInterval=       Interval to check Capturer avalability
                                     (default: 60s)
                                     [$ARKIME_CAPTURERCHECKINTERVAL]
      --viewerLogLocation=           Viewer log location, empty value pushes
                                     the log to container's stdout
                                     [$ARKIME_VIEWERLOGLOCATION]
      --capturerLogLocation=         Capturer log location, empty value pushes
                                     the log to container's stdout
                                     [$ARKIME_CAPTURERLOGLOCATION]
      --ipv4SpaceURL=                Download IPv4 space on startup and push to
                                     rirFile location defined in ArkimeOptions.
                                     empty means disabled (default:
                                     https://www.iana.org/assignments/ipv4-addr-

                                     ess-space/ipv4-address-space.csv)
                                     [$ARKIME_IPV4SPACEURL]
      --manufURL=                    Download MAC Vendor mapping on startup and
                                     push to ouiFile location defined in
                                     ArkimeOptions. empty means disabled
                                     (default:
                                     https://www.wireshark.org/download/automat-

                                     ed/data/manuf) [$ARKIME_MANUFURL]
      --geoLite2CountryURL=          Download GeoLite2 Country mmdb on startup
                                     and push to geoLite2Country location
                                     defined in ArkimeOptions. empty means
                                     disabled (default:
                                     https://github.com/P3TERX/GeoLite.mmdb/raw-

                                     /download/GeoLite2-Country.mmdb)
                                     [$ARKIME_GEOLITECOUNTRYURL]
      --geoLite2ASNURL=              Download GeoLite2 ASN mmdb on startup and
                                     push to geoLite2ASN location defined in
                                     ArkimeOptions. empty means disabled
                                     (default:
                                     https://github.com/P3TERX/GeoLite.mmdb/raw-

                                     /download/GeoLite2-ASN.mmdb)
                                     [$ARKIME_GEOLITEASNURL]
      --geoLiteRefreshInterval=      Auto re-download interval for
                                     GeoLite2CountryURL and GeoLite2ASNURL
                                     (default: 168h)
                                     [$ARKIME_GEOLITEREFRESHINTERVAL]  
```
[//]: <> (end of command line options)

