#!/bin/bash

#####################################################################
#                                                                   #
# Author:       Martin Boller                                       #
#                                                                   #
# Email:        martin@bollers.dk                                   #
# Last Update:  2022-05-09                                          #
# Version:      2.10                                                #
#                                                                   #
# Changes:      Tested on APU4D4 (2.10)                             #
#               Crowdsec implementation (2.00)                      #
#               Sysfsutils/performance CPU governor (1.30)          #
#               IP forwarding routine (1.20)                        #
#               Added get_information (1.10)                        #
#               Initial version (1.00)                              #
#                                                                   #
#####################################################################

get_information() {
    /usr/bin/logger 'get_information()' -t 'Debian-FW-20220213';
    echo -e "\e[32mget_information()\e[0m";
    read -p "FQDN of outgoing mailserver: " MAIL_SERVER;
    read -p "Port for outgoing mailserver: " MAIL_SERVER_PORT;
    read -p "Outgoing Sender Email Address: " MAIL_ADDRESS;
    read -sp "Password for sender email address: " MAIL_PASSWORD;
    read -p "Your Internal Domain: " INTERNAL_DOMAIN;
    read -p "Firewall host name: " FIREWALL_NAME;
#    read -p "DSHIELD userid: "  DSHIELD_USERID;
#    read -p "ALERTA server hostname: "  ALERTA_SERVER;
#    read -p "ALERTA API Key: "  ALERTA_APIKEY;
    read -p "ED25519 SSH Public key: " SSH_PUBLIC_KEY;
    # Configure wireless / HostAPD
    read -p "SSID for wireless: "  mySSID;
    read -p "WPA Password for wireless: "  myWPAPASSPHRASE;
    read -p "ISO Country code for wireless, i.e. DK: "  COUNTRY_CODE;
    # Set FQDN
    hostnamectl set-hostname $FIREWALL_NAME.$INTERNAL_DOMAIN;
    echo -e "\e[32mget_information() finished\e[0m";
    /usr/bin/logger 'get_information() finished' -t 'Debian-FW-20220213';
}

configure_locale() {
    /usr/bin/logger 'configure_locale()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_locale()\e[0m";
    echo -e "\e[36m-Configure locale (default:C.UTF-8)\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    update-locale LANG=en_GB.utf8 > /dev/null 2>&1
    cat << __EOF__  > /etc/default/locale
# /etc/default/locale
LANG=C.UTF-8
LANGUAGE=C.UTF-8
LC_ALL=C.UTF-8
__EOF__
    echo -e "\e[32mconfigure_locale() finished\e[0m";
    /usr/bin/logger 'configure_locale() finished' -t 'Debian-FW-20220213';
}

configure_bind() {
    /usr/bin/logger 'configure_bind()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_bind()\e[0m";
    systemctl stop bind9.service > /dev/null 2>&1
    echo -e "\e[36m-Configure bind options\e[0m";
    cat << __EOF__  > /etc/bind/named.conf.options
options {
	directory "/var/cache/bind";
	dnssec-validation auto;

	check-names master ignore;
	auth-nxdomain no;    # conform to RFC1035
	listen-on-v6 { none; };
	#filter-aaaa-on-v4 yes;
	listen-on { 127.0.0.1; 192.168.10.1; 192.168.20.1; 192.168.30.1; 192.168.40.1; };
	allow-query { homenet; };
	recursion yes;
	allow-recursion { homenet; };
	allow-query-cache { homenet; };
    ixfr-from-differences yes;
    empty-zones-enable yes;
    response-policy {
		#zone "rpz.block.misp";
		zone "threatfox.rpz";
    };
};
__EOF__

    # Generate rndc key
    rndc-confgen -a -c /etc/bind/rndc.key > /dev/null 2>&1
    # "local" BIND9 configuration details
    echo -e "\e[36m-Configure bind local\e[0m";
    cat << __EOF__  > /etc/bind/named.conf.local
//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";
include "/etc/bind/rndc.key";

acl homenet {
	127.0.0.0/8;
	192.168.10.0/24;
	192.168.20.0/24;
	192.168.30.0/24;
	192.168.40.0/24;
	};

zone "$INTERNAL_DOMAIN" {
	type master;
        file "/var/lib/bind/db.$INTERNAL_DOMAIN";
	check-names ignore;
        //allow-update { key rndc-key; };
        allow-update { 192.168.0.0/16; };
        allow-transfer { 192.168.10.1; localhost; };
        };

zone "10.168.192.in-addr.arpa" {
        type master;
       	check-names ignore;
//	allow-update { key rndc-key; };	
        allow-update { 192.168.10.0/24; };
        allow-transfer { 192.168.10.1; localhost; };
        file "/var/lib/bind/db.10.168.192.in-addr.arpa";
	};

zone "20.168.192.in-addr.arpa" {
        type master;
        check-names ignore;
//        allow-update { key rndc-key; };
        allow-update { 192.168.20.0/24; };
        allow-transfer { 192.168.10.1; localhost; };
        file "/var/lib/bind/db.20.168.192.in-addr.arpa";
	};

zone "30.168.192.in-addr.arpa" {
        type master;
        check-names ignore;
//        allow-update { key rndc-key; };
        allow-update { 192.168.30.0/24; };
        allow-transfer { 192.168.10.1; localhost; };
        file "/var/lib/bind/db.30.168.192.in-addr.arpa";
        };

zone "40.168.192.in-addr.arpa" {
        type master;
        check-names ignore;
//        allow-update { key rndc-key; };
        allow-update { 192.168.40.0/24; };
        allow-transfer { 192.168.10.1; localhost; };
        file "/var/lib/bind/db.40.168.192.in-addr.arpa";
        };

zone "threatfox.rpz" {
        type master;
        file "/var/lib/bind/threatfox.rpz";
        check-names ignore;
        allow-update { none; };
        allow-transfer { 192.168.10.1; localhost; 192.168.10.193; };
        allow-query { localhost; };
};

__EOF__

    echo -e "\e[36m-Configure forward lookup zone\e[0m";
    cat << __EOF__  > /var/lib/bind/db.$INTERNAL_DOMAIN
\$ORIGIN .
\$TTL 604800	; 1 week
$INTERNAL_DOMAIN	IN SOA	localhost. root.localhost. (
				    15994      ; serial
				    604800     ; refresh (1 week)
				    86400      ; retry (1 day)
				    2419200    ; expire (4 weeks)
				    604800     ; minimum (1 week)
				    )
			    NS	$FIREWALL_NAME.
			    A	127.0.0.1
			    AAAA	::1
$FIREWALL_NAME	A	192.168.10.1
			    A	192.168.20.1
			    A	192.168.30.1
			    A	192.168.40.1
__EOF__

    echo -e "\e[36m-Configure reverse lookup zones\e[0m";
    # 10.168.192.in-addr.arpa
    cat << __EOF__  > /var/lib/bind/db.10.168.192.in-addr.arpa
\$ORIGIN .
\$TTL 604800	; 1 week
10.168.192.in-addr.arpa	IN SOA	localhost. localhost.root. (
				10314      ; serial
				604800     ; refresh (1 week)
				86400      ; retry (1 day)
				2419200    ; expire (4 weeks)
				604800     ; minimum (1 week)
				)
			NS	$FIREWALL_NAME.
__EOF__

# BIND logging
    mkdir /var/log/named/ > /dev/null 2>&1
    touch /var/log/named/bind.log > /dev/null 2>&1
    touch /var/log/named/rpz.log > /dev/null 2>&1
    chown -R bind:bind /var/log/named/ > /dev/null 2>&1
    # "local" BIND9 configuration details
    echo -e "\e[36m-Configure bind local\e[0m";
    cat << __EOF__  > /etc/bind/named.conf.log
logging {
  channel bind_log {
    file "/var/log/named/bind.log" versions 2 size 50m;
    severity info;
    print-category yes;
    print-severity yes;
    print-time yes;
  };
# Response Policy Zone logging
  channel rpzlog {
    file "/var/log/named/rpz.log" versions unlimited size 100m;
    print-time yes;
    print-category yes;
    print-severity yes;
    severity error;
  };
  category default { bind_log; };
  category update { bind_log; };
  category update-security { bind_log; };
  category security { bind_log; };
  category queries { bind_log; };
  category lame-servers { bind_log; };
  category rpz { rpzlog; };
};
__EOF__
    echo 'include "/etc/bind/named.conf.log";' | tee -a /etc/bin/named.conf > /dev/null 2>&1
    # 20.168.192.in-addr.arpa
    cat << __EOF__  > /var/lib/bind/db.20.168.192.in-addr.arpa
\$ORIGIN .
\$TTL 604800	; 1 week
20.168.192.in-addr.arpa	IN SOA	localhost. localhost.root. (
				10314      ; serial
				604800     ; refresh (1 week)
				86400      ; retry (1 day)
				2419200    ; expire (4 weeks)
				604800     ; minimum (1 week)
				)
			NS	$FIREWALL_NAME.
__EOF__

    # 30.168.192.in-addr.arpa
    cat << __EOF__  > /var/lib/bind/db.30.168.192.in-addr.arpa
\$ORIGIN .
\$TTL 604800	; 1 week
30.168.192.in-addr.arpa	IN SOA	localhost. localhost.root. (
				10314      ; serial
				604800     ; refresh (1 week)
				86400      ; retry (1 day)
				2419200    ; expire (4 weeks)
				604800     ; minimum (1 week)
				)
			NS	$FIREWALL_NAME.
__EOF__

    # 40.168.192.in-addr.arpa
    cat << __EOF__  > /var/lib/bind/db.40.168.192.in-addr.arpa
\$ORIGIN .
\$TTL 604800	; 1 week
40.168.192.in-addr.arpa	IN SOA	localhost. localhost.root. (
				10314      ; serial
				604800     ; refresh (1 week)
				86400      ; retry (1 day)
				2419200    ; expire (4 weeks)
				604800     ; minimum (1 week)
				)
			NS	$FIREWALL_NAME.
__EOF__
    sync;
    systemctl restart bind9.service > /dev/null 2>&1
    echo -e "\e[32mconfigure_bind() finished\e[0m";
    /usr/bin/logger 'configure_bind() finished' -t 'Debian-FW-20220213';
}

configure_threatfox() {
    /usr/bin/logger 'configure_threatfox()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_threatfox()\e[0m";
    cat << __EOF__  > /lib/systemd/system/update-threatfox.timer
[Unit]
Description=Weekly job to update the threatfox RPZ db
Documentation=https://threatfox.abuse.ch/export/#rpz

[Timer]
# Don't run for the first 15 minutes after boot
OnBootSec=15min
# Run Weekly
OnCalendar=Weekly
# Specify service
Unit=update-threatfox.service

[Install]
WantedBy=multi-user.target
__EOF__

    cat << __EOF__  > /lib/systemd/system/update-threatfox.service
[Unit]
Description=service file downloading latest rpz from threatfox
Documentation=https://threatfox.abuse.ch/export/#rpz

[Service]
User=bind
Group=bind
ExecStartPre=-/usr/sbin/rndc zonestatus threatfox.rpz
ExecStart=-/usr/bin/wget -O /var/lib/bind/threatfox.rpz https://threatfox.abuse.ch/downloads/threatfox.rpz
ExecStopPost=-/usr/sbin/rndc reload
WorkingDirectory=/var/lib/bind/

[Install]
WantedBy=multi-user.target
__EOF__
    systemctl daemon-reload > /dev/null 2>&1
    systemctl enable update-threatfox.timer > /dev/null 2>&1
    systemctl enable update-threatfox.service > /dev/null 2>&1
    systemctl daemon-reload > /dev/null 2>&1
    systemctl start update-threatfox.timer > /dev/null 2>&1
    systemctl start update-threatfox.service > /dev/null 2>&1
    echo -e "\e[32mconfigure_threatfox() finished\e[0m";
    /usr/bin/logger 'configure_threatfox() finished' -t 'Debian-FW-20220213';
}

configure_dhcp_server() {
    /usr/bin/logger 'configure_dhcp_server()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_dhcp_server()\e[0m";
    # Bind generates key at install, use that or generate new in same location
    systemctl stop isc-dhcp.server.service > /dev/null 2>&1
    echo -e "\e[36m-Configure dhcpd.conf\e[0m";
    cat << __EOF__  > /etc/dhcp/dhcpd.conf
# DHCP configuration file

authoritative;
include "/etc/bind/rndc.key";

ddns-update-style standard;
default-lease-time 3600;
max-lease-time 2592000;
log-facility local7;
update-static-leases on;
allow client-updates;
#update-conflict-detection false;

zone $INTERNAL_DOMAIN. {
  primary 192.168.10.1;
  key rndc-key;
  }

zone 10.168.192.in-addr.arpa. {
  primary 192.168.10.1;
  key rndc-key;
  }

zone 20.168.192.in-addr.arpa. {
  primary 192.168.20.1;
  key rndc-key;
  }

zone 30.168.192.in-addr.arpa. {
  primary 192.168.30.1;
  key rndc-key;
  }

zone 40.168.192.in-addr.arpa. {
  primary 192.168.40.1;
  key rndc-key;
  }

# subnet 192.168.10.0
subnet 192.168.10.0 netmask 255.255.255.0 {
  option routers 192.168.10.1;
  option domain-name-servers 192.168.10.1;
  option domain-name "$INTERNAL_DOMAIN";
  range 192.168.10.100 192.168.10.250;
  ddns-domainname "$INTERNAL_DOMAIN.";
  ddns-rev-domainname "in-addr.arpa.";
}

# subnet 192.168.20.0
subnet 192.168.20.0 netmask 255.255.255.0 {
  option routers 192.168.20.1;
  option domain-name-servers 192.168.20.1;
  option domain-name "$INTERNAL_DOMAIN";
  range 192.168.20.10 192.168.20.254;
  ddns-domainname "$INTERNAL_DOMAIN.";
  ddns-rev-domainname "in-addr.arpa.";
}

# subnet 192.168.30.0
subnet 192.168.30.0 netmask 255.255.255.0 {
  option routers 192.168.30.1;
  option domain-name-servers 192.168.30.1;
  option domain-name "$INTERNAL_DOMAIN";
  range 192.168.30.10 192.168.30.254;
  ddns-domainname "$INTERNAL_DOMAIN.";
  ddns-rev-domainname "in-addr.arpa.";
}

# subnet 192.168.40.0
subnet 192.168.40.0 netmask 255.255.255.0 {
  option routers 192.168.40.1;
  option domain-name-servers 192.168.40.1;
  option domain-name "$INTERNAL_DOMAIN";
  range 192.168.40.1 192.168.40.254;
  ddns-domainname "$INTERNAL_DOMAIN.";
  ddns-rev-domainname "in-addr.arpa.";
}

# Server fixed addresses
#host misp01 {
#       hardware ethernet 08:00:27:d2:a4:ad;
#       fixed-address 192.168.10.25;
#}
__EOF__
    # Configure interfaces to listen on + disable dhcpv6
    sed -ie 's/INTERFACESv4=\"\"/INTERFACESv4=\"enp2s0 enp3s0 enp4s0\"/g' /etc/default/isc-dhcp-server > /dev/null 2>&1
    sed -ie 's/INTERFACESv6=\"\"/#INTERFACESv6=\"\"/g' /etc/default/isc-dhcp-server > /dev/null 2>&1
    sync;
    systemctl restart isc-dhcp.server.service > /dev/null 2>&1
    echo -e "\e[32mconfigure_dhcp_server()\e[0m";
    /usr/bin/logger 'configure_dhcp_server() finished' -t 'Debian-FW-20220213';
}

install_dshield() {
    /usr/bin/logger 'install_dshield()' -t 'Debian-FW-20220213';
    echo -e "\e[32minstall_dshield()\e[0m";
    mkdir /usr/local/dshield > /dev/null 2>&1
    cd /usr/local/dshield > /dev/null 2>&1
    wget -O /usr/local/dshield https://isc.sans.edu/clients/framework/iptables.tar.gz > /dev/null 2>&1
    tar zxvfp iptables.tar.gz > /dev/null 2>&1
    mv iptables ./ > /dev/null 2>&1
    rm iptables.tar.gz > /dev/null 2>&1
    cd ~; > /dev/null 2>&1
    echo -e "\e[32minstall_dshield() finished\e[0m";
    /usr/bin/logger 'install_dshield() finished' -t 'Debian-FW-20220213';
}

configure_dshield() {
    /usr/bin/logger 'configure_dshield()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_dshield()\e[0m";
    # copy default dshield files
    /usr/bin/cp /usr/local/dshield/dshield* /etc/;
    # Mail address for DSHIELD
    /usr/bin/sed -ie s/from=nobody\@nowhere.com/from=$MAIL_ADDRESS/g /etc/dshield.cnf;
    # DSHIELD userid
    /usr/bin/sed -ie s/userid=0/userid=$DSHIELD_USERID/g /etc/dshield.cnf;
    #!/bin/sh

    cat << __EOF__  > /etc/cron.hourly/dshield
#!/bin/sh
/usr/local/dshield/iptables.pl
/usr/bin/logger 'Processed iptables and sent to dshield' -t 'dshield';
exit 0
__EOF__
    sync;
    chmod +x /etc/cron.hourly/dshield;
    echo -e "\e[32mconfigure_dshield() finished\e[0m";
    /usr/bin/logger 'configure_dshield() finished' -t 'Debian-FW-20220213';
}

install_crowdsec() {
    /usr/bin/logger 'install_crowdsec()' -t 'Debian-FW-20220213';
    echo -e "\e[32minstall_crowdsec()\e[0m";
    # Add repo
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash  > /dev/null 2>&1
    #install crowdsec core daemon
    apt-get -qq -y install crowdsec > /dev/null 2>&1
    # install firewall bouncer
    apt-get -qq -y install crowdsec-firewall-bouncer-iptables > /dev/null 2>&1
    echo -e "\e[32minstall_crowdsec() finished\e[0m";
    /usr/bin/logger 'install_crowdsec() finished' -t 'Debian-FW-20220213';
}

configure_crowdsec() {
    /usr/bin/logger 'configure_crowdsec()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_crowdsec()\e[0m";
    # Collection iptables
    cscli parsers install crowdsecurity/iptables-logs > /dev/null 2>&1
    cscli parsers install crowdsecurity/geoip-enrich > /dev/null 2>&1
    cscli scenarios install crowdsecurity/iptables-scan-multi_ports > /dev/null 2>&1
    cscli scenarios install crowdsecurity/ssh-bf > /dev/null 2>&1
    cscli collections install crowdsecurity/linux > /dev/null 2>&1
    cscli collections install crowdsecurity/iptables > /dev/null 2>&1
    cscli postoverflows install crowdsecurity/rdns > /dev/null 2>&1
    # configure crowdsec to read iptables.log, specific to this firewall build, or it won't pick up log data
    # add - /var/log/iptables.log after the first filenames:
    sed -ie '/filenames:/a \  - /var/log/iptables.log' /etc/crowdsec/acquis.yaml > /dev/null 2>&1
    # Running 'sudo systemctl reload crowdsec' for the new configuration to be effective.
    systemctl reload crowdsec.service > /dev/null 2>&1
    # Enable auto complete for BASH
    source /etc/profile > /dev/null 2>&1
    source <(cscli completion bash) > /dev/null 2>&1
    echo -e "\e[32mconfigure_crowdsec() finished\e[0m";
    /usr/bin/logger 'configure_crowdsec() finished' -t 'Debian-FW-20220213';
}

configure_rsyslog() {
    /usr/bin/logger 'configure_rsyslog()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_rsyslog()\e[0m";
    # Writing iptables logdata to separate file
    echo -e "\e[36m-Configure syslog to filebeat\e[0m";
    cat << __EOF__  > /etc/rsyslog.d/30-iptables.conf
:msg,contains,"iptables:" /var/log/iptables.log
& stop
__EOF__
    # Writing ntppeers data from iptables logdata to separate file
    echo -e "\e[36m-Configure ntppeers.log\e[0m";
    cat << __EOF__  > /etc/rsyslog.d/30-ntppeers.conf
:msg,contains,"ntppeers:" /var/log/ntppeers.log
& stop
__EOF__
    sync;
    systemctl restart rsyslog.service > /dev/null 2>&1
    echo -e "\e[32mconfigure_rsyslog() finished\e[0m";
    /usr/bin/logger 'configure_rsyslog() finished' -t 'Debian-FW-20220213';
}

configure_exim() {
    /usr/bin/logger 'configure_exim()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_exim()\e[0m";
    echo -e "\e[36m-Configure exim4.conf.conf\e[0m";
    cat << __EOF__  > /etc/exim4/update-exim4.conf.conf
# This is a Debian Firewall specific file
dc_eximconfig_configtype='smarthost'
dc_other_hostnames=''
dc_local_interfaces='127.0.0.1'
dc_readhost='$MAIL_DOMAIN'
dc_relay_domains=''
dc_minimaldns='false'
dc_relay_nets='192.168.10.0/24, 192.168.20.0/24, 192.168.30.0/24, 192.168.40.0/24'
dc_smarthost='$MAIL_SERVER::$MAIL_ADDRESS'
CFILEMODE='644'
dc_use_split_config='true'
dc_hide_mailname='true'
dc_mailname_in_oh='true'
dc_localdelivery='mail_spool'
__EOF__

    echo -e "\e[36m-Configure mail access\e[0m";
    cat << __EOF__  > /etc/exim4/passwd.client
    # password file used when the local exim is authenticating to a remote
# host as a client.
#
# see exim4_passwd_client(5) for more documentation
$SMTP_SERVER:$MAIL_ADDRESS:$MAIL_PASSWORD
__EOF__

    echo -e "\e[36m-Configure mail addresses\e[0m";
    cat << __EOF__  > /etc/email-addresses
<my local user>: $MAIL_ADDRESS
root: $MAIL_ADDRESS
__EOF__
    # Time to reconfigure exim4
    dpkg-reconfigure -fnoninteractive exim4-config > /dev/null 2>&1
    echo -e "\e[32mconfigure_exim() finished\e[0m";
    /usr/bin/logger 'configure_exim() finished' -t 'Debian-FW-20220213';
}

install_filebeat() {
    /usr/bin/logger 'install_filebeat()' -t 'Debian-FW-20220213';
    echo -e "\e[32minstall_filebeat()\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    # Install key and apt source for elastic
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -  > /dev/null 2>&1
    #apt-key adv --fetch-keys https://artifacts.elastic.co/GPG-KEY-elasticsearch;
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-7.x.list > /dev/null 2>&1
    apt-get update > /dev/null 2>&1
    apt-get -qq -y install filebeat > /dev/null 2>&1
    systemctl daemon-reload > /dev/null 2>&1
    systemctl enable filebeat.service > /dev/null 2>&1
    echo -e "\e[32minstall_filebeat() finished\e[0m";
    /usr/bin/logger 'install_filebeat() finished' -t 'Debian-FW-20220213';
}

configure_filebeat() {
    /usr/bin/logger 'configure_filebeat()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_filebeat()\e[0m";
    echo -e "\e[32mconfigure rsyslog forwarding to filebeat\e[0m";
    # Forward all logs to Filebeat listening locally on 9001
    echo -e "\e[36m-Configure syslog to filebeat\e[0m";
    cat << __EOF__  > /etc/rsyslog.d/02-filebeat.conf
if \$msg contains "iptables:" then
*.* @127.0.0.1:9001
__EOF__
    systemctl restart rsyslog.service > /dev/null 2>&1
    echo -e "\e[32mconfigure_filebeat()\e[0m";
    echo -e "\e[36m-configure Logstash server for Filebeat\e[0m";
    # Depends on your individual setup, follow Elastic guidance and change as required in iptables.rules
    systemctl start filebeat.service > /dev/null 2>&1
    echo -e "\e[32mconfigure_filebeat() finished\e[0m";
    /usr/bin/logger 'configure_filebeat() finished' -t 'Debian-FW-20220213';
}

configure_timezone() {
    /usr/bin/logger 'configure_timezone()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_timezone()\e[0m";
    echo -e "\e[36m-Set timezone to Etc/UTC\e[0m";
    # Setting timezone to UTC
    export DEBIAN_FRONTEND=noninteractive;
    rm /etc/localtime > /dev/null 2>&1
    sh -c "echo 'Etc/UTC' > /etc/timezone";
    dpkg-reconfigure -f noninteractive tzdata > /dev/null 2>&1
    echo -e "\e[32mconfigure_timezone() finished\e[0m";
    /usr/bin/logger 'configure_timezone() finished' -t 'Debian-FW-20220213';
}

configure_sources() {
    /usr/bin/logger 'configure_sources()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_sources()\e[0m";
    echo -e "\e[36m-sources.list\e[0m";
    cat << __EOF__  > /etc/apt/sources.list
deb http://deb.debian.org/debian/ bullseye main contrib non-free
deb-src http://deb.debian.org/debian/ bullseye main contrib non-free

deb http://security.debian.org/debian-security bullseye-security main contrib non-free
deb-src http://security.debian.org/debian-security bullseye-security main contrib non-free

# bullseye-updates, previously known as 'volatile'
deb http://deb.debian.org/debian/ bullseye-updates main contrib non-free
deb-src http://deb.debian.org/debian/ bullseye-updates main contrib non-free

__EOF__
    sync;
    echo -e "\e[32mconfigure_sources() finished\e[0m";
}

configure_logrotate() {
    /usr/bin/logger 'configure_logrotate()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_logrotate()\e[0m";
    echo -e "\e[36m-ntppeers.log\e[0m";
    # configuring logrotation for ntppeers.log
    cat << __EOF__  > /etc/logrotate.d/ntp 
/var/log/ntppeers.log {
  rotate 1
  daily
  compress
  create 640 root root
  notifempty
  postrotate
    /usr/lib/rsyslog/rsyslog-rotate
  endscript
}
__EOF__

    echo -e "\e[36m-iptables.log\e[0m";
    # configuring logrotation for iptables.log
    cat << __EOF__  > /etc/logrotate.d/iptables 
/var/log/iptables.log {
  rotate 2
  daily
  compress
  create 640 root root
  notifempty
  postrotate
    /usr/lib/rsyslog/rsyslog-rotate
  endscript
}
__EOF__

    echo -e "\e[36m-bind.log\e[0m";
    # configuring logrotation for bind.log
    cat << __EOF__  > /etc/logrotate.d/named 
/var/log/named/bind.log {
  rotate 2
  daily
  compress
  create 640 bind bind
  notifempty
  postrotate
    /usr/lib/rsyslog/rsyslog-rotate
  endscript
}

/var/log/named/rpz.log {
  rotate 2
  daily
  compress
  create 640 bind bind
  notifempty
  postrotate
    /usr/lib/rsyslog/rsyslog-rotate
  endscript
}
__EOF__
    echo -e "\e[32mconfigure_logrotate() finished\e[0m";
    /usr/bin/logger 'configure_logrotate() finished' -t 'Debian-FW-20220213';
}

install_prerequisites() {
    /usr/bin/logger 'install_prerequisites' -t 'Debian-FW-20220213';
    echo -e "\e[1;32mInstalling Prerequisite packages\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    # OS Version
    # freedesktop.org and systemd
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
    /usr/bin/logger "Operating System: $OS Version: $VER" -t 'Debian-FW-20220213';
    echo -e "\e[1;32mOperating System: $OS Version: $VER\e[0m";
    # Install prerequisites
    echo -e "\e[36m-prerequisites...\e[0m";
    apt-get -qq -y install net-tools libio-socket-ssl-perl libnet-ssleay-perl bind9 isc-dhcp-server exim4 sysfsutils iptables vnstat iftop > /dev/null 2>&1
    # Install some basic tools on a Debian net install
    /usr/bin/logger '..Install some basic tools on a Debian net install' -t 'Debian-FW-20220213';
    apt-get -qq -y install sudo adduser wget whois unzip apt-transport-https ca-certificates curl gnupg2 software-properties-common dnsutils > /dev/null 2>&1
    apt-get -qq -y install bash-completion debian-goodies dirmngr ethtool firmware-iwlwifi firmware-linux-free firmware-linux-nonfree > /dev/null 2>&1
    apt-get -qq -y install sudo flashrom geoip-database unattended-upgrades python3 python3-pip > /dev/null 2>&1
    python3 -m pip install --upgrade pip;
    # Set correct locale
    systemctl daemon-reload > /dev/null 2>&1
    systemctl enable bind9.service > /dev/null 2>&1
    systemctl enable isc-dhcp-server.service > /dev/null 2>&1
    echo -e "\e[1;32mInstalling Prerequisite packages finished\e[0m";
    /usr/bin/logger 'install_prerequisites() finished' -t 'Debian-FW-20220213';
}

configure_cpu() {
    /usr/bin/logger 'configure_cpu()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_cpu()\e[0m";
    echo -e "\e[36m-CPU performance governor\e[0m";
    cat << __EOF__  >> /etc/sysfs.conf
## Configure AMD Jaguar to run all cores at 1Ghz - boost at 1.4Ghz
devices/system/cpu/cpu0/cpufreq/scaling_governor = performance
devices/system/cpu/cpu1/cpufreq/scaling_governor = performance
devices/system/cpu/cpu2/cpufreq/scaling_governor = performance
devices/system/cpu/cpu3/cpufreq/scaling_governor = performance
__EOF__
    sync;
    echo -e "\e[32mconfigure_cpu() finished\e[0m";
    /usr/bin/logger 'configure_cpu() finished' -t 'Debian-FW-20220213';
}

enable_ipforwarding() {
    /usr/bin/logger 'enable_ipforwarding()' -t 'Debian-FW-20220213';
    echo -e "\e[32menable_ipforwarding()\e[0m";
    echo -e "\e[36m-Enabling IPv4 Forwarding\e[0m";
    /usr/bin/sed -ie s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g /etc/sysctl.conf
    # The current ruleset is IPv4 only, so do NOT enable Ipv6 forwarding just yet
    #/usr/bin/sed -ie s/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/g /etc/sysctl.conf
    sync;
    echo -e "\e[32menable_ipforwarding() finished\e[0m";
    /usr/bin/logger 'enable_ipforwarding() finished' -t 'Debian-FW-20220213';
}

configure_resolv() {
    /usr/bin/logger 'configure_resolv()' -t 'Debian-FW-20220213';    
    echo -e "\e[32mconfigure_resolv()\e[0m";
    echo -e "\e[36m-Configuring resolv.conf\e[0m";
    mv /etc/resolv.conf /etc/resolv.conf.isp > /dev/null 2>&1
    # DHCP changes your resolv.conf to use the ISPs dns and search order, so let's make sure we always use local BIND9
    cat << __EOF__  > /etc/resolv.conf
domain $INTERNAL_DOMAIN
search $INTERNAL_DOMAIN
# BIND9 configured to listen on localhost
nameserver 127.0.0.1
__EOF__
    sync;
    # Make it immutable or these changes will be overwritten everytime dhcp lease renews
    /usr/bin/chattr +i /etc/resolv.conf > /dev/null 2>&1
    echo -e "\e[32mconfigure_resolv() finished\e[0m";
    /usr/bin/logger 'configure_resolv() finished' -t 'Debian-FW-20220213';    
}

install_updates() {
    echo -e "\e[32m - install_updates()\e[0m";
    /usr/bin/logger 'install_updates()' -t 'Debian-FW-20220213';
    export DEBIAN_FRONTEND=noninteractive;
    apt-get -qq -y install --fix-policy > /dev/null 2>&1
    echo -e "\e[36m ... update\e[0m" && apt-get -qq update > /dev/null 2>&1
    echo -e "\e[36m ... full-upgrade\e[0m" && apt-get -qq -y full-upgrade > /dev/null 2>&1
    echo -e "\e[36m ... cleaning up apt\e[0m";
    echo -e "\e[36m ... autoremove\e[0m" && apt-get -qq -y --purge autoremove > /dev/null 2>&1
    echo -e "\e[36m ... autoclean\e[0m" && apt-get -qq autoclean > /dev/null 2>&1
    echo -e "\e[36m ... Done\e[0m" > /dev/null 2>&1
    sync;
    echo -e "\e[32m - install_updates() finished\e[0m";
    /usr/bin/logger 'install_updates() finished' -t 'Debian-FW-20220213';
}

install_ntp_tools() {
    echo -e "\e[32m - install_ntp_tools()\e[0m";
    /usr/bin/logger 'install_ntp_tools()' -t 'Debian-FW-20220213';
    export DEBIAN_FRONTEND=noninteractive;
    echo -e "\e[36m ... installing ntp tools\e[0m";
    apt-get -qq -y install ntpstat ntpdate > /dev/null 2>&1
    echo -e "\e[32m - install_ntp_tools() finished\e[0m";
    /usr/bin/logger 'install_ntp_tools() finished' -t 'Debian-FW-20220213';
}

install_ntp() {
    /usr/bin/logger 'install_ntp()' -t 'Debian-FW-20220213';
    echo -e "\e[32m - install_ntp()\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    echo -e "\e[36m ... installing ntp\e[0m";
    apt-get -qq -y install ntp > /dev/null 2>&1
    /usr/bin/logger 'install_ntp() finished' -t 'Debian-FW-20220213';
    echo -e "\e[32m - install_ntp() finished\e[0m";
}

configure_ntp() {
    /usr/bin/logger 'configure_ntp()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_ntp()\e[0m";
    echo -e "\e[36m-Stop ntpd\e[0m";
    systemctl stop ntp.service;
    echo -e "\e[36m-Create new ntp.conf\e[0m";
    cat << __EOF__  > /etc/ntp.conf
# /etc/ntp.conf, configuration for ntpd; see ntp.conf(5) for help

driftfile /var/lib/ntp/ntp.drift

# Enable this if you want statistics to be logged.
#statsdir /var/log/ntpstats/

statistics loopstats peerstats clockstats
filegen loopstats file loopstats type day enable
filegen peerstats file peerstats type day enable
filegen clockstats file clockstats type day enable

# Specify one or more NTP servers.

# Use servers from the NTP Pool Project. Approved by Ubuntu Technical Board
# on 2011-02-08 (LP: #104525). See http://www.pool.ntp.org/join.html for
# more information.
# Stratum-1 Servers to sync with - pick 4 to 6 good ones from
# http://support.ntp.org/bin/view/Servers/
#
# Selected for quality in Northern Europe
server ptbtime2.ptb.de iburst
server ntps1-1.eecsit.tu-berlin.de iburst
server time.antwerpspace.be  iburst
server time.esa.int iburst

# Access control configuration; see /usr/share/doc/ntp-doc/html/accopt.html for
# details.  The web page <http://support.ntp.org/bin/view/Support/AccessRestrictions>
# might also be helpful.
#
# Note that "restrict" applies to both servers and clients, so a configuration
# that might be intended to block requests from certain clients could also end
# up blocking replies from your own upstream servers.

# By default, exchange time with everybody, but don't allow configuration.
restrict -4 default kod notrap nomodify nopeer noquery limited
restrict -6 default kod notrap nomodify nopeer noquery limited

# Local users may interrogate the ntp server more closely.
restrict 127.0.0.1
restrict ::1

# Needed for adding pool entries
restrict source notrap nomodify noquery

# Clients from this (example!) subnet have unlimited access, but only if
# cryptographically authenticated.
#restrict 192.168.123.0 mask 255.255.255.0 notrust


# If you want to provide time to your local subnet, change the next line.
# (Again, the address is an example only.)
#broadcast 192.168.123.255

# If you want to listen to time broadcasts on your local subnet, de-comment the
# next lines.  Please do this only if you trust everybody on the network!
#disable auth
#broadcastclient
leapfile /var/lib/ntp/leap-seconds.list
__EOF__

    # Create folder for logfiles and let ntp own it
    echo -e "\e[36m-Create folder for logfiles and let ntp own it\e[0m";
    mkdir /var/log/ntpd
    chown ntp /var/log/ntpd
    sync;    
    ## Restart NTPD
    systemctl restart ntp.service;
    /usr/bin/logger 'configure_ntp() finished' -t 'Debian-FW-20220213';
}

configure_update-leap() {
    /usr/bin/logger 'configure_update-leap()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_update-leap()\e[0m";
    echo -e "\e[36m-Creating service unit file\e[0m";
    cat << __EOF__  > /lib/systemd/system/update-leap.service
# service file running update-leap
# triggered by update-leap.timer

[Unit]
Description=service file running update-leap
Documentation=man:update-leap

[Service]
User=ntp
Group=ntp
ExecStart=-/usr/bin/wget -O /var/lib/ntp/leap-seconds.list https://www.ietf.org/timezones/data/leap-seconds.list
WorkingDirectory=/var/lib/ntp/

[Install]
WantedBy=multi-user.target
__EOF__

   echo -e "\e[36m-creating timer unit file\e[0m";

   cat << __EOF__  > /lib/systemd/system/update-leap.timer
# runs update-leap Weekly.
[Unit]
Description=Weekly job to check for updated leap-seconds.list file
Documentation=man:update-leap

[Timer]
# Don't run for the first 15 minutes after boot
OnBootSec=15min
# Run Weekly
OnCalendar=Weekly
# Specify service
Unit=update-leap.service

[Install]
WantedBy=multi-user.target
__EOF__

    sync;
    echo -e "\e[36m-Get initial leap file and making sure timer and service can run\e[0m";
    wget -O /var/lib/ntp/leap-seconds.list http://www.ietf.org/timezones/data/leap-seconds.list;
    chown ntp:ntp /var/lib/ntp/leap-seconds.list;
    systemctl daemon-reload;
    systemctl enable update-leap.timer;
    systemctl enable update-leap.service;
    systemctl daemon-reload;
    systemctl start update-leap.timer;
    systemctl start update-leap.service;
    /usr/bin/logger 'configure_update-leap() finished' -t 'Debian-FW-20220213';
}

configure_iptables() {
    /usr/bin/logger 'configure_iptables()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_iptables()\e[0m";
    echo -e "\e[32m-Creating iptables rules file\e[0m";
    cat << __EOF__  >> /etc/network/iptables.rules
#
# Debian Bullseye / Buster based Firewall
# IPTABLES Ruleset
# Author: Martin Boller (c) 2016
# bsecure.dk
# Version 1.0 / 2016-04-21 
#
# Version 1.1 / 2017-01-26
# Version 2.0 / 2019-11-29 (APU)
# Version 3.0 / 2022-02-13

#*raw
#:PREROUTING ACCEPT [0:0]
#:OUTPUT DROP     [0:0]
# Do not perform connection tracking for NTP traffic
#-A PREROUTING -p udp --dport 123 -j NOTRACK
#-A OUTPUT     -p udp --sport 123 -j NOTRACK
#COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]

# To redirect HTTP traffic to Squid, un-comment below
#-A PREROUTING ! -i enp1s0 -p tcp --dport 80 -j DNAT --to 192.168.10.1:3128
#-A PREROUTING -i enp2s0 -s 192.168.10.0/24 ! -d 192.168.20.0/24 -j NOTRACK
#-A PREROUTING -i enp3s0 -s 192.168.20.0/24 ! -d 192.168.10.0/24 -j NOTRACK

# NAT everything from inside to outside
-A POSTROUTING -s 192.168.0.0/16 -o enp1s0 -j MASQUERADE
COMMIT

*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
:LOG_DROPS - [0:0]

## DROP RFC1918 on enp1s0
-A INPUT -i enp1s0 -s 0.0.0.0/8 -j LOG_DROPS
-A INPUT -i enp1s0 -s 127.0.0.0/8 -j LOG_DROPS
-A INPUT -i enp1s0 -s 10.0.0.0/8 -j LOG_DROPS
# Using 192.168.10.0 and 192.168.20.0 nets internally so no dropping there -A INPUT -i enp1s0 -s 192.168.0.0/16 -j LOG_DROPS
-A INPUT -i enp1s0 -s 172.16.0.0/12 -j LOG_DROPS
-A INPUT -i enp1s0 -s 224.0.0.0/4 -j LOG_DROPS

## DROP IP fragments
-A INPUT -f -j LOG_DROPS
-A INPUT -m ttl --ttl-lt 4 -j LOG_DROPS

## DROP bad TCP/UDP combinations
-A INPUT -p tcp --dport 0 -j LOG_DROPS
-A INPUT -p udp --dport 0 -j LOG_DROPS
-A INPUT -p tcp --tcp-flags ALL NONE -j LOG_DROPS
-A INPUT -p tcp --tcp-flags ALL ALL -j LOG_DROPS

## Block specific persistent attackers
## Cloud Best Solutions NOC
#-A INPUT -s 5.188.206.164 -j LOG_DROPS
#-A INPUT -i enp1s1 -p udp --sport 123 -j DROP
#-I INPUT -i enp1s0 -s 109.206.205.233 -j DROP

## Pass everything on loopback
-A INPUT -i lo -j ACCEPT

# DHCP as inet side uses DHCP
-A OUTPUT -o enp1s0 -p udp --sport 67:68 -j ACCEPT

# iperf
-A OUTPUT -p tcp -m tcp --dport 5201 -j ACCEPT
-A INPUT -i enp2s0 -p tcp -m tcp --dport 5201 -j ACCEPT

## DNS on all interfaces (NOT recommended)
#-A INPUT -p udp --dport 53 -j ACCEPT
#-A INPUT -p tcp --dport 53 -j ACCEPT
#-A OUTPUT -p tcp --dport 53 -j ACCEPT
#-A OUTPUT -p udp --dport 53 -j ACCEPT

## GPSD on port 2947/TCP
-A INPUT -i lo -p tcp --dport 2947 -j ACCEPT
-A OUTPUT -p tcp --dport 2947 -j ACCEPT

## Crowdsec LAPI
-A INPUT -i lo -p tcp --dport 8080 -j ACCEPT
-A OUTPUT -p tcp --dport 8080 -j ACCEPT

## dns, dhcp, ntp, squid, icmp-echo
-A INPUT ! -i enp1s0 -p udp --dport 53 -j ACCEPT
-A INPUT ! -i enp1s0 -p tcp --dport 53 -j ACCEPT
-A INPUT ! -i enp1s0 -p udp --dport 67:68 -j ACCEPT

## RSYNC
-A OUTPUT ! -o enp1s0 -p tcp --dport 873 -j ACCEPT

## Allow DNS over TLS
-A INPUT ! -i enp1s0 -p tcp --dport 853 -j ACCEPT
## Allowing 123/udp both direction so we can be an NTP Server on the Internet
-A INPUT -i enp1s0 -p udp --dport 123 -j LOG --log-prefix "ntppeers: " --log-level 7
-A INPUT -i enp1s0 -p udp --dport 123 -j ACCEPT
-A OUTPUT -o enp1s0 -p udp --sport 123 -j ACCEPT
-A INPUT ! -i enp1s0 -p tcp --dport 3128 -j ACCEPT
-A INPUT ! -i enp1s0 -p icmp -j ACCEPT
# NFS Client
-A OUTPUT -p tcp --dport 2049 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --sport 2049 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -p udp --dport 2049 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p udp --sport 2049 -m state --state ESTABLISHED -j ACCEPT

## SSH on internal interfaces
-A INPUT -i enp2s0 -p tcp --dport 22 -j ACCEPT
-A INPUT -i enp3s0 -p tcp --dport 22 -j ACCEPT
-A INPUT -i enp4s0 -p tcp --dport 22 -j ACCEPT
-A INPUT -i wlp5s0 -p tcp --dport 22 -j ACCEPT
-A OUTPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -i enp1s0 -p tcp --dport 22 -j LOG_DROPS
## RSYSLOG output to Logstash on port 5000
#-A INPUT -i enp2s0 -p tcp --dport 5000 -j ACCEPT
#-A OUTPUT -p tcp --dport 5000 -j ACCEPT
#-A INPUT -i enp3s0 -p tcp --dport 22 -j ACCEPT

## Metricbeat output to logstash on port 6055
-A INPUT -i enp2s0 -p tcp --dport 6055 -j ACCEPT
-A INPUT -i enp3s0 -p tcp --dport 6055 -j ACCEPT
-A OUTPUT -p tcp --dport 6055 -j ACCEPT


## Outbound initiated by gateway to internet
-A OUTPUT -o lo -j ACCEPT
#
-A OUTPUT -p tcp --dport 53 -j ACCEPT
-A OUTPUT -p udp --dport 53 -j ACCEPT
-A OUTPUT -p tcp --sport 53 -j ACCEPT
-A OUTPUT -p udp --sport 53 -j ACCEPT
-A OUTPUT -o enp1s0 -p tcp --dport 43 -j ACCEPT
-A OUTPUT -o enp1s0 -p tcp --dport 80 -j ACCEPT
-A OUTPUT -o enp1s0 -p udp --dport 123 -j ACCEPT
-A OUTPUT -o enp1s0 -p udp --sport 123 -j ACCEPT
-A OUTPUT -o enp1s0 -p tcp --dport 443 -j ACCEPT
-A OUTPUT -o enp1s0 -p tcp --dport 587 -j ACCEPT
# DHCP as inet side uses DHCP
-A OUTPUT -o enp1s0 -p udp --sport 67:68 -j ACCEPT
# TIME/NTP stuff
-A INPUT -i enp2s0 -p udp --dport 123 -j ACCEPT
-A INPUT -i enp3s0 -p udp --dport 123 -j ACCEPT
-A INPUT -i enp4s0 -p udp --dport 123 -j ACCEPT
-A INPUT -i wlp5s0 -p udp --dport 123 -j ACCEPT
-A OUTPUT -o enp2s0 -p udp --dport 123 -j ACCEPT
-A OUTPUT -o enp3s0 -p udp --dport 123 -j ACCEPT
-A OUTPUT -o enp4s0 -p udp --dport 123 -j ACCEPT
-A OUTPUT -o wlp5s0 -p udp --dport 123 -j ACCEPT

## Any outbound tcp, udp, and icmp-echo to the inside network
-A OUTPUT ! -o enp1s0 -p udp --dport 68 -j ACCEPT
-A OUTPUT -p icmp -j ACCEPT

# FINAL INPUT/OUTPUT - related and drop
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -j LOG_DROPS
-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -j LOG_DROPS
#############################################################################

## IP forwarding rules: forward all internal networks outbound to enp1s0

## Internal Networks
-A FORWARD ! -i enp1s0 -s 192.168.0.0/16 -p tcp -j ACCEPT
-A FORWARD ! -i enp1s0 -s 192.168.0.0/16 -p udp -j ACCEPT
-A FORWARD ! -i enp1s0 -s 192.168.0.0/16 -p icmp -j ACCEPT
-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -j LOG_DROPS

## LOGGING
## get rid of broadcast noise
-A LOG_DROPS -d 255.255.255.255 -j DROP
# Drop Broadcast to internal networks
-A LOG_DROPS -m pkttype --pkt-type broadcast -d 192.168.10.255/24 -j DROP
-A LOG_DROPS -m pkttype --pkt-type broadcast -d 192.168.20.255/24 -j DROP
-A LOG_DROPS -p ip -m limit --limit 60/sec -j LOG --log-prefix "iptables: " --log-level 7
-A LOG_DROPS -j DROP

## Commit all of the above rules
COMMIT
__EOF__

    #Apply firewall rules before (pre-up) networking starts
    # to be secure all the time
    echo -e "\e[36m-Script applying iptables rules\e[0m";
    cat << __EOF__  >> /etc/network/if-pre-up.d/firewallrules
#!/bin/sh
iptables-restore < /etc/network/iptables.rules
exit 0
__EOF__

    # blackhole RFC1918 networks not in use
    cat << __EOF__  >> /etc/network/if-up.d/blacholerfc1918
#! /bin/bash
# add routes for blackhole
route add -net 10.0.0.0/8 gw 127.0.0.1 metric 200
route add -net 172.16.0.0/12 gw 127.0.0.1 metric 200
#route add -net 192.168.0.0/16 gw 127.0.0.1 metric 200
route add -net 224.0.0.0/4 gw 127.0.0.1 metric 200
exit 0
__EOF__
    sync;
    ## make the scripts executable
    chmod +x /etc/network/if-pre-up.d/firewallrules;
    chmod +x /etc/network/if-up.d/blacholerfc1918;
    /usr/bin/logger 'configure_iptables() finished' -t 'Debian-FW-20220213';
}

configure_interfaces() {
    /usr/bin/logger 'configure_interfaces()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_interfaces()\e[0m";
    echo -e "\e[36m-Create interfaces file\e[0m";
    ## Important this will overwrite your current interfaces file and may mess with all your networking on this system
    cat << __EOF__  >> /etc/network/interfaces
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo enp2s0 enp3s0 enp4s0 wlp5s0

# Loopback interface
iface lo inet loopback

# The primary network interface
# WAN - Internet side
allow-hotplug enp1s0
iface enp1s0 inet dhcp
# Actived with MAC Address 00:20:91:97:dc:95 - change permanent MAC
hwaddress ether 00:20:91:97:dc:95
dns-nameservers 192.168.10.1

allow-hotplug enp2s0
iface enp2s0 inet static
  hwaddress ether 00:20:91:97:ce:02
  address 192.168.10.1
  network 192.168.10.0
  netmask 255.255.255.0
  dns-nameservers 192.168.10.1

allow-hotplug enp3s0
iface enp3s0 inet static
  hwaddress ether 00:20:91:97:ce:03
  address 192.168.20.1
  network 192.168.20.0
  netmask 255.255.255.0
  dns-nameservers 192.168.20.1

allow-hotplug enp4s0
iface enp4s0 inet static
  hwaddress ether 00:20:91:97:ce:04
  address 192.168.30.1
  network 192.168.30.0
  netmask 255.255.255.0
  dns-nameservers 192.168.30.1

allow-hotplug wlp5s0
iface wlp5s0 inet static
  hwaddress ether 00:20:91:97:ce:05
  address 192.168.40.1
  network 192.168.40.0
  netmask 255.255.255.0
  dns-nameservers 192.168.40.1
__EOF__
    /usr/bin/logger 'configure_interfaces() finished' -t 'Debian-FW-20220213';
}

configure_motd() {
    echo -e "\e[32mconfigure_motd()\e[0m";
    echo -e "\e[36m-Create motd file\e[0m";
    cat << __EOF__  >> /etc/motd

*******************************************
***                                     ***
***              Firewall               ***
***      ------------------------       ***          
***        PC Engines APU4C4 FW         ***
***                                     ***
***       Version 2.00 Feb 2022         ***
***                                     ***
********************||*********************
             (\__/) ||
             (•ㅅ•) ||
            /  　  づ
__EOF__
    
    # do not show motd twice
    sed -ie 's/session    optional     pam_motd.so  motd=\/etc\/motd/#session    optional     pam_motd.so  motd=\/etc\/motd/' /etc/pam.d/sshd
    sync;
    /usr/bin/logger 'configure_motd() finished' -t 'Debian-FW-20220213';
}

install_ssh_keys() {
    /usr/bin/logger 'install_ssh_keys()' -t 'Debian-FW-20220213';
    echo -e "\e[32minstall_ssh_keys()\e[0m";
    echo -e "\e[36m-Add public key to authorized_keys file\e[0m";
    # Echo add SSH public key for root logon - change this to your own key
    mkdir /root/.ssh
    echo "ssh-ed25519 $SSH_PUBLIC_KEY" | tee -a /root/.ssh/authorized_keys
    chmod 700 /root/.ssh
    chmod 600 /root/.ssh/authorized_keys
    sync;
    /usr/bin/logger 'install_SSH_PUBLIC_KEYs() finished' -t 'Debian-FW-20220213';
}

configure_sshd() {
    /usr/bin/logger 'configure_sshd()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_sshd()\e[0m";
    ## Generate new host keys
    echo -e "\e[36m-Delete and recreate host SSH keys\e[0m";
    rm -v /etc/ssh/ssh_host_*;
    dpkg-reconfigure openssh-server;
    sync;
    /usr/bin/logger 'configure_sshd() finished' -t 'Debian-FW-20220213';
}

disable_timesyncd() {
    /usr/bin/logger 'disable_timesyncd()' -t 'Debian-FW-20220213';
    echo -e "\e[32mDisable_timesyncd()\e[0m";
    systemctl stop systemd-timesyncd
    systemctl daemon-reload
    systemctl disable systemd-timesyncd
    /usr/bin/logger 'disable_timesyncd() finished' -t 'Debian-FW-20220213';
}

configure_dhcp_ntp() {
    /usr/bin/logger 'configure_dhcp_ntp()' -t 'Debian-FW-20220213';
    echo -e "\e[32mconfigure_dhcp_ntp()\e[0m";
    ## Remove ntp and timesyncd exit hooks to cater for server using DHCP
    echo -e "\e[36m-Remove scripts utilizing DHCP\e[0m";
    rm /etc/dhcp/dhclient-exit-hooks.d/ntp
    rm /etc/dhcp/dhclient-exit-hooks.d/timesyncd
    ## Remove ntp.conf.dhcp if it exist
    echo -e "\e[36m-Removing ntp.conf.dhcp\e[0m";    
    rm /run/ntp.conf.dhcp
    ## Disable NTP option for dhcp
    echo -e "\e[36m-Disable ntp_servers option from dhclient\e[0m";   
    sed -i -e "s/option ntp_servers/#option ntp_servers/" /etc/dhcpcd.conf;
    ## restart NTPD yet again after cleaning up DHCP
    systemctl restart ntp
    /usr/bin/logger 'configure_dhcp_ntp() finished' -t 'Debian-FW-20220213';
}

finish_reboot() {
    echo -e "\e[1;31m - Countdown to reboot!\e[0m";
    /usr/bin/logger 'Countdown to reboot!' -t 'Debian-FW-20220213'
    secs=30;
    echo -e;
    echo -e "\e[1;31m--------------------------------------------\e[0m";
        while [ $secs -gt 0 ]; do
            echo -ne "\e[1;32m - Rebooting in (seconds):  "
            echo -ne "\e[1;31m$secs\033[0K\r"
            sleep 1
            : $((secs--))
        done;
    sync;
    echo -e
    echo -e "\e[1;31m - REBOOTING!\e[0m";
    /usr/bin/logger 'Rebooting!!' -t 'Debian-FW-20220213'
    reboot;
}

configure_grubserial() {
    /usr/bin/logger 'configure_grubserial()' -t 'Debian-FW-20220213'
    echo -e "\e[32mconfigure_grubserial()\e[0m";
    echo 'GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8"' | tee -a /etc/default/grub > /dev/null 2>&1
    update-grub > /dev/null 2>&1
    echo -e "\e[32mconfigure_grubserial()\e[0m";
}

configure_hostapd() {
    /usr/bin/logger 'configure_hostapd()' -t 'Debian-FW-20220213'
    # Install hostapd
    apt-get -qq -y install hostapd > /dev/null 2>&1
    # Create hostapd config file
    cat << __EOF__  >  /etc/hostapd/hostapd.conf
interface=wlp5s0
driver=nl80211

ssid=$mySSID
hw_mode=g
channel=0
max_num_sta=128
auth_algs=1
disassoc_low_ack=1
wpa_ptk_rekey=3600
country_code=$COUNTRY_CODE

ieee80211ac=1
ieee80211n=1

wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=$myWPAPASSPHRASE
wpa_pairwise=CCMP

logger_syslog=127
logger_syslog_level=2
logger_stdout=127
logger_stdout_level=2
__EOF__
    /usr/bin/logger 'configure_hostapd()' -t 'Debian-FW-20220213'
}

install_alerta() {
    /usr/bin/logger 'install_alerta()' -t 'Debian-FW-20220213'
    export DEBIAN_FRONTEND=noninteractive;
    apt-get -qq -y install python3-pip python3-venv > /dev/null 2>&1
    id alerta || (groupadd alerta && useradd -g alerta alerta) > /dev/null 2>&1
    cd /opt > /dev/null 2>&1
    python3 -m venv alerta > /dev/null 2>&1
    /opt/alerta/bin/pip install --upgrade pip wheel > /dev/null 2>&1
    /opt/alerta/bin/pip install alerta > /dev/null 2>&1
    mkdir /home/alerta/ > /dev/null 2>&1
    chown -R alerta:alerta /home/alerta > /dev/null 2>&1
    /usr/bin/logger 'install_alerta() finished' -t 'Debian-FW-20220213'
}

configure_alerta_heartbeat() {
    /usr/bin/logger 'configure_alerta_heartbeat()' -t 'Debian-FW-20220213'
    echo "configure_alerta_heartbeat()";
    export DEBIAN_FRONTEND=noninteractive;
    id alerta || (groupadd alerta && useradd -g alerta alerta);
    mkdir /home/alerta/;
    chown -R alerta:alerta /home/alerta;
    # Create Alerta configuration file
    cat << __EOF__  >  /home/alerta/.alerta.conf
[DEFAULT]
endpoint = http://$ALERTA_SERVER/api
key = $ALERTA_APIKEY
__EOF__

    # Create  Service
    cat << __EOF__  >  /lib/systemd/system/alerta-heartbeat.service
[Unit]
Description=Alerta Heartbeat service
Documentation=https://http://docs.alerta.io/en/latest/deployment.html#house-keeping
Wants=network-online.target

[Service]
User=alerta
Group=alerta
ExecStart=-/opt/alerta/bin/alerta --config-file /home/alerta/.alerta.conf heartbeat --timeout 120
#Restart=always
WorkingDirectory=/home/alerta

[Install]
WantedBy=multi-user.target
__EOF__

   cat << __EOF__  >  /lib/systemd/system/alerta-heartbeat.timer
[Unit]
Description=sends heartbeats to alerta every 60 seconds
Documentation=https://http://docs.alerta.io/en/latest/deployment.html#house-keeping
Wants=network-online.target

[Timer]
OnUnitActiveSec=60s
Unit=alerta-heartbeat.service

[Install]
WantedBy=multi-user.target
__EOF__
    systemctl daemon-reload > /dev/null 2>&1
    systemctl enable alerta-heartbeat.timer > /dev/null 2>&1
    systemctl enable alerta-heartbeat.service > /dev/null 2>&1
    systemctl start alerta-heartbeat.timer > /dev/null 2>&1
    systemctl start alerta-heartbeat.service > /dev/null 2>&1
    echo "configure_alerta_heartbeat() finished";
    /usr/bin/logger 'configure_alerta_heartbeat() finished' -t 'Debian-FW-20220213'
}


#################################################################################################################
## Main Routine                                                                                                 #
#################################################################################################################
main() {

echo -e "\e[32m-----------------------------------------------------\e[0m";
echo -e "\e[32mStarting Installation of Debian-FW-20220213\e[0m";
echo -e "\e[32m-----------------------------------------------------\e[0m";
echo -e;

configure_grubserial;

# Ask for user input
get_information;

# Install and configure the basics
configure_sources;
install_updates;
install_prerequisites;
configure_locale;
configure_timezone;

# Getting the time right
disable_timesyncd;
install_ntp_tools;
install_ntp;
configure_ntp;
configure_update-leap;
configure_dhcp_ntp;

# CrowdSec setup
install_crowdsec;
configure_crowdsec;

# DShield setup
#install_dshield;
#configure_dshield;

# Networking
configure_interfaces;
configure_iptables;
enable_ipforwarding;
configure_dhcp_server;
configure_bind;
configure_threatfox;
configure_resolv;
configure_hostapd;

# CPU
configure_cpu;

# SSH setup
install_SSH_PUBLIC_KEYs;
configure_sshd;
configure_motd;

# Mail setup
configure_exim;

# Logging
## Syslog
configure_rsyslog;
## Filebeat if you run the elastic stack or openstack
#install_filebeat;
#configure_filebeat;
## logrotate
configure_logrotate;

# If using alerta.io install alerta and send heartbeats to alertaserver
#install_alerta;
#configure_alerta_heartbeat;

## Finish with encouraging message, then reboot
echo -e "\e[32mInstallation and configuration of Debian-FW-20220213 complete.\e[0m";
echo -e "\e[1;31mAfter reboot, please verify everything works correctly and that nothing listens on the external interface\e[0m";
echo -e;

finish_reboot;
}

main

exit 0

#################################################################################################
# Information: Use these commands for t-shooting                                                #
#################################################################################################
#
# BIND
# Check zone status
# rndc zonestatus threatfox.rpz
# rndc zonestatus 10.168.192.in-addr.arpa
# systemctl status bind9
# 
#
# Update system
# time (export DEBIAN_FRONTEND=noninteractive; apt update; apt dist-upgrade -y)
#
#################################################################################################
