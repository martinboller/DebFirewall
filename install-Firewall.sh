#!/bin/bash

#####################################################################
#                                                                   #
# Author:       Martin Boller                                       #
#                                                                   #
# Email:        martin@bollers.dk                                   #
# Last Update:  2020-07-06                                          #
# Version:      1.30                                                #
#                                                                   #
# Changes:      Sysfsutils/performance CPU governor (1.30)          #
#               IP forwarding routine (1.20)                        #
#               Added get_information (1.10)                        #
#               Initial version (1.00)                              #
#                                                                   #
#####################################################################

configure_locale() {
    echo -e "\e[32mconfigure_locale()\e[0m";
    echo -e "\e[36m-Configure locale (default:C.UTF-8)\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    update-locale LANG=en_GB.utf8;
    sudo sh -c "cat << EOF  > /etc/default/locale
# /etc/default/locale
LANG=C.UTF-8
LANGUAGE=C.UTF-8
LC_ALL=C.UTF-8
EOF";
    /usr/bin/logger 'configure_locale()' -t 'Debian based Firewall';
}

get_information() {
    echo -e "\e[32mget_information()\e[0m";
    read -s "FQDN of mailserver: "  SMTP_SERVER;
    read -s "Port for mailserver: "  SMTP_SERVER_PORT;
    read -s "Port for mailserver: "  MAIL_ADDRESS;
    read -s "Domain for mailserver: "  MAIL_DOMAIN;
    read -s "Internal Domain: "  INTERNAL_DOMAIN;
    read -s "Firewall host name: "  FIREWALL_NAME;
    read -s "DSHIELD userid: "  DSHIELD_USERID;
    read -s "ALERTA server hostname: "  ALERTA_SERVER;
    read -s "ALERTA API Key: "  ALERTA_APIKEY;
    read -s "ED25519 SSH Public key: "  SSH_KEY;
    /usr/bin/logger 'get_information()' -t 'Debian based Firewall';
}

configure_bind() {
    echo -e "\e[32mconfigure_bind()\e[0m";
    systemctl stop bind9.service;

    echo -e "\e[36m-Configure bind options\e[0m";
    sudo sh -c "cat << EOF  > /etc/bind/named.conf.options
    options {
	directory "/var/cache/bind";

	//========================================================================
	// If BIND logs error messages about the root key being expired,
	// you will need to update your keys.  See https://www.isc.org/bind-keys
	//========================================================================
	dnssec-validation auto;
	
	check-names master ignore;
	auth-nxdomain no;    # conform to RFC1035
	listen-on-v6 { none; };
	listen-on { 127.0.0.1; 192.168.10.1; 192.168.20.1; 192.168.30.1; 192.168.40.1; };
	allow-query { homenet; };
	recursion yes;
	allow-recursion { homenet; };
	allow-query-cache { homenet; };
    ixfr-from-differences yes;
    empty-zones-enable yes;
};
EOF";

    # "local" BIND9 configuration details
    echo -e "\e[36m-Configure bind local\e[0m";
    sudo sh -c "cat << EOF  > /etc/bind/named.conf.local
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
        allow-update { 192.168.0.0/8; };
        allow-transfer { 192.168.10.1; localhost; };
        };

zone "10.168.192.in-addr.arpa" {
        type master;
       	check-names ignore;
//	allow-update { key rndc-key; };	
        allow-update { 192.168.0.0/8; };
        allow-transfer { 192.168.10.1; localhost; };
        file "/var/lib/bind/db.10.168.192.in-addr.arpa";
	};

zone "20.168.192.in-addr.arpa" {
        type master;
        check-names ignore;
//        allow-update { key rndc-key; };
        allow-update { 192.168.0.0/8; };
        allow-transfer { 192.168.10.1; localhost; };
        file "/var/lib/bind/db.20.168.192.in-addr.arpa";
	};

zone "30.168.192.in-addr.arpa" {
        type master;
        check-names ignore;
//        allow-update { key rndc-key; };
        allow-update { 192.168.0.0/8; };
        allow-transfer { 192.168.10.1; localhost; };
        file "/var/lib/bind/db.30.168.192.in-addr.arpa";
        };

zone "40.168.192.in-addr.arpa" {
        type master;
        check-names ignore;
//        allow-update { key rndc-key; };
        allow-update { 192.168.0.0/8; };
        allow-transfer { 192.168.10.1; localhost; };
        file "/var/lib/bind/db.40.168.192.in-addr.arpa";
        };
EOF";

    echo -e "\e[36m-Configure forward lookup zone\e[0m";
    sudo sh -c "cat << EOF  > /var/lib/bind/db.$INTERNAL_DOMAIN
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
EOF";

    echo -e "\e[36m-Configure reverse lookup zones\e[0m";
    # 10.168.192.in-addr.arpa
    sudo sh -c "cat << EOF  > /var/lib/bind/db.10.168.192.in-addr.arpa
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

EOF";

    # 20.168.192.in-addr.arpa
    sudo sh -c "cat << EOF  > /var/lib/bind/db.20.168.192.in-addr.arpa
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

EOF";

    # 30.168.192.in-addr.arpa
    sudo sh -c "cat << EOF  > /var/lib/bind/db.30.168.192.in-addr.arpa
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

EOF";

    # 40.168.192.in-addr.arpa
    sudo sh -c "cat << EOF  > /var/lib/bind/db.40.168.192.in-addr.arpa
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

EOF";
    sync;
    systemctl restart bind9.service;
    /usr/bin/logger 'configure_bind()' -t 'Debian based Firewall';
}

configure_dhcp_server() {
    echo -e "\e[32mconfigure_dhcp_server()\e[0m";
    # Bind generates key at install, use that or generate new in same location
    systemctl stop isc-dhcp.server.service;
    echo -e "\e[36m-Configure dhcpd.conf\e[0m";
    sudo sh -c "cat << EOF  > /etc/dhcp/dhcpd.conf
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
  range 192.168.20.50 192.168.20.254;
  ddns-domainname "$INTERNAL_DOMAIN.";
  ddns-rev-domainname "in-addr.arpa.";
}

# subnet 192.168.30.0
subnet 192.168.30.0 netmask 255.255.255.0 {
  option routers 192.168.30.1;
  option domain-name-servers 192.168.30.1;
  option domain-name "$INTERNAL_DOMAIN";
  range 192.168.30.1 192.168.30.254;
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

EOF";
    sync;
    systemctl restart isc-dhcp.server.service;
    /usr/bin/logger 'configure_dhcp_server()' -t 'Debian based Firewall';
}

install_dshield() {
    echo -e "\e[32minstall_dshield()\e[0m";
    mkdir /usr/local/dshield;
    cd /usr/local/dshield;
    wget -O /usr/local/dshield https://isc.sans.edu/clients/framework/iptables.tar.gz
    tar zxvfp iptables.tar.gz;
    mv iptables ./;
    rm iptables.tar.gz;
    cd ~;
    /usr/bin/logger 'install_dshield()' -t 'Debian based Firewall';
}

configure_dshield() {
    echo -e "\e[32mconfigure_dshield()\e[0m";
    # copy default dshield files
    /usr/bin/cp /usr/local/dshield/dshield* /etc/;
    # Mail address for DSHIELD
    /usr/bin/sed -ie s/from=nobody\@nowhere.com/from=$MAIL_ADDRESS/g /etc/dshield.cnf;
    # DSHIELD userid
    /usr/bin/sed -ie s/userid=0/userid=$DSHIELD_USERID/g /etc/dshield.cnf;
    #!/bin/sh

    sudo sh -c "cat << EOF  > /etc/cron.hourly/dshield
#!/bin/sh
/usr/local/dshield/iptables.pl
/usr/bin/logger 'Processed iptables and sent to dshield' -t 'dshield';
exit 0
EOF";
    sync;
    chmod +x /etc/cron.hourly/dshield;

    /usr/bin/logger 'configure_dshield()' -t 'Debian based Firewall';
}

configure_rsyslog() {
    echo -e "\e[32mconfigure_rsyslog()\e[0m";
    # Forward all logs to Filebeat listening locally on 9001
    echo -e "\e[36m-Configure syslog to filebeat\e[0m";
    sudo sh -c "cat << EOF  > /etc/rsyslog.d/02-filebeat.conf
if $msg contains "iptables:" then
*.* @127.0.0.1:9001
EOF";
    # Writing iptables logdata to separate file
    echo -e "\e[36m-Configure syslog to filebeat\e[0m";
    sudo sh -c "cat << EOF  > /etc/rsyslog.d/30-iptables.conf
:msg,contains,"iptables:" /var/log/iptables.log
& stop
EOF";
    sync;
    systemctl restart rsyslog.service;
    /usr/bin/logger 'configure_rsyslog()' -t 'Debian based Firewall';
}

configure_exim() {
    echo -e "\e[32mconfigure_exim()\e[0m";
    
    echo -e "\e[36m-Configure exim4.conf.conf\e[0m";
    sudo sh -c "cat << EOF  > /etc/exim4/update-exim4.conf.conf
# /etc/exim4/update-exim4.conf.conf
#
# Edit this file and /etc/mailname by hand and execute update-exim4.conf
# yourself or use 'dpkg-reconfigure exim4-config'
#
# Please note that this is _not_ a dpkg-conffile and that automatic changes
# to this file might happen. The code handling this will honor your local
# changes, so this is usually fine, but will break local schemes that mess
# around with multiple versions of the file.
#
# update-exim4.conf uses this file to determine variable values to generate
# exim configuration macros for the configuration file.
#
# Most settings found in here do have corresponding questions in the
# Debconf configuration, but not all of them.
#
# This is a Debian specific file

dc_eximconfig_configtype='smarthost'
dc_other_hostnames=''
dc_local_interfaces='127.0.0.1'
dc_readhost='$MAIL_DOMAIN'
dc_relay_domains=''
dc_minimaldns='false'
dc_relay_nets='192.168.10.0/24, 192.168.20.0/24, 192.168.30.0/24, 192.168.40.0/24'
dc_smarthost='$MAIL_SERVER::$MAIL_SERVER_PORT'
CFILEMODE='644'
dc_use_split_config='true'
dc_hide_mailname='true'
dc_mailname_in_oh='true'
dc_localdelivery='mail_spool'
EOF";

    echo -e "\e[36m-Configure mail access\e[0m";
    sudo sh -c "cat << EOF  > /etc/exim4/passwd.client
    # password file used when the local exim is authenticating to a remote
# host as a client.
#
# see exim4_passwd_client(5) for more documentation
#
# Example:
### target.mail.server.example:login:password
$SMTP_SERVER:$MAIL_ADDRESS:$MAIL_PASSWORD
EOF";

    echo -e "\e[36m-Configure mail addresses\e[0m";
    sudo sh -c "cat << EOF  > /etc/email-addresses
# This is /etc/email-addresses. It is part of the exim package
#
# This file contains email addresses to use for outgoing mail. Any local
# part not in here will be qualified by the system domain as normal.
#
# It should contain lines of the form:
#
#user: someone@isp.com
#otheruser: someoneelse@anotherisp.com
<my local user>: $MAIL_ADDRESS
root: $MAIL_ADDRESS
EOF";

    # Time to reconfigure exim4 - Just accept the defaults
    dpgk-reconfigure exim4-config;
    /usr/bin/logger 'configure_exim()' -t 'Debian based Firewall';
}

install_filebeat() {
    export DEBIAN_FRONTEND=noninteractive;
    # Install key and apt source for elastic
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    #apt-key adv --fetch-keys https://artifacts.elastic.co/GPG-KEY-elasticsearch;
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list;
    apt-get update;
    apt-get -y install filebeat;
    systemctl daemon-reload;
    systemctl enable filebeat.service;
    /usr/bin/logger 'install_filebeat()' -t 'Debian based Firewall';
}

configure_filebeat() {
    echo -e "\e[32mconfigure_filebeat()\e[0m";
    echo -e "\e[36m-configure Logstash server for Filebeat\e[0m";
    # Depends on your individual setup, follow Elastic guidance and change as required in iptables.rules
    systemctl start filebeat.service;
    /usr/bin/logger 'configure_filebeat()' -t 'Debian based Firewall';
}

configure_timezone() {
    echo -e "\e[32mconfigure_timezone()\e[0m";
    echo -e "\e[36m-Set timezone to Etc/UTC\e[0m";
    # Setting timezone to UTC
    export DEBIAN_FRONTEND=noninteractive;
    sudo rm /etc/localtime
    sudo sh -c "echo 'Etc/UTC' > /etc/timezone";
    sudo dpkg-reconfigure -f noninteractive tzdata;
    /usr/bin/logger 'configure_timezone()' -t 'Debian based Firewall';
}

install_prerequisites() {
    echo -e "\e[32minstall_prerequisites()\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    sudo sync \
    && echo -e "\e[36m-prerequisites...\e[0m" && sudo apt-get install libio-socket-ssl-perl libnet-ssleay-perl bind9 isc-dhcp-server exim4 sysfsutils;
    systemctl daemon-reload;
    systemctl enable bind9.service;
    systemctl enable isc-dhcp-server.service;
    /usr/bin/logger 'install_prerequisites()' -t 'Debian based Firewall';
}

configure_cpu() {
    echo -e "\e[32mconfigure_cpu()\e[0m";
    echo -e "\e[36m-CPU performance governoer\e[0m";
    sudo sh -c "cat << EOF  >> /etc/sysfs.conf
## Configure AMD Jaguar to run all cores at 1Ghz
devices/system/cpu/cpu0/cpufreq/scaling_governor = performance
devices/system/cpu/cpu1/cpufreq/scaling_governor = performance
devices/system/cpu/cpu2/cpufreq/scaling_governor = performance
devices/system/cpu/cpu3/cpufreq/scaling_governor = performance
EOF";
    sync;
    /usr/bin/logger 'configure_ipfwd()' -t 'Debian based Firewall';
}

configure_ipfwd() {
    echo -e "\e[32mconfigure_ipfwd()\e[0m";
    echo -e "\e[36m-Enabling IPv4 Forwarding\e[0m";
    /usr/bin/sed -ie s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g /etc/sysctl.conf
    # The current ruleset is IPv4 only, so do NOT enable Ipv6 forwarding just yet
    #/usr/bin/sed -ie s/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/g /etc/sysctl.conf
    sync;
    /usr/bin/logger 'configure_ipfwd()' -t 'Debian based Firewall';
}

configure_resolv() {
    echo -e "\e[32mconfigure_resolv()\e[0m";
    echo -e "\e[36m-Configuring resolv.conf\e[0m";
    # DHCP changes your resolv.conf to use the ISPs dns and search order, so let's make sure we always use local BIND9
    sudo sh -c "cat << EOF  > /etc/resolv.conf
domain $INTERNAL_DOMAIN
search $INTERNAL_DOMAIN
# BIND9 configured to listen on localhost
nameserver 127.0.0.1
EOF";
    sync;
    # Make it immutable or these changes will be overwritten
    /usr/bin/chattr +i /etc/resolv.conf
    /usr/bin/logger 'configure_resolv()' -t 'Debian based Firewall';    
}

install_updates() {
    echo -e "\e[32minstall_updates()\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    sudo sync \
    && echo -e "\e[36m-update...\e[0m" && sudo apt-get update \
    && echo -e "\e[36m-upgrade...\e[0m" && sudo apt-get -y upgrade \
    && echo -e "\e[36m-dist-upgrade...\e[0m" && sudo apt-get -y dist-upgrade \
    && echo -e "\e[36m-autoremove...\e[0m" && sudo apt-get -y --purge autoremove \
    && echo -e "\e[36m-autoclean...\e[0m" && sudo apt-get autoclean \
    && echo -e "\e[36m-Done.\e[0m" \
    && sudo sync;
    /usr/bin/logger 'install_updates()' -t 'Debian based Firewall';
}

install_ntp_tools() {
    echo -e "\e[32minstall_ntp_tools()\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    sudo apt-get -y install ntpstat ntpdate;
    /usr/bin/logger 'install_ntp_tools()' -t 'Debian based Firewall';
}

install_ntp() {
    echo -e "\e[32minstall_ntp()\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    sudo apt-get -y install ntp;
    /usr/bin/logger 'install_ntp()' -t 'Debian based Firewall';
}

configure_ntp() {
    echo -e "\e[32mconfigure_ntp()\e[0m";
    echo -e "\e[36m-Stop ntpd\e[0m";
    sudo systemctl stop ntp.service;

    echo -e "\e[36m-Create new ntp.conf\e[0m";

    sudo sh -c "cat << EOF  > /etc/ntp.conf
##################################################
#
# NTP Setup for Debian based Firewall
# Add local NTP servers if you have any.
#      /etc/ntp.conf
#
##################################################

driftfile /var/lib/ntp/ntp.drift

# Statistics will be logged. Comment out next line to disable
statsdir /var/log/ntpstats/
statistics loopstats peerstats clockstats
filegen  loopstats  file loopstats  type week  enable
filegen  peerstats  file peerstats  type week  enable
filegen  clockstats  file clockstats  type week  enable

# Separate logfile for NTPD
logfile /var/log/ntpd/ntpd.log
logconfig =syncevents +peerevents +sysevents +allclock

# NTP Servers on own network
#server 192.168.10.2 iburst prefer
#server 192.168.30.2 iburst 

# Stratum-1 Servers to sync with - pick 4 to 6 good ones from
# http://support.ntp.org/bin/view/Servers/
#
# DK - Denmark
server ntp01.algon.dk iburst
server ntp2.sptime.se iburst
#server 80.71.132.103 iburst

# DE - Germany
server ntp2.fau.de iburst
server clock2.infonet.ee iburst
server rustime01.rus.uni-stuttgart.de  iburst
server ntp01.hoberg.ch iburst

# Access control configuration; see /usr/share/doc/ntp-doc/html/accopt.html for
# details.  The web page <http://support.ntp.org/bin/view/Support/AccessRestrictions>
# might also be helpful.
#
# Note that restrict applies to both servers and clients, so a configuration
# that might be intended to block requests from certain clients could also end
# up blocking replies from your own upstream servers.

# By default, exchange time with everybody, but do not allow configuration.
restrict -4 default kod notrap nomodify nopeer noquery
restrict -6 default kod notrap nomodify nopeer noquery

# Local users may interrogate the ntp server more closely.
restrict 127.0.0.1
restrict ::1

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
#leap file location
leapfile /var/lib/ntp/leap-seconds.list
EOF";

    # Create folder for logfiles and let ntp own it
    echo -e "\e[36m-Create folder for logfiles and let ntp own it\e[0m";
    sudo mkdir /var/log/ntpd
    sudo chown ntp /var/log/ntpd
    sync;    
    ## Restart NTPD
    sudo systemctl restart ntp.service;
    /usr/bin/logger 'configure_ntp()' -t 'Debian based Firewall';
}

configure_update-leap() {
    echo -e "\e[32mconfigure_update-leap()\e[0m";
    echo -e "\e[36m-Creating service unit file\e[0m";

    sudo sh -c "cat << EOF  > /lib/systemd/system/update-leap.service
# service file running update-leap
# triggered by update-leap.timer

[Unit]
Description=service file running update-leap
Documentation=man:update-leap

[Service]
User=ntp
Group=ntp
ExecStart=-/usr/bin/update-leap -F -f /etc/ntp.conf -s http://www.ietf.org/timezones/data/leap-seconds.list /var/lib/ntp/leap-seconds.list
WorkingDirectory=/var/lib/ntp/

[Install]
WantedBy=multi-user.target
EOF";

   echo -e "\e[36m-creating timer unit file\e[0m";

   sudo sh -c "cat << EOF  > /lib/systemd/system/update-leap.timer
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
EOF";

    sync;
    echo -e "\e[36m-Get initial leap file and making sure timer and service can run\e[0m";
    wget -O /var/lib/ntp/leap-seconds.list http://www.ietf.org/timezones/data/leap-seconds.list;
    chmod +x /usr/local/bin/update-leap;
    sudo /usr/local/bin/update-leap;
    sudo systemctl daemon-reload;
    sudo systemctl enable update-leap.timer;
    sudo systemctl enable update-leap.service;
    sudo systemctl daemon-reload;
    sudo systemctl start update-leap.timer;
    sudo systemctl start update-leap.service;
    /usr/bin/logger 'configure_update-leap()' -t 'Debian based Firewall';
}

configure_iptables() {
    echo -e "\e[32mconfigure_iptables()\e[0m";
    echo -e "\e[32m-Creating iptables rules file\e[0m";
    sudo sh -c "cat << EOF  >> /etc/network/iptables.rules
# Debian Buster based Firewall
# IPTABLES Ruleset
# Author: Martin Boller 2019
# 
# Based on the 2016 work by Joff Thyer, BHIS
# 
# Version 2.0 / 2019-11-29 (APU4 firewall)

*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]

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
#-A INPUT -s 92.119.160.90 -j LOG_DROPS

## Pass everything on loopback
-A INPUT -i lo -j ACCEPT

## DNS on all interfaces (NOT recommended)
#-A INPUT -p udp --dport 53 -j ACCEPT
#-A INPUT -p tcp --dport 53 -j ACCEPT

## dns, dhcp, ntp, squid, icmp-echo
-A INPUT ! -i enp1s0 -p udp --dport 53 -j ACCEPT
-A INPUT ! -i enp1s0 -p tcp --dport 53 -j ACCEPT
-A INPUT ! -i enp1s0 -p udp --dport 67:68 -j ACCEPT
-A INPUT ! -i enp1s0 -p udp --dport 123 -j ACCEPT
## Allow DNS over TLS
-A INPUT ! -i enp1s0 -p tcp --dport 853 -j ACCEPT

## Allowing 123/udp both direction so we can be an NTP Server on the Internet too - for when You're a stratum1 server only
#-A INPUT -i enp1s0 -p udp --dport 123 -j ACCEPT
#-A OUTPUT -o enp1s0 -p udp --sport 123 -j ACCEPT
-A INPUT ! -i enp1s0 -p tcp --dport 3128 -j ACCEPT
-A INPUT ! -i enp1s0 -p icmp -j ACCEPT

# NFS Client
#-A OUTPUT -p tcp --dport 2049 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#-A INPUT -p tcp --sport 2049 -m state --state ESTABLISHED -j ACCEPT
#-A OUTPUT -p udp --dport 2049 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#-A INPUT -p udp --sport 2049 -m state --state ESTABLISHED -j ACCEPT

## SSH on internal interfaces
-A INPUT -i enp2s0 -p tcp --dport 22 -j ACCEPT
-A INPUT -i enp3s0 -p tcp --dport 22 -j ACCEPT
-A INPUT -i enp4s0 -p tcp --dport 22 -j ACCEPT
-A INPUT -i wlan0 -p tcp --dport 22 -j ACCEPT
-A OUTPUT -p tcp --dport 22 -j ACCEPT

## RSYSLOG output to remote syslog - now changed to syslog
#-A INPUT -i enp2s0 -p tcp --dport 5000 -j ACCEPT
#-A OUTPUT -p tcp --dport 5000 -j ACCEPT

## File- and Metricbeat output to logstash on port 6055
-A INPUT -i enp2s0 -p tcp --dport 6055 -j ACCEPT
#-A INPUT -i enp3s0 -p tcp --dport 6055 -j ACCEPT
-A OUTPUT -p tcp --dport 6055 -j ACCEPT

## Outbound initiated by gateway to internet
-A OUTPUT -o lo -j ACCEPT
#
-A OUTPUT -p tcp --dport 53 -j ACCEPT
-A OUTPUT -p udp --dport 53 -j ACCEPT
-A OUTPUT -o enp1s0 -p tcp --dport 43 -j ACCEPT
-A OUTPUT -o enp1s0 -p tcp --dport 80 -j ACCEPT
-A OUTPUT -o enp1s0 -p udp --dport 123 -j ACCEPT
-A OUTPUT -o enp1s0 -p udp --sport 123 -j ACCEPT
-A OUTPUT -o enp1s0 -p tcp --dport 443 -j ACCEPT
-A OUTPUT -o enp1s0 -p tcp --dport 587 -j ACCEPT
# DHCP as inet side uses DHCP
-A OUTPUT -o enp1s0 -p udp --sport 67:68 -j ACCEPT

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
-A LOG_DROPS -p ip -m limit --limit 60/sec -j LOG --log-prefix "iptables:" --log-level 7
-A LOG_DROPS -j DROP

## Commit all of the above rules
COMMIT
EOF";

    echo -e "\e[36m-Script applying iptables rules\e[0m";
    sudo sh -c "cat << EOF  >> /etc/network/if-up.d/firewallrules
#!/bin/sh
iptables-restore < /etc/network/iptables.rules
exit 0
EOF";
    sync;
    ## make the script executable
    chmod +x /etc/network/if-up.d/firewallrules

    sudo sh -c "cat << EOF  >> /etc/network/iptables.rules
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo enp1s0 enp2s0 enp3s0 enp4s0 wlp5s0

# Loopback interface
iface lo inet loopback

# add itables rules pre-nics and add routes for blackhole
pre-up iptables-restore </etc/network/iptables.rules
up route add -net 10.0.0.0/8 gw 127.0.0.1 metric 200
up route add -net 172.16.0.0/12 gw 127.0.0.1 metric 200
#up route add -net 192.168.0.0/16 gw 127.0.0.1 metric 200
up route add -net 224.0.0.0/4 gw 127.0.0.1 metric 200

# The primary network interface
# WAN - Internet side
allow-hotplug enp1s0
iface enp1s0 inet dhcp
# Actived with MAC Address 00:20:91:97:dc:95 - change permanent MAC
hwaddress ether 00:20:91:97:dc:95
dns-nameservers 192.168.10.1, 192.168.20.1

allow-hotplug enp2s0
iface enp2s0 inet static
  address 192.168.10.1
  network 192.168.10.0
  netmask 255.255.255.0
  dns-nameservers 192.168.10.1

allow-hotplug enp3s0
iface enp3s0 inet static
  address 192.168.20.1
  network 192.168.20.0
  netmask 255.255.255.0
  dns-nameservers 192.168.20.1

allow-hotplug enp4s0
iface enp4s0 inet static
  address 192.168.30.1
  network 192.168.30.0
  netmask 255.255.255.0
  dns-nameservers 192.168.30.1

allow-hotplug wlan0
iface wlan0 inet static
  address 192.168.40.1
  network 192.168.40.0
  netmask 255.255.255.0
  dns-nameservers 192.168.40.1
  EOF";
    /usr/bin/logger 'configure_iptables()' -t 'Debian based Firewall';
}

configure_interfaces() {
    echo -e "\e[32mconfigure_interfaces()\e[0m";
    echo -e "\e[36m-Create interfaces file\e[0m";
    ## Important this will overwrite your current interfaces file and may mess with all your networking on this system
    sudo sh -c "cat << EOF  >> /etc/network/interfaces
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo enp1s0 enp2s0 enp3s0 enp4s0 wlan0

# Loopback interface
iface lo inet loopback

# add itables rules 'pre-up' and add routes for blackhole
pre-up iptables-restore </etc/network/iptables.rules
up route add -net 10.0.0.0/8 gw 127.0.0.1 metric 200
up route add -net 172.16.0.0/12 gw 127.0.0.1 metric 200
#up route add -net 192.168.0.0/16 gw 127.0.0.1 metric 200
up route add -net 224.0.0.0/4 gw 127.0.0.1 metric 200

# The primary network interface
# WAN - Internet side
allow-hotplug enp1s0
iface enp1s0 inet dhcp
# If your ISP require a specific MAC address - change permanent MAC
  #hwaddress ether 00:20:DE:AD:BE:EF
  dns-nameservers 127.0.0.1

allow-hotplug enp2s0
iface enp2s0 inet static
  address 192.168.10.1
  network 192.168.10.0
  netmask 255.255.255.0
  dns-nameservers 192.168.10.1

allow-hotplug enp3s0
iface enp3s0 inet static
  address 192.168.20.1
  network 192.168.20.0
  netmask 255.255.255.0
  dns-nameservers 192.168.20.1

allow-hotplug enp4s0
iface enp4s0 inet static
  address 192.168.30.1
  network 192.168.30.0
  netmask 255.255.255.0
  dns-nameservers 192.168.30.1

allow-hotplug wlan0
iface wlan0 inet static
  address 192.168.40.1
  network 192.168.40.0
  netmask 255.255.255.0
  dns-nameservers 192.168.40.1
EOF";
    /usr/bin/logger 'configure_interfaces()' -t 'Debian based Firewall';
}

configure_motd() {
    echo -e "\e[32mconfigure_motd()\e[0m";
    echo -e "\e[36m-Create motd file\e[0m";
    sudo sh -c "cat << EOF  >> /etc/motd

*******************************************
***                                     ***
***              Firewall               ***
***      ------------------------       ***          
***        PC Engines APU4C4 FW         ***
***                                     ***
***       Version 1.20 Dec 2019         ***
***                                     ***
********************||*********************
             (\__/) ||
             (•ㅅ•) ||
            /  　  づ
EOF";
    
    sync;
    /usr/bin/logger 'configure_motd()' -t 'Debian based Firewall';
}

install_ssh_keys() {
    echo -e "\e[32minstall_ssh_keys()\e[0m";
    echo -e "\e[36m-Add public key to authorized_keys file\e[0m";
    # Echo add SSH public key for root logon - change this to your own key
    sudo mkdir /root/.ssh
    echo "ssh-ed25519 $SSH_KEY" | sudo tee -a /root/.ssh/authorized_keys
    sudo chmod 700 /root/.ssh
    sudo chmod 600 /root/.ssh/authorized_keys
    sync;
    /usr/bin/logger 'install_ssh_keys()' -t 'Debian based Firewall';
}

configure_sshd() {
    echo -e "\e[32mconfigure_sshd()\e[0m";
    ## Generate new host keys
    echo -e "\e[36m-Delete and recreate host SSH keys\e[0m";
    rm -v /etc/ssh/ssh_host_*;
    dpkg-reconfigure openssh-server;
    sync;
    /usr/bin/logger 'configure_sshd()' -t 'Debian based Firewall';
}

disable_timesyncd() {
    echo -e "\e[32mDisable_timesyncd()\e[0m";
    sudo systemctl stop systemd-timesyncd
    sudo systemctl daemon-reload
    sudo systemctl disable systemd-timesyncd
    /usr/bin/logger 'disable_timesyncd()' -t 'Debian based Firewall';
}

configure_dhcp_ntp() {
    echo -e "\e[32mconfigure_dhcp_ntp()\e[0m";
    ## Remove ntp and timesyncd exit hooks to cater for server using DHCP
    echo -e "\e[36m-Remove scripts utilizing DHCP\e[0m";
    sudo rm /etc/dhcp/dhclient-exit-hooks.d/ntp
    sudo rm /etc/dhcp/dhclient-exit-hooks.d/timesyncd
    ## Remove ntp.conf.dhcp if it exist
    echo -e "\e[36m-Removing ntp.conf.dhcp\e[0m";    
    sudo rm /run/ntp.conf.dhcp
    ## Disable NTP option for dhcp
    echo -e "\e[36m-Disable ntp_servers option from dhclient\e[0m";   
    sudo sed -i -e "s/option ntp_servers/#option ntp_servers/" /etc/dhcpcd.conf;
    ## restart NTPD yet again after cleaning up DHCP
    sudo systemctl restart ntp
    /usr/bin/logger 'configure_dhcp_ntp()' -t 'Debian based Firewall';
}

finish_reboot() {
    secs=10
    echo -e;
    echo -e "\e[1;31m--------------------------------------------\e[0m";
        while [ $secs -gt 0 ]; do
            echo -ne "Rebooting in: \e[1;31m$secs seconds\033[0K\r"
            sleep 1
            : $((secs--))
        done;
    sudo sync;
    echo -e
    echo -e "\e[1;31mREBOOTING!\e[0m";
    /usr/bin/logger 'finalized installation of Debian based Firewall' -t 'Debian based Firewall'
    reboot;
}

install_alerta() {
    export DEBIAN_FRONTEND=noninteractive;
    apt-get -y install python3-pip python3-venv;
    id alerta || (groupadd alerta && useradd -g alerta alerta);
    cd /opt;
    python3 -m venv alerta;
    /opt/alerta/bin/pip install --upgrade pip wheel;
    /opt/alerta/bin/pip install alerta;
    mkdir /home/alerta/;
    chown -R alerta:alerta /home/alerta;
}

configure_heartbeat() {
    echo "Configure Heartbeat Alerts on Alerta Server";
    export DEBIAN_FRONTEND=noninteractive;
    id alerta || (groupadd alerta && useradd -g alerta alerta);
    mkdir /home/alerta/;
    chown -R alerta:alerta /home/alerta;
    # Create Alerta configuration file
    sudo sh -c "cat << EOF  >  /home/alerta/.alerta.conf
[DEFAULT]
endpoint = http://$ALERTA_SERVER/api
key = $ALERTA_APIKEY
EOF";

    # Create  Service
    sudo sh -c "cat << EOF  >  /lib/systemd/system/alerta-heartbeat.service
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
EOF";

   sudo sh -c "cat << EOF  >  /lib/systemd/system/alerta-heartbeat.timer
[Unit]
Description=sends heartbeats to alerta every 60 seconds
Documentation=https://http://docs.alerta.io/en/latest/deployment.html#house-keeping
Wants=network-online.target

[Timer]
OnUnitActiveSec=60s
Unit=alerta-heartbeat.service

[Install]
WantedBy=multi-user.target
EOF";
    systemctl daemon-reload;
    systemctl enable alerta-heartbeat.timer;
    systemctl enable alerta-heartbeat.service;
    systemctl start alerta-heartbeat.timer;
    systemctl start alerta-heartbeat.service;
    /usr/bin/logger 'Configured heartbeat service' -t 'Alerta Server)';
}


#################################################################################################################
## Main Routine                                                                                                 #
#################################################################################################################
main() {

echo -e "\e[32m-----------------------------------------------------\e[0m";
echo -e "\e[32mStarting Installation of Debian based Firewall\e[0m";
echo -e "\e[32m-----------------------------------------------------\e[0m";
echo -e;

# Ask for user input
get_information;

# Install and configure the basics
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

# DShield setup
install_dshield;
configure_dshield;

# Networking
configure_interfaces;
configure_iptables;
configure_ipfwd;
configure_dhcp_server;
configure_bind;
configure_resolv;

# CPU
configure_cpu;

# SSH setup
install_ssh_keys;
configure_sshd;
configure_motd;

# Mail setup
configure_exim;

# Logging
## Syslog
configure_rsyslog;
## Filebeat
install_filebeat;
configure_filebeat;

# If using alerta.io install alerta and send heartbeats to alertaserver
install_alerta;
configure_heartbeat;

## Finish with encouraging message, then reboot
echo -e "\e[32mInstallation and configuration of Debian based Firewall complete.\e[0m";
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
# Check syslog for 'finalized installation of stratum-1 server'
#   then at least the script finished, but there should also be
#   a log entry for each routine called (main)
#
# dmesg | grep pps
# sudo ppstest /dev/pps0
# sudo ppswatch -a /dev/pps0
#
# sudo gpsd -D 5 -N -n /dev/ttyAMA0 /dev/pps0 -F /var/run/gpsd.sock
# sudo systemctl stop gpsd.*
# sudo killall -9 gpsd
# sudo dpkg-reconfigure -plow gpsd
#
# cgps -s
# gpsmon
# ipcs -m
# ntpshmmon
#
# ntpq -crv -pn
# watch -n 10 'ntpstat; ntpq -p -crv; ntptime;'
#
# If HW clock installed
# dmesg | grep rtc
# hwclock --systohc --utc
# hwclock --show --utc --debug
# cat /sys/class/rtc/rtc0/date
# cat /sys/class/rtc/rtc0/time
# cat /sys/class/rtc/rtc0/since_epoch
# cat /sys/class/rtc/rtc0/name
# i2cdetect -y 1
#
# Update system
# export DEBIAN_FRONTEND=noninteractive; apt update; apt dist-upgrade -y; echo y | rpi-update;
#
#################################################################################################
