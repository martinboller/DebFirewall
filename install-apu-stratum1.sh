#!/bin/bash

#####################################################################
#                                                                   #
# Author:       Martin Boller                                       #
#                                                                   #
# Email:        martin@bollers.dk                                   #
# Last Update:  2020-04-06                                          #
# Version:      1.00                                                #
#                                                                   #
# Changes:      Based on Stratum1 server script (1.00)              #
#                                                                   #
#                                                                   #
# Note: This is adapted from the Raspberry Pi script, adjusted      #
#       for the APU (AMD CPU) systems                               #
#####################################################################

configure_gps() {
    echo -e "\e[32mconfigure_gps()\e[0m";
    ## Install gpsd
    export DEBIAN_FRONTEND=noninteractive;
    echo -e "\e[36m-Install gpsd\e[0m";
    sudo apt-get -y install gpsd gpsd-clients;
    ## Setup GPSD
    echo -e "\e[36m-Setup gpsd\e[0m";
    sudo systemctl stop gpsd.socket;
    sudo systemctl stop gpsd.service;
    sudo sh -c "cat << EOF  > /etc/default/gpsd
# /etc/default/gpsd
## Stratum1
START_DAEMON="true"
GPSD_OPTIONS="-n"
DEVICES="/dev/gps0 /dev/gpspps0"
USBAUTO="false"
GPSD_SOCKET="/var/run/gpsd.sock"
EOF";
    sync;
    sudo systemctl daemon-reload;
    sudo systemctl restart gpsd.service;
    sudo systemctl restart gpsd.socket;
    ## Configure GPSD socket
    grep -q Stratum1 /lib/systemd/system/gpsd.socket 2> /dev/null || {
        echo -e "\e[36m-Ensure that gpsd listens to all connection requests\e[0m";
        sudo sed /lib/systemd/system/gpsd.socket -i -e "s/ListenStream=127.0.0.1:2947/ListenStream=0.0.0.0:2947/";
        sudo sh -c "cat << EOF  >> /lib/systemd/system/gpsd.socket
;; Stratum1
EOF";
    }

    grep -q Stratum1 /etc/rc.local 2> /dev/null || {
        echo -e "\e[36m-Tweak GPS device at start up\e[0m";
        sudo sed /etc/rc.local -i -e "s/^exit 0$//";
        printf "## Stratum1
systemctl stop gpsd.socket;
systemctl stop gpsd.service;

# default GPS device settings at power on
stty -F /dev/ttyS2 9600
sleep 10
systemctl restart gpsd.service;
systemctl restart gpsd.socket;
sleep 2
# Force gps service to wakeup
gpspipe -r -n 1 &

exit 0
" | sudo tee -a /etc/rc.local > /dev/null;
    }

    [ -f "/etc/dhcp/dhclient-exit-hooks.d/ntp" ] && {
        sudo rm -f /etc/dhcp/dhclient-exit-hooks.d/ntp;
    }

    [ -f "/etc/udev/rules.d/99-gps.rules" ] || {
        echo -e "\e[36m-create rule to create symbolic link\e[0m";
        sudo sh -c "cat << EOF  > /etc/udev/rules.d/99-gps.rules
## Stratum1
KERNEL=="pps4",SYMLINK+="gpspps0"
KERNEL=="ttyS2", SYMLINK+="gps0"
KERNEL=="ttyS2", RUN+="/bin/setserial -v /dev/%k low_latency"
KERNEL=="ttyS2", RUN+="/usr/sbin/ldattach pps /dev/%k"
EOF";
    }
    /usr/bin/logger 'configure_gps()' -t 'Stratum1 NTP Server';
}

configure_pps() {
    echo -e "\e[32mconfigure_pps()\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    ## Install pps tools
    echo -e "\e[36m-Install PPS tools\e[0m";
    sudo apt-get -y install pps-tools;
    }
    /usr/bin/logger 'configure_pps()' -t 'Stratum1 NTP Server';
}

install_ntp_tools() {
    echo -e "\e[32minstall_ntp_tools()\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    sudo apt-get -y install ntpstat ntpdate;
    /usr/bin/logger 'install_ntp_tools()' -t 'Stratum1 NTP Server';
}

install_ntp() {
    echo -e "\e[32minstall_ntp()\e[0m";
    export DEBIAN_FRONTEND=noninteractive;
    sudo apt-get -y install ntp;
    /usr/bin/logger 'install_ntp()' -t 'Stratum1 NTP Server';
}

configure_ntp() {
    echo -e "\e[32mconfigure_ntp()\e[0m";
    echo -e "\e[36m-Stop ntpd\e[0m";
    sudo systemctl stop ntp.service;

    echo -e "\e[36m-Create new ntp.conf\e[0m";

    sudo sh -c "cat << EOF  > /etc/ntp.conf
##################################################
#
# GPS / PPS Disciplined NTP Server @ stratum-1
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
logfile /var/log/ntp.log
logconfig =syncevents +peerevents +sysevents +allclock

# Driver 20; NMEA(0), /dev/gpsu, /dev/gpsppsu, /dev/gpsu: Generic NMEA GPS Receiver
# http://doc.ntp.org/current-stable/drivers/driver20.html
# time1 time:     Specifies the PPS time offset calibration factor, in seconds and fraction, with default 0.0.
# time2 time:     Specifies the serial end of line time offset calibration factor, in seconds and fraction, with default 0.0.
# stratum number: Specifies the driver stratum, in decimal from 0 to 15, with default 0.
# refid string:   Specifies the driver reference identifier, an ASCII string from one to four characters, with default GPS.
# flag1 0 | 1:    Disable PPS signal processing if 0 (default); enable PPS signal processing if 1.
# flag2 0 | 1:    If PPS signal processing is enabled, capture the pulse on the rising edge if 0 (default); capture on the falling edge if 1.
# flag3 0 | 1:    If PPS signal processing is enabled, use the ntpd clock discipline if 0 (default); use the kernel discipline if 1.
# flag4 0 | 1:    Obscures location in timecode: 0 for disable (default), 1 for enable.

###############################################################################################
# Driver 22 unit 0; kPPS(0), gpsd: /dev/gpspss0: Kernel-mode PPS ref-clock for the precise seconds
# http://doc.ntp.org/current-stable/drivers/driver22.html
# NTPD doesn't go below 3
#
server  127.127.22.4  minpoll 3  maxpoll 3  prefer  true
fudge   127.127.22.4  refid kPPS time1 0.002953
#
# time1 time:     Specifies the time offset calibration factor, in seconds and fraction, with default 0.0.
# time2 time:     Not used by this driver.
# stratum number: Specifies the driver stratum, in decimal from 0 to 15, with default 0.
# refid string:   Specifies the driver reference identifier, an ASCII string from one to four characters, with default PPS.
# flag1 0 | 1:    Not used by this driver.
# flag2 0 | 1:    Specifies PPS capture on the rising (assert) pulse edge if 0 (default) or falling (clear) pulse edge if 1. Not used under Windows - if the special serialpps.sys serial port driver is installed then the leading edge will always be used.
# flag3 0 | 1:    Controls the kernel PPS discipline: 0 for disable (default), 1 for enable. Not used under Windows - if the special serialpps.sys serial port driver is used then kernel PPS will be available and used.
# flag4 0 | 1:    Record a timestamp once for each second if 1. Useful for constructing Allan deviation plots.

###############################################################################################
# Driver 28 unit 0; SHM(0), gpsd: NMEA data from shared memory provided by gpsd
# http://doc.ntp.org/current-stable/drivers/driver28.html
#
server  127.127.28.0  minpoll 4  maxpoll 5  prefer  true
fudge   127.127.28.0  refid SHM0 stratum 5 flag1 1  time1 0.1387804
#
# time1 time:     Specifies the time offset calibration factor, in seconds and fraction, with default 0.0.
# time2 time:     Maximum allowed difference between remote and local clock, in seconds. Values  less 1.0 or greater 86400.0 are ignored, and the default value of 4hrs (14400s) is used instead. See also flag 1.
# stratum number: Specifies the driver stratum, in decimal from 0 to 15, with default 0.
# refid string:   Specifies the driver reference identifier, an ASCII string from one to four characters, with default SHM.
# flag1 0 | 1:    Skip the difference limit check if set. Useful for systems where the RTC backup cannot keep the time over long periods without power and the SHM clock must be able to force long-distance initial jumps. Check the difference limit if cleared (default).
# flag2 0 | 1:    Not used by this driver.
# flag3 0 | 1:    Not used by this driver.
# flag4 0 | 1:    If flag4 is set, clockstats records will be written when the driver is polled.

# Driver 28 Unit 2; SHM(2), gpsd: PPS data from shared memory provided by gpsd
# http://doc.ntp.org/current-stable/drivers/driver28.html
server  127.127.28.1  minpoll 3  maxpoll 3  true
fudge   127.127.28.1  refid SHM2  stratum 1

# Stratum-1 Servers to sync with - pick 4 to 6 good ones from
# http://support.ntp.org/bin/view/Servers/
#
# Selected for quality
server time.esa.int iburst
server ntps1-1.eecsit.tu-berlin.de iburst
server rustime01.rus.uni-stuttgart.de iburst
server time.antwerpspace.be  iburst
server ntp01.algon.dk iburst
server ntp2.sptime.se iburst
# Internal Stratum-1 server maxpoll 5 (32s) to refresh before ARP times out (60s)
# If you don't have any internal Stratum-1 systems don't do this
server toc.bollers.dk iburst maxpoll 5

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
    sync;    
    ## Restart NTPD
    sudo systemctl restart ntp.service;
    /usr/bin/logger 'configure_ntp()' -t 'Stratum1 NTP Server';
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
    /usr/bin/logger 'configure_update-leap()' -t 'Stratum1 NTP Server';
}

#################################################################################################################
## Main Routine                                                                                                 #
#################################################################################################################
main() {

echo -e "\e[32m-----------------------------------------------------\e[0m";
echo -e "\e[32mStarting Installation of NTP Server\e[0m";
echo -e "\e[32m-----------------------------------------------------\e[0m";
echo -e;

configure_gps;

configure_pps;

configure_ntp;

## Finish with encouraging message, then reboot
echo -e "\e[32mInstallation and configuration of Stratum-1 server complete.\e[0m";
echo -e "\e[1;31mAfter reboot, please verify GPSD and NTPD operation\e[0m";
echo -e;

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
# sudo ppstest /dev/gpspss0
# sudo ppswatch -a /dev/gpspss0
#
# sudo gpsd -D 5 -N -n /dev/ttyS2 /dev/gpspss0 -F /var/run/gpsd.sock
# sudo systemctl stop gpsd.*
# sudo killall -9 gpsd
# sudo dpkg-reconfigure -plow gpsd
#
# cgps -s
# gpsmon
# ipcs -m
# ntpshmmon
#
# ntpq -cmru 
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
# export DEBIAN_FRONTEND=noninteractive; apt update; apt dist-upgrade -y;
#
#################################################################################################
