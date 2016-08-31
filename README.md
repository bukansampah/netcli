## Examples

* telnet to JunOS

    '''
    earth:netcli rendo$ ./netcli.py --ipv4 192.168.1.27 --username admin --password password123 --protocol telnet --cmd "show version | no-more"
    [send->] show version | no-more
    show version | no-more
    Hostname: surabaya
    Model: vmx
    Junos: 15.1F6.9
    JUNOS OS Kernel 64-bit  [20160616.329709_builder_stable_10]
    JUNOS OS libs [20160616.329709_builder_stable_10]
    JUNOS OS runtime [20160616.329709_builder_stable_10]
    JUNOS OS time zone information [20160616.329709_builder_stable_10]
    JUNOS network stack and utilities [20160701.104257_builder_junos_151_f6]
    JUNOS modules [20160701.104257_builder_junos_151_f6]
    JUNOS OS libs compat32 [20160616.329709_builder_stable_10]
    JUNOS OS 32-bit compatibility [20160616.329709_builder_stable_10]
    JUNOS libs compat32 [20160701.104257_builder_junos_151_f6]
    JUNOS runtime [20160701.104257_builder_junos_151_f6]
    JUNOS Packet Forwarding Engine Simulation Package [20160701.104257_builder_junos_151_f6]
    JUNOS py base [20160701.104257_builder_junos_151_f6]
    JUNOS OS vmguest [20160616.329709_builder_stable_10]
    JUNOS OS crypto [20160616.329709_builder_stable_10]
    JUNOS platform support [20160701.104257_builder_junos_151_f6]
    JUNOS libs [20160701.104257_builder_junos_151_f6]
    JUNOS mtx Data Plane Crypto Support [20160701.104257_builder_junos_151_f6]
    JUNOS daemons [20160701.104257_builder_junos_151_f6]
    JUNOS Voice Services Container package [20160701.104257_builder_junos_151_f6]
    JUNOS Services SSL [20160701.104257_builder_junos_151_f6]
    JUNOS Services Stateful Firewall [20160701.104257_builder_junos_151_f6]
    JUNOS Services RPM [20160701.104257_builder_junos_151_f6]
    JUNOS Services PTSP Container package [20160701.104257_builder_junos_151_f6]
    JUNOS Services NAT [20160701.104257_builder_junos_151_f6]
    JUNOS Services Mobile Subscriber Service Container package [20160701.104257_builder_junos_151_f6]
    JUNOS Services MobileNext Software package [20160701.104257_builder_junos_151_f6]
    JUNOS Services LL-PDF Container package [20160701.104257_builder_junos_151_f6]
    JUNOS Services Jflow Container package [20160701.104257_builder_junos_151_f6]
    JUNOS Services IPSec [20160701.104257_builder_junos_151_f6]
    JUNOS IDP Services [20160701.104257_builder_junos_151_f6]
    JUNOS Services HTTP Content Management package [20160701.104257_builder_junos_151_f6]
    JUNOS Services Crypto [20160701.104257_builder_junos_151_f6]
    JUNOS Services Captive Portal and Content Delivery Container package [20160701.104257_builder_junos_151_f6]
    JUNOS Services COS [20160701.104257_builder_junos_151_f6]
    JUNOS Border Gateway Function package [20160701.104257_builder_junos_151_f6]
    JUNOS AppId Services [20160701.104257_builder_junos_151_f6]
    JUNOS Services Application Level Gateways [20160701.104257_builder_junos_151_f6]
    JUNOS Services AACL Container package [20160701.104257_builder_junos_151_f6]
    JUNOS Packet Forwarding Engine Support (M/T Common) [20160701.104257_builder_junos_151_f6]
    JUNOS Online Documentation [20160701.104257_builder_junos_151_f6]
    JUNOS FIPS mode utilities [20160701.104257_builder_junos_151_f6]

    admin@surabaya>
    earth:netcli rendo$
    '''


* telnet to ios-xr

    ```
    earth:netcli rendo$ ./netcli.py --ipv4 192.168.1.29 --username admin --password password123 --protocol telnet --cmd "terminal length 0;show version"
    [send->] terminal length 0
    [send->] show version
    terminal length 0
    Wed Aug 31 02:37:48.871 UTC
    RP/0/0/CPU0:ios#
    show version
    Wed Aug 31 02:37:48.951 UTC

    Cisco IOS XR Software, Version 6.0.1[Default]
    Copyright (c) 2016 by Cisco Systems, Inc.

    ROM: GRUB, Version 1.99(0), DEV RELEASE

    ios uptime is 41 minutes
    System image file is "bootflash:disk0/xrvr-os-mbi-6.0.1/mbixrvr-rp.vm"

    cisco IOS XRv Series (Intel 686 F6M12S2) processor with 3145278K bytes of memory.
    Intel 686 F6M12S2 processor at 2903MHz, Revision 2.174
    IOS XRv Chassis

    3 GigabitEthernet
    1 Management Ethernet
    97070k bytes of non-volatile configuration memory.
    866M bytes of hard disk.
    2321392k bytes of disk0: (Sector size 512 bytes).

    Configuration register on node 0/0/CPU0 is 0x2102
    Boot device on node 0/0/CPU0 is disk0:
    Package active on node 0/0/CPU0:
    iosxr-infra, V 6.0.1[Default], Cisco Systems, at disk0:iosxr-infra-6.0.1
        Built on Mon May  9 12:06:47 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    iosxr-fwding, V 6.0.1[Default], Cisco Systems, at disk0:iosxr-fwding-6.0.1
        Built on Mon May  9 12:06:47 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    iosxr-routing, V 6.0.1[Default], Cisco Systems, at disk0:iosxr-routing-6.0.1
        Built on Mon May  9 12:06:47 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    iosxr-ce, V 6.0.1[Default], Cisco Systems, at disk0:iosxr-ce-6.0.1
        Built on Mon May  9 12:06:48 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    xrvr-os-mbi, V 6.0.1[Default], Cisco Systems, at disk0:xrvr-os-mbi-6.0.1
        Built on Mon May  9 12:07:35 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    xrvr-base, V 6.0.1[Default], Cisco Systems, at disk0:xrvr-base-6.0.1
        Built on Mon May  9 12:06:47 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    xrvr-fwding, V 6.0.1[Default], Cisco Systems, at disk0:xrvr-fwding-6.0.1
        Built on Mon May  9 12:06:48 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    xrvr-mgbl-x, V 6.0.1[Default], Cisco Systems, at disk0:xrvr-mgbl-x-6.0.1
        Built on Mon May  9 12:06:55 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    iosxr-mpls, V 6.0.1[Default], Cisco Systems, at disk0:iosxr-mpls-6.0.1
        Built on Mon May  9 12:06:47 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    iosxr-mgbl, V 6.0.1[Default], Cisco Systems, at disk0:iosxr-mgbl-6.0.1
        Built on Mon May  9 12:06:47 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    iosxr-mcast, V 6.0.1[Default], Cisco Systems, at disk0:iosxr-mcast-6.0.1
        Built on Mon May  9 12:06:48 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    xrvr-mcast-supp, V 6.0.1[Default], Cisco Systems, at disk0:xrvr-mcast-supp-6.0.1
        Built on Mon May  9 12:06:48 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    iosxr-bng, V 6.0.1[Default], Cisco Systems, at disk0:iosxr-bng-6.0.1
        Built on Mon May  9 12:06:45 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    xrvr-bng-supp, V 6.0.1[Default], Cisco Systems, at disk0:xrvr-bng-supp-6.0.1
        Built on Mon May  9 12:06:45 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    iosxr-security, V 6.0.1[Default], Cisco Systems, at disk0:iosxr-security-6.0.1
        Built on Mon May  9 12:06:39 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    xrvr-fullk9-x, V 6.0.1[Default], Cisco Systems, at disk0:xrvr-fullk9-x-6.0.1
        Built on Mon May  9 12:07:39 UTC 2016
        By iox-lnx-003 in /auto/srcarchive12/production/6.0.1/xrvr/workspace for pie

    RP/0/0/CPU0:ios#
    earth:netcli rendo$
    ```


* ssh to JunOS

    ```
    $ ./netcli.py --ipv4 192.168.1.27 --username admin --password password123 --protocol ssh --cmd "show version | no-more"
    ssh - connecting to: 192.168.1.27
    Connected (version 2.0, client OpenSSH_6.6.1)

    Authentication (publickey) failed.
    Authentication (password) successful!
    [send->]show version | no-more
    Hostname: surabaya
    Model: vmx
    Junos: 15.1F6.9
    JUNOS OS Kernel 64-bit  [20160616.329709_builder_stable_10]
    JUNOS OS libs [20160616.329709_builder_stable_10]
    JUNOS OS runtime [20160616.329709_builder_stable_10]
    JUNOS OS time zone information [20160616.329709_builder_stable_10]
    JUNOS network stack and utilities [20160701.104257_builder_junos_151_f6]
    JUNOS modules [20160701.104257_builder_junos_151_f6]
    JUNOS OS libs compat32 [20160616.329709_builder_stable_10]
    JUNOS OS 32-bit compatibility [20160616.329709_builder_stable_10]
    JUNOS libs compat32 [20160701.104257_builder_junos_151_f6]
    JUNOS runtime [20160701.104257_builder_junos_151_f6]
    JUNOS Packet Forwarding Engine Simulation Package [20160701.104257_builder_junos_151_f6]
    JUNOS py base [20160701.104257_builder_junos_151_f6]
    JUNOS OS vmguest [20160616.329709_builder_stable_10]
    JUNOS OS crypto [20160616.329709_builder_stable_10]
    JUNOS platform support [20160701.104257_builder_junos_151_f6]
    JUNOS libs [20160701.104257_builder_junos_151_f6]
    JUNOS mtx Data Plane Crypto Support [20160701.104257_builder_junos_151_f6]
    JUNOS daemons [20160701.104257_builder_junos_151_f6]
    JUNOS Voice Services Container package [20160701.104257_builder_junos_151_f6]
    JUNOS Services SSL [20160701.104257_builder_junos_151_f6]
    JUNOS Services Stateful Firewall [20160701.104257_builder_junos_151_f6]
    JUNOS Services RPM [20160701.104257_builder_junos_151_f6]
    JUNOS Services PTSP Container package [20160701.104257_builder_junos_151_f6]
    JUNOS Services NAT [20160701.104257_builder_junos_151_f6]
    JUNOS Services Mobile Subscriber Service Container package [20160701.104257_builder_junos_151_f6]
    JUNOS Services MobileNext Software package [20160701.104257_builder_junos_151_f6]
    JUNOS Services LL-PDF Container package [20160701.104257_builder_junos_151_f6]
    JUNOS Services Jflow Container package [20160701.104257_builder_junos_151_f6]
    JUNOS Services IPSec [20160701.104257_builder_junos_151_f6]
    JUNOS IDP Services [20160701.104257_builder_junos_151_f6]
    JUNOS Services HTTP Content Management package [20160701.104257_builder_junos_151_f6]
    JUNOS Services Crypto [20160701.104257_builder_junos_151_f6]
    JUNOS Services Captive Portal and Content Delivery Container package [20160701.104257_builder_junos_151_f6]
    JUNOS Services COS [20160701.104257_builder_junos_151_f6]
    JUNOS Border Gateway Function package [20160701.104257_builder_junos_151_f6]
    JUNOS AppId Services [20160701.104257_builder_junos_151_f6]
    JUNOS Services Application Level Gateways [20160701.104257_builder_junos_151_f6]
    JUNOS Services AACL Container package [20160701.104257_builder_junos_151_f6]
    JUNOS Packet Forwarding Engine Support (M/T Common) [20160701.104257_builder_junos_151_f6]
    JUNOS Online Documentation [20160701.104257_builder_junos_151_f6]
    JUNOS FIPS mode utilities [20160701.104257_builder_junos_151_f6]

    earth:netcli rendo$
    ```
