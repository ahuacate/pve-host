<H1>PVE Host Setup and Toolbox</H1>

This guide is about installing PVE host hardware. We recommend you read this guide before attempting a PVE host build.

Our Easy Script Toolbox add-ons make all the required changes and configurations in preparation to support any Ahuacate CT or VM.

It is a mandatory requirement Toolbox add-on 'PVE Basic' is run on all PVE hosts (primary and secondary). PVE Basic includes <span style="color:red">critical PVE Container UID & GID mapping required by all Ahuacate CTs and VMs</span> resolving permission rights for bind-mounted shared data.

<h2>Features</h2>
Toolbox add-ons prepare your PVE hosts to support any Ahuacate CT or VM. Toolbox add-ons include the following tasks:

1. PVE Basic - required by all PVE hosts (mandatory / required)
    - Update Proxmox
    - Check and set Proxmox subscription key (free or enterprise)
    - Install nbtscan SW
    - Adjust sysctl parameters
    - Perform PVE container (CT) mapping
2. PVE Full Build - run all toolbox add-ons
3. PVESM NFS Storage - add additional NFS PVE storage mounts
4. PVESM SMB/CIFS Storage - add additional SMB/CIFS storage mounts
5. PVE Hostname Updater - change the hostname of a node
6. PVE Network Updater - change a hosts network configuration
7. Fail2Ban Installer
8. SSMTP Email Installer
9. SSH Key Installer -  add or create your own private SSH access key

Remember 'PVE Basic' must be run on all PVE hosts.

**Prerequisites**
Network prerequisites are:
- [x] Layer 2/3 Network Switches
- [x] Network Gateway is `XXX.XXX.XXX.5` ( *default is 192.168.1.5* )
- [x] Network DHCP server is `XXX.XXX.XXX.5` ( *default is 192.168.1.5* )
- [x] Internet access for the PVE host

- [x] File server or NAS (i.e NAS-01) . Our default NAS IPv4 address is `XXX.XXX.XXX.10` ( *default is 192.168.1.10* )
- [x] File server or NAS is configured with network shares, either CIFS or NFS, as per these guides:
  - PVE hosted NAS [build guide](https://github.com/ahuacate/pve-nas)
  - OEM (Synology) or Linux NAS [build guide](https://github.com/ahuacate/nas-hardmetal)

Other prerequisites (information the User should have available before starting):

- [ ] SMB/NAS CIFS user account credentials as per these (Only if your adding PVE storage using NAS SMB/CIFS storage mounts)
- [ ] Optional PVE Postfix
  - Email account credentials
  - MailGun account credentials

>Note: The network Local Domain or Search domain must be set. We recommend only top-level domain (spTLD) names for residential and small networks names because they cannot be resolved across the internet. Routers and DNS servers know, in theory, not to forward ARPA requests they do not understand onto the public internet. It is best to choose one of our listed names: local, home.arpa, localdomain or lan only. Do NOT use made-up names.

<h2><b>Easy Scripts</b></h2>

Easy Scripts automate the installation and/or configuration processes. Easy Scripts are hardware type-dependent so choose carefully. Easy Scripts are based on bash scripting. `Cut & Paste` our Easy Script command into a terminal window, press `Enter`, and follow the prompts and terminal instructions. 

Our Easy Scripts have preset configurations. The installer may accept or decline the ES values. If you decline the User will be prompted to input all required configuration settings. PLEASE read our guide if you are unsure.

<h4><b>PVE Host Toolbox Easy Script</b></h4>
Built for any PVE host. You must first SSH login to your PVE host `ssh root@IP_address`. Then you must run the following command.

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-setup/master/pve_host_setup_toolbox.sh)"
```

<hr>

<h4>Table of Contents</h4>

<!-- TOC -->

- [1. Prepare your Hardware](#1-prepare-your-hardware)
    - [1.1. PVE OS Installation](#11-pve-os-installation)
        - [1.1.1. PVE OS Install - Primary & Secondary Host](#111-pve-os-install---primary--secondary-host)
        - [1.1.2. Proxmox VE OS Install - Final Steps](#112-proxmox-ve-os-install---final-steps)
- [2. File Server (NAS)](#2-file-server-nas)
- [3. Network Switch Setup - VLANs, 802.3ad, PfSense, OpenVPN Gateway](#3-network-switch-setup---vlans-8023ad-pfsense-openvpn-gateway)
    - [3.1. Network Options - Ready PVE-01 for pfSense](#31-network-options---ready-pve-01-for-pfsense)
    - [3.2. Network Options - Basic (no pfSense)](#32-network-options---basic-no-pfsense)
    - [3.3. Configure your Network Switch - pfSense](#33-configure-your-network-switch---pfsense)
        - [3.3.1. Set Network Switch port profiles and LAG groups - pfSense](#331-set-network-switch-port-profiles-and-lag-groups---pfsense)
        - [3.3.2. Create Network Switch VLANs - pfSense](#332-create-network-switch-vlans---pfsense)
        - [3.3.3. Setup network switch ports - pfSense](#333-setup-network-switch-ports---pfsense)
        - [3.3.4. Setup network WiFi SSiDs for the VPN service - pfSense](#334-setup-network-wifi-ssids-for-the-vpn-service---pfsense)
        - [3.3.5. Edit your UniFi network firewall - pfSense](#335-edit-your-unifi-network-firewall---pfsense)
- [4. PVE Host Toolbox](#4-pve-host-toolbox)
        - [4.0.6. SMTP Server Credentials](#406-smtp-server-credentials)
    - [4.1. Run our PVE Host Toolbox Easy Script](#41-run-our-pve-host-toolbox-easy-script)
- [5. Other PVE Host Stuff](#5-other-pve-host-stuff)
    - [5.1. Create a PVE Cluster](#51-create-a-pve-cluster)
        - [5.1.1. Create a Cluster](#511-create-a-cluster)
        - [5.1.2. Join the other Nodes to the New Cluster](#512-join-the-other-nodes-to-the-new-cluster)
        - [5.1.3. How to delete an existing cluster on a node](#513-how-to-delete-an-existing-cluster-on-a-node)
- [6. Maintenance Tools](#6-maintenance-tools)
    - [6.1. Toolbox Updater for all CTs OS](#61-toolbox-updater-for-all-cts-os)

<!-- /TOC -->
<hr>

# 1. Prepare your Hardware

PVE hosts can be any x86 hardware with a few conditions. The hardware should have Intel NIC devices (clone NICs seem okay).

In this guide, you have the option to build a PVE host which also serves as a backend NAS with an optional SSD cache. PVE supports ZFS and LVM filesystems which support RAID and any number of storage disks. You can read about our containerized PVE NAS solutions [here](https://github.com/ahuacate/pve-nas) which uses a PVE Ubuntu CT as the frontend.

PVE host hardware with 3x or more Intel ethernet NICs has the option to support the pfSense VM build. With pfSense you can install OpenVPN Gateways, HAProxy servers, and more using multiple NICs and VLANs.

Secondary PVE cluster hosts or nodes need only a 1x ethernet NIC. A minimum of two secondary PVE hosts is required to form a cluster quorum in the event a PVE host fails.

Remember when your primary PVE-01 host goes offline your PfSense services (i.e. OpenVPN, HAProxy) are also offline.

**Primary Host Build** (Could serve as a PVE File Server NAS)
*  Quality Mainboard Hardware
*  4x LAN PCIe Intel I350-T4  (optional)
*  10GbE Intel NIC (optional)
*  CPU support for Intel AES-NI, QAT Crypto (required by pfSense addon service OpenVPN)
*  16Gb RAM (Recommend 32Gb ECC)
*  1x 240Gb Samsung PM883 (Recommend 2x SSDs in Raid1)
*  2x 480Gb Samsung PM883 for Boot & NAS Cache (optional - For NAS backend)
*  6-10TB Rotational Disks (Optional - For NAS backend)

**Secondary Host Build** - Cluster Node Hardware
* Any X86 hardware to complete a 3x PVE host cluster
* Hardware example: Intel Celeron, Pentium, i3/i5/i7 NUC models with minimum 16Gb RAM and 1x LAN 1GbE NIC (Intel NIC)

## 1.1. PVE OS Installation
Go to the Proxmox website and [download](https://www.proxmox.com/en/downloads) the latest ISO and burn it to a USB stick. Instructions are [here](https://pve.proxmox.com/wiki/Prepare_Installation_Media).

In this guide, we refer to SCSi and SATA (Serial ATA) controller devices designated disk names such as `sda`, `sdb`, `sdc` and so on, a generic Linux naming convention, as `sdx` only. Ideally `sda` (and `sdb`) should be allocated as the Proxmox OS SSD device.

Some main boards may not show disk devices as `sda/sdb/sdc` because the SSD is not installed on a SCSi or SATA controller. For example, NVMe drives show as /dev/nvme0(n1..). It's most important to check your hardware device schematics and note which device type is designated to which type of hard drive (SSD) you have installed. 

### 1.1.1. PVE OS Install - Primary & Secondary Host
In this build, you can install 1 or 2 enterprise-grade SSD in your host.

Boot from the Proxmox installation USB stick and configure Proxmox VE as follows:

**Proxmox Virtualization Environment (PVE)** - At this stage you must select your PVE OS installation drives, Raid type and partition sizes. Click 'options' and complete as follows:

| Option                        | Value                 | Notes                                     |
|-------------------------------|-----------------------|-------------------------------------------|
| Filesystem - 1x SSD           | `ext4 or zfs (RAID0)` | *Personally I use ZFS*                    |
| Filesystem - 2x SSD           | `ext4 or zfs (RAID1)` | *Personally I use ZFS - redundancy*       |
| **Disk Setup - SATA**         |                       |                                           |
| Harddisk 0                    | /dev/sdx              |                                           |
| Harddisk 1                    | /dev/sdx              |                                           |
| **Disk Setup - PCIe NVMe**    |                       |                                           |
| Harddisk 0                    | /dev/nvmeXn1          |                                           |
| Harddisk 1                    | /dev/nvmeXn1          |                                           |
| **Advanced Options**          |                       |                                           |
| ashift                        | `12`                  | *4K sector size. For 8K sectors use `13`* |
| compress                      | `lz4`                 |                                           |
| checksum                      | `on`                  |                                           |
| copies                        | `1`                   |                                           |
| SSD size - 240GB (or smaller) | `220`                 | *Over-provisioning to 220GB*              |


### 1.1.2. Proxmox VE OS Install - Final Steps

The final step is to configure a basic network device. If you have multiple onboard ethernet LAN NIC devices, 10GbE ethernet or a multi-port Intel PCIe LAN Card installed, you must choose *one single device only* to configure at this stage.

If you have 10GbE ethernet, on a primary or secondary PVE host, then always select and configure the 10GbE device.

If your PVE host has only 1GbE LAN NICs then you must choose the first ethernet device ID of either an onboard mainboard Intel NIC or if available the first device of your installed Intel PCIe LAN Card. Your decision is based on how many valid (Intel brand) ethernet devices are available ignoring all other brands if you can. For example, if you have an Intel I350-T4 PCIe x4 LAN Card 4x Port installed and 2x onboard **Realtek** NICs, always ignore the 2x **Realtek** devices from all selection criteria. Try to use only Intel NICs whenever possible.

Here's a table to help you understand your options:

|                             | Port 1 | Port 2 | Port 3 | Port 4 | Port 5 | Port 6 |
|-----------------------------|--------|--------|--------|--------|--------|--------|
| 10GbE SFP+                  | ✅      |        |        |        |        |        |
| Onboard x2 (Realtek)        | ❌      | ❌      |        |        |        |        |
| Intel PCIe LAN Card 6x Port | ☑      | ☑      | ☑      | ☑      | ☑      | ☑      |
|                             |        |        |        |        |        |        |
| Onboard x1 (Intel)          | ✅      |        |        |        |        |        |
| Intel PCIe LAN Card 2x Port | ☑      | ☑      |        |        |        |        |
|                             |        |        |        |        |        |        |
| Onboard x2 (Intel)          | ✅      | ☑      |        |        |        |        |
| Intel PCIe LAN Card 2x Port | ☑      | ☑      |        |        |        |        |
|                             |        |        |        |        |        |        |
| Onboard x1 (Realtek)        | ❌      |        |        |        |        |        |
| Intel PCIe LAN Card 4x Port | ✅      | ☑      | ☑      | ☑      |        |        |

Primary PVE hosts must be assigned hostname `pve-01.local`, IPv4 address of `192.168.1.101` or at least denoted by xxx.xxx.xxx.`101`, and if your want to create a pfSense OpenVPN Gateway for your network clients then you must have a minimum of 3x Intel Ethernet LAN NICs available (i.e. PCIe Intel I350-T4 card installed) in your primary host. 

The remaining steps in configuring PVE are self-explanatory. Configure each PVE host as follows:

| Option               | Primary Host            | Secondary Host          | Secondary Host          | Notes                                                                                                                                                                                            |
|----------------------|-------------------------|-------------------------|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Country              | Type your Country       | Type your Country       | Type your Country       |                                                                                                                                                                                                  |
| Timezone             | Select                  | Select                  | Select                  |                                                                                                                                                                                                  |
| Keymap               | `en-us`                 | `en-us`                 | `en-us`                 |                                                                                                                                                                                                  |
| Password             | Enter your new password | Enter your new password | Enter your new password | *Same root password on all nodes*                                                                                                                                                                |
| E-mail               | Enter your Email        | Enter your Email        | Enter your Email        | *You best use a valid email address (recommended). It needs to be valid for PVE Postfix alerts and other email services to work. If you don't want to enter a valid email type mail@example.com* |
| Management interface | Leave Default           | Leave Default           | Leave Default           |                                                                                                                                                                                                  |
| Hostname             | `pve-01.local`          | `pve-02.local`          | `pve-03.local`          | *Note the naming convention and use of 'local'*                                                                                                                                                  |
| IP Address           | `192.168.1.101`         | `192.168.1.102`         | `192.168.1.103`         | *Note the IP number assignments - XXX.XXX.XXX.101 > .102 > .103 >*                                                                                                                               |
| Netmask              | `255.255.255.0`         | `255.255.255.0`         | `255.255.255.0`         |                                                                                                                                                                                                  |
| Gateway              | `192.168.1.5`           | `192.168.1.5`           | `192.168.1.5`           |                                                                                                                                                                                                  |
| DNS Server 1         | `192.168.1.254`         | `192.168.1.254`         | `192.168.1.254`         | *Set to use a PiHole CT at this static IP*                                                                                                                                                       |
| DNS Server 2         | `192.168.1.5`           | `192.168.1.5`           | `192.168.1.5`           | *Set to use your router static IP*                                                                                                                                                               |


# 2. File Server (NAS)

You must have a running network-accessible file server (NAS) that supports NFS and/or CIFS sharing protocol. Proxmox provides storage to VMs by creating a CIFS or NFS backend storage pool by mounting your NAS export shares points.

The NAS server CIFS or NFS properties must be configured so your PVE host backend can mount these NAS shares automatically.

Your options are:

**NAS Appliance** - A NAS of any brand or type (Synology, OMV, QNap, FreeNAS, Windows or Linux server). The NAS must on your available on your LAN network preferably with IPv4 address `XXX.XXX.XXX.10` ( *ahuacate default is 192.168.1.10* ). The NAS must support SMB3, NFSv4.1 and ACL services.

**PVE NAS** - A PVE NAS storage pool using ZFS or LVM Raid (backend) can be hosted on a Proxmox host (preferred pve-01). Frontend management and NAS services are by a PVE Ubuntu CT (hostname label NAS-01). NAS-01 fully supports SMB3, NFSv4.1 and ACL services. A detailed guide with build options is available [here](https://github.com/ahuacate/pve-nas).


# 3. Network Switch Setup - VLANs, 802.3ad, PfSense, OpenVPN Gateway

If you've chosen to install a PfSense and OpenVPN Gateway server on PVE-01 then you must make additional network modifications. Your LAN network switches must be L2/L3 compatible because you need to set up VLANs.

If you followed our guide then your primary host PVE-01 will have a minimum of 3x Ethernet LAN 1GbE NICs. Builds with 5x Ethernet LAN 1GbE NICs enable you to use 802.3ad Dynamic link aggregation to increase performance and reliability.

Secondary hosts only require 1x Ethernet LAN NIC. If you have more NICs available then use 802.3ad Dynamic link aggregation on these hosts too to increase bandwidth.

You should by now have at least your primary host PVE-01 ready and running. In the next steps, we need to configure your LAN network switches to match your PVE hosts' needs.

## 3.1. Network Options - Ready PVE-01 for pfSense

First, decide how many LAN ports you are going to configure on your PVE hosts and network switches. For our PVE-01 pfSense build a minimum of 3x NICs and switch LAN ports is required.

It's important to note there is a PVE Linux Bridge, Bond and VLAN naming convention must be adhered to. This naming convention is used in all our Proxmox builds and Easy Scripts.

On PVE-01 we create the following PVE Linux Bridges which are associated with their VLAN ID. The Linux Network Device name varies because it's determined by the host's mainboard (here we use *enp0s0-enp0s3*). The sample below shows a 3x Ethernet LAN NIC configuration, with an optional 4x NIC configuration for a VPN Local Gateway service,  with no PVE Linux Bonds (LAG-802.3ad). 

| PVE Linux Bridge    | Network Devices | Description                                                                   | VLAN ID |
|---------------------|-----------------|-------------------------------------------------------------------------------|---------|
| vmbr0               | enp0s0          | PVE HOST NIC ( i.e. 192.168.1.101 )                                           | vlan1   |
| vmbr2               | enp0s1          | VPN Gateway Egress (WAN encrypted link to the internet)                       | vlan2   |
| vmbr30              | enp0s2          | VPN World Gateway (LAN gateway for clients to random world VPN servers)       | vlan30  |
| *Below is optional* |                 |                                                                               |         |
| vmbr40              | enp0s3          | VPN Local Gateway (LAN gateway for clients to a local in-country VPN servers) | vlan40  |

The next table illustrates using PVE Linux Bonds (LAG) of 1GbE slaves and a 10GbE SFP+ NIC. Whenever a 10GbE NIC is available always assigned it to PVE host Linux Bridge vmbr0.

Note: Shown below *enp0s0~5* are the hosts 1GbE ethernet NIC devices (Intel PCIe LAN Card 6x Port) and *enp68s0f0* is the 10GbE NIC. Always first create the PVE Linux Bonds and then create the PVE Linux Bridges using the PVE Linux Bonds as the slaves. The above table is an example of the many combinations of network bonds and slaves available to you. But always remember to assign any available 10GbE or the first available PVE Linux Bond to PVE Linux Bridge vmbr0 which is your PVE-01 host LAN.

So with a PVE network configuration plan, you must configure your PVE-01 connected network switch to use VLANs and in a pfSense environment you must also assign specific network switch ports to specific VLAN numbers and in the case of vmbr2 you must assign an IPv4 address. 

Our network is configured to use VLANs in accordance with the network road map shown [here](https://github.com/ahuacate/network-roadmap). 

When PVE hosts have multiple 1GbE NICs you can use NIC bonding (also called NIC teaming or Link Aggregation, LAG and in PVE Linux Network Bond) which is a technique for binding multiple NICs to a single network device. By doing link aggregation, two NICs can appear as one logical interface, resulting in double speed. This is a native Linux kernel feature that is supported by most smart L2/L3 switches with IEEE 802.3ad support.

On the network switch appliance side you are going to use 802.3ad Dynamic link aggregation (802.3ad)(LACP) so your switch must be 802.3ad compliant. This creates aggregation groups of NICs that share the same speed and duplex settings as each other. A link aggregation group (LAG) combines many physical ports to make a single high-bandwidth data path, implement the traffic load sharing among the member ports in the group and enhance connection reliability.

## 3.2. Network Options - Basic (no pfSense)

This is easy. Simply configure PVE Linux Bridge vmbr0 with a single 1GbE, 10GbE, or a PVE Linux Bond for PVE Linux Bridge vmbr0. Nothing more to do. In our Easy Script, you will be prompted for such configurations with no pfSense available.

## 3.3. Configure your Network Switch - pfSense

These instructions are based on an UniFi US-24 port switch. Just transpose the settings to UniFi US-48 or whatever brand of Layer 2/3 Switch you use. The examples are guides for setting up the following network switch configurations:

- 3x LAN 1GbE
- 4x LAN 1Gb PLUS 10GbE SFP+
- 4x LAN 1GbE
- 6x LAN 1GbE

### 3.3.1. Set Network Switch port profiles and LAG groups - pfSense

For ease of port management, I always use switch ports 1 - (4 or 6) for my primary PVE-01. Configure your network switch port profiles and LAG groups as follows:

**Primary Host Build - Type A - Optional PVE NAS** - 3x LAN 1GbE

| UniFi US-24                    | Port ID               | Port ID                | Port ID                |
|--------------------------------|-----------------------|------------------------|------------------------|
| **Port Number**                | 1                     | 2                      | 3                      |
| **LAG Bond**                   |                       |                        |                        |
| **Switch Port Profile / VLAN** | All                   | VPN-egress(2)          | LAN-vpngate-world (30) |
| **LAN cable connected to**     | Port1 ->PVE-01 (NIC1) | Port2 -> PVE-01 (NIC2) | Port3 -> PVE-01 (NIC3) |
| **PVE Linux Bond**             |                       |                        |                        |
| **PVE Bridge**                 | vmbr0                 | vmbr2                  | vmbr30                 |
| **PVE Comment**                | PVE host LAN          | VPN-egress             | vpngate-world          |

Note: The **Switch Port Profile / VLAN** must be first configured in your network switch (UniFi Controller).

**Primary Host Build - Type A - Optional PVE NAS** - 4x LAN 1Gb PLUS 10GbE

| UniFi US-24 Gen2                | SFP+ Port ID            | Port ID                    | Port ID                                         |
|---------------------------------|-------------------------|----------------------------|-------------------------------------------------|
| **Port Number**                 |                         | 1                          | 3                                               |
| **Port Number**                 | 26                      | 2                          | 4                                               |
| **LAG Bond**                    |                         | LAG 1 & 2                  |                                                 |
| **Switch Port Profile / VLAN**  | All                     | VPN-egress (2)             | LAN-vpngate-world (30) :LAN-vpngate-local (40)  |
| **LAN cable connected to**      | N/A                     | Port1+2 -> PVE-01 (NIC1+2) | Port3 -> PVE-01 (NIC3) : Port4 -> PVE-01 (NIC4) |
| **LAN SFP+ cable connected to** | Port 26 > PVE-01 (SFP+) |                            |                                                 |
|                                 |                         |                            |                                                 |
| **Host NIC Ports**              | SFP+                    | Port 1+2                   | Port 3+4                                        |
| **PVE Linux Bond**              |                         | bond2                      |                                                 |
| **PVE Bridge**                  | vmbr0                   | vmbr2                      | vmbr30 : vmbr40                                 |
| **PVE Comment**                 | PVE LAN SFP+            | VPN-egress Bond2           | vpngate-world : vpngate-local                   |

**Primary Host Build - Type A - Optional PVE NAS** - 4x LAN 1GbE

| UniFi US-24                    | Port ID               | Port ID                | Port ID                | Port ID                 |
|--------------------------------|-----------------------|------------------------|------------------------|-------------------------|
| **Port Number**                | 1                     | 2                      | 3                      | 4                       |
| **LAG Bond**                   |                       |                        |                        |                         |
| **Switch Port Profile / VLAN** | All                   | VPN-egress(2)          | LAN-vpngate-world (30) | :LAN-vpngate-local (40) |
| **LAN cable connected to**     | Port1 ->PVE-01 (NIC1) | Port2 -> PVE-01 (NIC2) | Port3 -> PVE-01 (NIC3) | Port4 -> PVE-01 (NIC4)  |
| **PVE Linux Bond**             |                       |                        |                        |                         |
| **PVE Bridge**                 | vmbr0                 | vmbr2                  | vmbr30                 | vmbr40                  |
| **PVE Comment**                | PVE host LAN          | VPN-egress             | vpngate-world          | vpngate-local           |

**Primary Host Build - Type A - Optional PVE NAS** - 6x LAN 1GbE

| UniFi US-24                    | Port ID                    | Port ID                    | Port ID                                         |
|--------------------------------|----------------------------|----------------------------|-------------------------------------------------|
| **Port Number**                | 1                          | 3                          | 5                                               |
| **Port Number**                | 2                          | 4                          | 6                                               |
| **LAG Bond**                   | LAG 1-2                    | LAG 3-4                    |                                                 |
| **Switch Port Profile / VLAN** | All                        | VPN-egress (2)             | LAN-vpngate-world (30) : LAN-vpngate-local (40) |
| **LAN cable connected to**     | Port1+2 -> pve-01 (NIC1+2) | Port3+4 -> pve-01 (NIC3+4) | Port5 -> pve-01 (NIC5) : Port6 -> pve-01 (NIC6) |
|                                |                            |                            |                                                 |
| **pve-01 NIC Ports**           | Port 1+2                   | Port 3+4                   | Port 5+6                                        |
| **PVE Linux Bond**             | `bond0`                    | `bond1`                    |                                                 |
| **PVE Bridge**                 | `vmbr0`                    | `vmbr1`                    | `vmbr2 : vmbr3`                                 |
| **PVE Comment**                | PVE LAN Bond               | VPN-egress Bond            | vpngate-world : vpngate-local                   |

The above table, based on an UniFi US-24 model, shows port 1+2 are link aggregated (LAG), port 3+4 are another LAG and ports 5 and 6 are NOT LAG'd. So ports 1 to 6 numbering on your switch correspond with the PVE-01 NIC devices (i.e. enp1s0 -  enp1s5).

### 3.3.2. Create Network Switch VLANs - pfSense

Three VLANs are required.

1. VLAN2 - *WAN/VPN-egress (VLAN2)*
2. VLAN30 - *LAN-vpngate-world (VLAN30)*
3. VLAN40 - *LAN-vpngate-local (VLAN40)*

These instructions are specifically for UniFi controller `Settings` > `Networks` > `Create New Network`.

*  Create a new network to be used for the Egress of encrypted traffic out of the network to your VPN servers.

| Description    | Value                   | Notes                                                                                                                      |
|----------------|-------------------------|----------------------------------------------------------------------------------------------------------------------------|
| Name           | `VPN-egress`            | *This network will be used as the WAN for pfSense OpenVPN clients (encrypted exit).*                                       |
| Purpose        | `Guest`                 | *Network Guest security policies.*                                                                                         |
| VLAN           | `2`                     | *A dedicated VLAN for the WAN used by OpenVPN client(s) for network paths and firewall rules use Guest security policies.* |
| Gateway/Subnet | `192.168.2.5/28`        | *Only 2 addresses on this subnet so /29 is ideal*                                                                          |
| DHCP Server    | `Enabled`               | *Just use default range 192.168.2.1 -- 192.168.2.14*                                                                       |
| Other Settings | *Just leave as default* |                                                                                                                            |

* Create **two** new VLAN only networks to be used as VPN gateways by OpenVPN clients in pfSense.

| Description   | Value                   | Notes                                                                                                                                              |
|---------------|-------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| Name          | **`LAN-vpngate-world`** | *This is the network where LAN clients will be restricted to the vpngate-world server*                                                             |
| Purpose       | `VLAN Only`             | This is critical. *We don't want the UniFi USG to do anything with any client on this VLAN other than be sure that they can get to their gateway.* |
| VLAN          | `30`                    |                                                                                                                                                    |
| IGMP Snooping | `Disabled`              |                                                                                                                                                    |
| DHCP Guarding | `192.168.30.5`          |                                                                                                                                                    |
|               |                         |                                                                                                                                                    |
| Name          | **`LAN-vpngate-local`** | *This is the network where LAN clients will be restricted to the vpngate-world server*                                                             |
| Purpose       | `VLAN Only`             | *This is critical. We don't want the UniFi USG to do anything with any client on this VLAN other than be sure that they can get to their gateway.* |
| VLAN          | `40`                    |                                                                                                                                                    |
| IGMP Snooping | `Disabled`              |                                                                                                                                                    |
| DHCP Guarding | `192.168.40.5`          |                                                                                                                                                    |

### 3.3.3. Setup network switch ports - pfSense

Here we configure the network switch ports.

Again the instructions are for the UniFi controller `Devices` > `Select device - i.e UniFi Switch 24/48` > `Ports`  and select your port and `edit` and `apply` as follows:

| Description           | 3x LAN 1GbE              | 4x LAN 1GbE & SFP+       | 4x LAN 1GbE              | 6x LAN 1GbE              |
|-----------------------|--------------------------|--------------------------|--------------------------|--------------------------|
| Name                  | **`Port 1`**             | **`Port 26 (SFP+)`**     | **`Port 1`**             | **`Port 1 & 2`**         |
| Switch Port Profile   | `All`                    | `All`                    | `All`                    | `All`                    |
| **Profile Overrides** |                          |                          |                          |                          |
| Operation             | `☐` Aggregate            | `☐` Aggregate            | `☐` Aggregate            | `☑` Aggregate            |
| Aggregate Ports       | N/A                      | N/A                      | N/A                      | `1-2`                    |
| Link Speed            | Autonegotiation          | Autonegotiation          | Autonegotiation          | Autonegotiation          |
|                       |                          |                          |                          |                          |
| Name                  | **`Port 2`**             | **`Port 1 & 2`**         | **`Port 2`**             | **`Port 3 & 4`**         |
| Switch Port Profile   | `VPN-egress(2)`          | `VPN-egress(2)`          | `VPN-egress(2)`          | `VPN-egress(2)`          |
| **Profile Overrides** |                          |                          |                          |                          |
| Operation             | `☐` Aggregate            | `☑` Aggregate            | `☐` Aggregate            | `☑` Aggregate            |
| Aggregate Ports       | N/A                      | `1-2`                    | N/A                      | `3-4`                    |
| Link Speed            | Autonegotiation          | Autonegotiation          | Autonegotiation          | Autonegotiation          |
|                       |                          |                          |                          |                          |
| Name                  | **`Port 3`**             | **`Port 3`**             | **`Port 3`**             | **`Port 5`**             |
| Switch Port Profile   | `LAN-vpngate-world (30)` | `LAN-vpngate-world (30)` | `LAN-vpngate-world (30)` | `LAN-vpngate-world (30)` |
| Profile Overrides     | Leave Default            | Leave Default            | Leave Default            | Leave Default            |
|                       |                          |                          |                          |                          |
| Name                  |                          | **`Port 4`**             | **`Port 4`**             | **`Port 6`**             |
| Switch Port Profile   |                          | `LAN-vpngate-local (40)` | `LAN-vpngate-local (40)` | `LAN-vpngate-local (40)` |
| Profile Overrides     |                          | Leave Default            | Leave Default            | Leave Default            |

Shown below is a sample of a 6x LAN port configuration.

![unifi_ports_01](README.assets/unifi_ports_01.png)

### 3.3.4. Setup network WiFi SSiDs for the VPN service - pfSense

We have two VPN VLAN's so we can create 2x new WiFI SSIDs. All traffic on these WiFi connections will exit encrypted to the internet via your preset VPN VLAN (30 or 40). The following instructions are for the UniFi controller `Settings` > `Wireless Networks` > `Create New Wireless Network` and fill out the form details as shown below:

| Description    | Value                     | Value                     |
|----------------|---------------------------|---------------------------|
| Name/SSID      | **`hello-vpngate-world`** | **`hello-vpngate-local`** |
| Enabled        | `☑`                       | `☑`                       |
| Security       | `WPA Personal`            | `WPA Personal`            |
| Security Key   | Enter a password          | Enter a password          |
| VLAN           | `30`                      | `40`                      |
| Other Settings | Leave as default          | Leave as default          |

### 3.3.5. Edit your UniFi network firewall - pfSense

This section is a little confusing. I try my best.

The pfSense VM is a fully functional independent OS with its own virtual networking. This pfSense virtual networking connects via bridges to your PVE-01 host computer PVE Linux Bridges (vmbr0, vmbr2,vmbr30, and optional vmbr40). In summary it's from one *bridge* to another *bridge*.

On the creation of your PVE pfSense VM, you will create a PVE VirtIO (paravirtualized) network device inside the VM. Each pfSense VM Virtio device is bridged to a PVE Linux Bridge (i.e. vmbr0 etc). Your pfSense PVE VM hardware configuration, subject to your host's networking capabilities, will resemble the following table:

| pfSense Network Device ID    | Settings                                          |
|------------------------------|---------------------------------------------------|
| <> Network Device (net0)     | virtio=3A:13:29:66:31:35,bridge=vmbr0,firewall=1  |
| <> Network Device (net1)     | virtio=1A:14:AH:3B:7B:35,bridge=vmbr2,firewall=1  |
| <> Network Device (net2)     | virtio=9E:3F:F9:5A:77:D1,bridge=vmbr30,firewall=1 |
| *Optional 4x LAN NIC below:* |                                                   |
| <> Network Device (net3)     | virtio=12:79:A0:1F:2C:8A,bridge=vmbr40,firewall=1 |

So when you configure and setup pfSense your pfSense Interfaces Assignments in the pfSense web management frontend will show:

| pfSense Interface                 | Network port               |
|-----------------------------------|----------------------------|
| LAN                               | vtnet0 (3A:13:29:66:31:35) |
| WAN ( *i.e VLAN2* )               | vtnet1 (1A:14:AH:3B:7B:35) |
| OPT1 ( *i.e Gateway for VLAN30* ) | vtnet2 (9E:3F:F9:5A:77:D1) |
| *Optional 4x LAN NIC below:*      |                            |
| OPT2 ( *i.e Gateway for VLAN40* ) | vtnet3 (12:79:A0:1F:2C:8A) |

When you install pfSense on host PVE-01 you must be assigned a LAN, WAN and your VPN gateway interfaces. Make sure the PVE VM Virtio MAC address corresponds with PVE Linux Bridge vmbr(x) ad is correctly assigned to the pfSense vtnet(x) assignments.

The pfSense WAN interface must be VLAN2 which is labeled in your UniFi controller (switch) as `VPN-egress`. Because it's configured with network `Guest security policies` in the UniFi controller it has no access to other network VLANs. The reason for this is explained build recipe for `VPN-egress` shown [here](#332-create-network-switch-vlans---pfsense).

For HAProxy to work you must authorize UniFi VLAN2 (WAN in pfSense addon service HAProxy) to have access to your Proxmox LXCs, CTs or VMs static container IPv4 addresses. These instructions are for a UniFi controller `Settings` > `Guest Control`  and look under the `Access Control` section. Under `Pre-Authorization Access` click`**+** Add IPv4 Hostname or subnet` to add the following IPv4 addresses to authorize access for VLAN2 clients. Fill out the form details as shown below:

| \+ Add IPv4 Hostname or subnet | By Hostname (recommended) | By IP          | Description         |
|--------------------------------|---------------------------|----------------|---------------------|
| IPv4                           | jellyfin.local            | 192.168.50.111 | *Jellyfin Server*   |
| IPv4                           | nzbget.local              | 192.168.30.112 | *Nzbget Server*     |
| IPv4                           | deluge.local              | 192.168.30.113 | *Deluge Server*     |
| IPv4                           | flexget.local             | 192.168.50.114 | *Flexget Server*    |
| IPv4                           | sonarr.local              | 192.168.50.115 | *Sonarr Server*     |
| IPv4                           | radarr.local              | 192.168.50.116 | *Radarr Server*     |
| IPv4                           | lidarr.local              | 192.168.50.117 | *Lidarr Server*     |
| IPv4                           | ahuabooks.local           | 192.168.50.118 | *Ahuabooks Server*  |
| IPv4                           | ombi.local                | 192.168.50.119 | *Ombi Server*       |
| IPv4                           | jackett.local             | 192.168.50.120 | *Jackett Server*    |
| IPv4                           | kodirsync.local           | 192.168.50.121 | *Kodi-rsync Server* |
| IPv4                           | vidcoderr.local           | 192.168.80.122 | *Vidcoder Server*   |
| IPv4                           | ahuabooks.local           |                | *Ahuabooks Server*  |

And click `Apply Changes`.

As you've probably concluded you must add all new HAProxy backend server IPv4 address(s) to the UniFi Pre-Authorization Access list for HAProxy frontend to have access to these servers.


# 4. PVE Host Toolbox

Our Easy Script Toolbox will configure and ready your PVE hosts to support Ahuacate CTs or VMs. Each Toolbox script will create, modify and change system settings including:

1. PVE Basic - required by all PVE hosts (mandatory / required)
    - Update Proxmox
    - Check and set Proxmox subscription key (free or enterprise)
    - Install nbtscan SW
    - Adjust sysctl parameters
    - Perform PVE container (CT) mapping
2. PVE Full Build - run all toolbox add-ons
3. PVESM NFS Storage - add additional NFS PVE storage mounts
4. PVESM SMB/CIFS Storage - add additional SMB/CIFS storage mounts
5. PVE Hostname Updater - change the hostname of a node
6. PVE Network Updater - change a hosts network configuration
7. Fail2Ban Installer
8. SSMTP Email Installer
9. SSH Key Installer -  add or create your own private SSH access key

The available options vary between PVE primary and secondary hosts.

### 4.0.6. SMTP Server Credentials

You will have the option to install an SSMTP Email server. SSMTP is Mail Transfer Agent (MTA) used to send email alerts about your machines like details about new user accounts, unwarranted login attempts, and system critical alerts to the system's designated administrator.

You will be asked for the credentials of an SMTP Server. You can use Gmail, GoDaddy, AWS, or any SMTP server credentials (i.e address, port, username and password, encryption type etc.

But we recommend you create an account at mailgun.com to relay your NAS system emails to your designated administrator. With mailgun you are not potentially exposing your private email server credentials held within a text file on your PVE host. This is an added layer of security.

## 4.1. Run our PVE Host Toolbox Easy Script

To execute SSH into your PVE host ( i.e. `ssh root@192.168.1.101` ) or use the Proxmox web interface CLI shell `pve-0x` > `>_ Shell` and cut & paste the following into the CLI terminal window and press ENTER:

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-setup/master/pve_host_setup_toolbox.sh)"
```

> We recommended you establish an SSH connection from a computer CLI terminal or with an application like Putty (a free SSH and telnet client for Windows) https://www.putty.org instead of using the Proxmox web interface CLI shell.

# 5. Other PVE Host Stuff

## 5.1. Create a PVE Cluster

Proxmox requires a minimum of three PVE hosts on the same network to form a cluster - PVE-01, PVE-02 and PVE-03.

### 5.1.1. Create a Cluster

Using the PVE web interface on host PVE-01, go to `Datacenter` > `Cluster` > `Create Cluster` and fill out the fields as follows:

| Create Cluster | Value         | Notes |
|----------------|---------------|-------|
| Cluster Name   | `pve-cluster` |       |
| Ring 0 Address | Leave Blank   |       |

And Click `Create`.

### 5.1.2. Join the other Nodes to the New Cluster

The first step in joining other nodes to your cluster, `pve-cluster`, is to copy PVE-01 cluster manager fingerprint/join information into your clipboard.

**Step One:**

Using PVE web interface on host PVE-01, go to `Datacenter` > `Cluster` > `Join Information` and a new window will appear showing `Cluster Join Information` with the option to `Copy Information` into your clipboard. Click `Copy Information`.

**Step Two:**

Using the PVE web interface on the OTHER hosts, PVE-02/03/04, go to `Datacenter` > `Cluster` > `Join Cluster` and a new window will appear showing `Cluster Join` with the option to paste the `Cluster Join Information` into an `Information` field. Paste the information, enter your root password into the `Password` field and the other fields will automatically be filled.

And  Click `Join`. Repeat for on all nodes.

All PVE host management can be performed from the PVE-01 node.  Using the PVE web management WebGUI (https://192.168.1.101:8006) all added cluster hosts should be listed below `Datacenter (pve-cluster)`. Or type `pvecm status` into any host `pve-01` > `>_Shell`:

```
pvecm status

# Results ...
Quorum information
------------------
Date:             Mon Jul 22 13:44:10 2019
Quorum provider:  corosync_votequorum
Nodes:            3
Node ID:          0x00000001
Ring ID:          1/348
Quorate:          Yes

Votequorum information
----------------------
Expected votes:   3
Highest expected: 3
Total votes:      3
Quorum:           2  
Flags:            Quorate 

Membership information
----------------------
    Nodeid      Votes Name
0x00000001          1 192.168.1.101 (local)
0x00000002          1 192.168.1.102
0x00000003          1 192.168.1.103
```

### 5.1.3. How to delete an existing cluster on a node

If you make a mistake when setting up your cluster the following should reset your cluster settings to the PVE default.

```bash
systemctl stop pve-cluster
pmxcfs -l
rm -f /etc/pve/cluster.conf /etc/pve/corosync.conf
rm -f /etc/cluster/cluster.conf /etc/corosync/corosync.conf
systemctl stop pve-cluster
rm /var/lib/pve-cluster/.pmxcfs.lockfile
rm -f /etc/corosync/authkey
systemctl start pve-cluster
systemctl restart pvedaemon
systemctl restart pveproxy
systemctl restart pvestatd
reboot
```
<hr>

# 6. Maintenance Tools

## 6.1. Toolbox Updater for all CTs OS
The script performs an OS update on all PVE CTs. All CTs are returned to their former run state in the background before moving on to CT.

To run the Updater run the Toolbox.
