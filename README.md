<H1>PVE Host Build</H1>

This guide is for building and configuring PVE hardware.

As with all our guides there is a Easy Script to automate your PVE build, configuration and installation tasks. The Easy Script will offer the installer options based on your available hardware. The same Easy Script works on both primary and secondary PVE hosts.

But first step is to prepare your network and check our prerequisite requirements before running our Easy Script. The Easy Script will configure your storage, ZFS cache, networking and make system changes to your hardware. After running our Easy Script you should be ready to install and create our suite of PVE containers (CTs). Therefore its important you first read and follow our prerequisite guide.

Our Easy Script will prompt the installer with options:

**Options for Primary PVE Hosts only** - Your Main PVE Host (PVE-01)
- Configure PVE host networking ready for installing pfSense
  - requires a minimum of 3x Intel Ethernet NICs
- Configure PVE host networking (no pfSense)
- Add PVE storage by creating a CIFS backend storage pool
- Add PVE storage by creating a NFS backend storage pool
- Create installer SSH key pairs for connecting to your PVE hosts root account via SSH

**Options for Primary & Secondary PVE Hosts**
- Configure PVE Postfix email service so you can receive email alerts
- Install Fail2Ban as a intrusion prevention software to protects your PVE host from brute-force attacks

**Prerequisites**
Network prerequisites are:
- [x] Layer 2/3 Network Switches
- [x] Network Gateway is `XXX.XXX.XXX.5` ( *default is 192.168.1.5* )
- [x] Network DHCP server is `XXX.XXX.XXX.5` ( *default is 192.168.1.5* )
- [x] Internet access for the PVE host

- [x] File server or NAS (i.e NAS-01) . Our default NAS IPv4 address is `XXX.XXX.XXX.10` ( *default is 192.168.1.10* )
- [x] File server or NAS is configured with network shares, either CIFS or NFS, as per these [instructions](https://github.com/ahuacate/synobuild) and guides.

Other prerequisites (information the installer should have readily available before starting):

- [ ] NAS CIFS user account credentials as per these [instructions.](https://github.com/ahuacate/synobuild) (Only if your adding PVE storage using NAS CIFS storage mounts)

- [ ] Optional PVE Postfix
  - Email account credentials
  - MailGun credentials

<h4>Easy Script</h4>

Our single Easy Script can be used on both primary and secondary PVE hosts. Your user input is required. The script will create, edit and/or change system files on your PVE host. When an optional default setting is provided you can accept our default (recommended) by pressing ENTER on your keyboard. Or overwrite our default value by typing in your own value and then pressing ENTER to accept and to continue to the next step.

After executing the Easy Script in your PVE host SSH terminal you will asked or prompted for input about:

- Verify PVE enterprise subscription status - A patch will be applied if you do not have a valid PVE subscription
- Fully update your PVE host OS
- Install prerequisite software - nbtscan, ifupdown2
- Update PVE turnkey appliance list
- Increase the PVE inotify limits
- Perform PVE host UID/GID mapping for unprivileged CTs
- Select PVE host type - Primary or Secondary
- Configure your PVE host network interface card (NIC) 
- Optional - Create NFS and/or CIFS backend storage mounts for your PVE hosts (Recommended - Must be done at some stage)
- Optional - Install and configure Postfix SMTP email server and alerts (Recommended - requires a valid email & Mailgun credentials)
- Optional - Install and configure SSH Authorized Keys (Recommended)
- Optional - Install and configure Fail2Ban (Recommended)

The available options are different between primary and secondary hosts. Its best to perform all the recommended tasks. For example, by setting up the default Postfix SMTP server you will receive email copies of not only PVE alerts but also copies of newly created SSH keys pairs for your convenience.

Easy Scripts are based on bash scripting. Simply `Cut & Paste` our Easy Script command into your terminal window, press `Enter` and follow the prompts and terminal instructions. But PLEASE first read our guide so you fully understand each scripts prerequisites and your input requirements.

**Installation**
This Easy Script is for primary and secondary PVE hosts. It gives the installer options to run our option add-ons to full configure your PVE hosts.

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-build/master/scripts/pve_host_build.sh)"
```
**Add-on** (optional)
Optional Add-on Easy Scripts can be run anytime. They are for adding new PVE NAS storage mounts, installing Postfix email alerts and other services.

Add-on - Add PVE NFS Storage Mounts

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-build/master/scripts/pve_add_nfs_mounts.sh"
```

Add-on - Add PVE CIFS Storage Mounts

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-build/master/scripts/pve_add_cifs_mounts.sh"
```

Add-on - Install and configure Postfix and email alerts

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-build/master/scripts/pve_setup_postfix.sh"
```

Add-on - Configuring SSH Authorized Keys

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-build/master/scripts/pve_setup_sshkey.sh"
```

Add-on - Install and configure Fail2ban

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-build/master/scripts/pve_setup_fail2ban.sh"
```

<hr>

<h4>Table of Contents</h4>
<!-- TOC -->

- [1. Preparing your Hardware](#1-preparing-your-hardware)
    - [1.1. PVE OS Installation](#11-pve-os-installation)
        - [1.1.1. PVE OS Install - Primary Host - (1-2)x SSD OS & ZFS Cache ( + ZFS File Server)](#111-pve-os-install---primary-host---1-2x-ssd-os--zfs-cache---zfs-file-server)
        - [1.1.2. PVE OS Install - Primary Host - (1-2)x SSD OS & (1-2)x SSD ZFS Cache ( + ZFS File Server)](#112-pve-os-install---primary-host---1-2x-ssd-os--1-2x-ssd-zfs-cache---zfs-file-server)
        - [1.1.3. PVE OS Install - Primary Host - 1x SSD OS](#113-pve-os-install---primary-host---1x-ssd-os)
        - [1.1.4. PVE OS Install - Secondary Host](#114-pve-os-install---secondary-host)
        - [1.1.5. Proxmox VE OS Install - Final Steps](#115-proxmox-ve-os-install---final-steps)
    - [1.2. Primary Host - Creating SSD partitions for ZFS Cache](#12-primary-host---creating-ssd-partitions-for-zfs-cache)
        - [1.2.1. Primary Host - Partition PVE OS SSD(s) for ZFS Cache ( + ZFS File Server)](#121-primary-host---partition-pve-os-ssds-for-zfs-cache---zfs-file-server)
        - [1.2.2. Primary Host - Partition Dedicated ZFS Cache SSD ( + ZFS File Server)](#122-primary-host---partition-dedicated-zfs-cache-ssd---zfs-file-server)
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
- [4. Easy Script](#4-easy-script)
    - [4.1. Prerequisite Credentials and Input Requirements](#41-prerequisite-credentials-and-input-requirements)
        - [4.1.1. SMTP Server Credentials](#411-smtp-server-credentials)
    - [4.2. Run our Easy Script](#42-run-our-easy-script)
- [5. Other PVE Host Stuff](#5-other-pve-host-stuff)
    - [5.1. Create a PVE Cluster](#51-create-a-pve-cluster)
        - [5.1.1. Create a Cluster](#511-create-a-cluster)
        - [5.1.2. Join the other Nodes to the New Cluster](#512-join-the-other-nodes-to-the-new-cluster)
        - [5.1.3. How to delete a existing cluster on a node](#513-how-to-delete-a-existing-cluster-on-a-node)
- [6. Patches and Fixes](#6-patches-and-fixes)
    - [6.1. pfSense – disable firewall with pfctl -d](#61-pfsense--disable-firewall-with-pfctl--d)
    - [6.2. Proxmox Backup Error - Permissions](#62-proxmox-backup-error---permissions)
    - [6.3. Simple bash script to APT update all LXC containers which are stopped or running status](#63-simple-bash-script-to-apt-update-all-lxc-containers-which-are-stopped-or-running-status)

<!-- /TOC -->

<hr>

# 1. Preparing your Hardware

PVE hosts can be built using any x86 hardware with a few conditions. Always use Intel NIC devices (clones seem to be okay too). And only use enterprise grade SSD drives when creating ZFS Cache builds.

In this guide you have the option to configure a PVE host which also serves as a backend ZFS file server with optional SSD cache. PVE has inbuilt ZFS to create Raid-Z storage tanks featuring as many disks as you like. You can read about our containerized NAS solution [here](https://github.com/ahuacate/pve-zfs-nas) which uses a PVE Ubuntu CT as the frontend.

We also have a primary PVE host build option, for hardware with 3x or more Intel NICs, for pfSense. With pfSense your can create OpenVPN Gateways, HAProxy servers and more using multiple NICs and VLANs. Our pfSense setup requires L2/L3 switches uses VLANs.

Secondary PVE hosts require only a 1x NIC. A minimum of two secondary PVE hosts is needed to form a quorum in the event a PVE host fails. Note: The downside is when your primary PVE host goes offline then your PfSense services (i.e. OpenVPN, HAProxy) are also offline.

Your PVE host hardware specifications are determined by your mainboard type.

**Primary Host Build - Type A** - Could serve as your PVE ZFS File Server (NAS)
*  Quality Mainboard Hardware
*  4x LAN PCIe Intel I350-T4  (optional)
*  10GbE Intel NIC (optional)
*  CPU support for Intel AES-NI (required by pfSense addon service OpenVPN)
*  16Gb RAM (Recommend 32Gb ECC)
*  1x 240Gb Samsung PM883 (Recommend 2x SSDs in Raid1)
*  2x 480Gb Samsung PM883 for Boot & ZFS Cache (optional - For ZFS NAS)
*  6-10TB Rotational Disks (Optional - For ZFS NAS)

**Primary Host Build - Type B** (Qotom Mini PC Q500G6-S05 - No ZFS File Server)
*  Qotom Mini PC Q500G6-S05 - I5 Intel (any x86 Qotom with a minimum of 4x Intel Ethernet NICs)
*  6x LAN 1GbE Intel NICs
*  Support for Intel AES-NI (required for OpenVPN Gateway)
*  16Gb of RAM  (16Gb is max for Qotom)
*  240Gb Samsung PM883 x1 (Enterprise Grade SSD)

**Secondary Host Build** - Cluster Node Hardware
* Any X86 hardware to complete a 3x PVE host cluster
* Hardware example: Intel Celeron, Pentium, i3/i5/i7 NUC models with minimum 16Gb RAM and 1x LAN 1GbE NIC (Intel NIC)

## 1.1. PVE OS Installation
Go to the Proxmox website and [download](https://www.proxmox.com/en/downloads) the latest ISO and burn to USB stick. Instructions are [here](https://pve.proxmox.com/wiki/Prepare_Installation_Media).

In this guide we refer to SCSi and SATA (Serial ATA) controller devices designated disk names such as `sda`, `sdb`, `sdc` and so on, a generic Linux naming convention, as `sdx` only. Ideally `sda` (and `1sdb`) should be allocated as the Proxmox OS SSD device.

Always use the ZFS disk format.

Note:  Some main boards may not show disk devices as `sda/sdb/sdc` because the SSD is not installed on a SCSi or SATA controller. For example, NVMe drives show as /dev/nvme0(n1..). Its most important to check your hardware device schematics and note which device type is designated to which type of hard drive (SSD) you have installed. 

### 1.1.1. PVE OS Install - Primary Host - (1-2)x SSD OS & ZFS Cache ( + ZFS File Server)

In this build you can install 1 or 2 enterprise grade SSD in your host. 2x SSDs (Raid 1) will give your added redundancy and reliability. The SSDs will be partitioned to serve as dedicated L2ARC and ZIL logs cache to increase ZFS file serving performance.

Boot from the Proxmox installation USB stick and configure Proxmox VE as follows:

**Proxmox Virtualization Environment (PVE)** - At this stage you must select your PVE OS installation drives, Raid type and partition sizes. Click 'options' and complete as follows:

| Option                     | Value         | Notes                                                                    |
|----------------------------|---------------|--------------------------------------------------------------------------|
| Filesystem - 1x SSD        | `zfs (RAID0)` |                                                                          |
| Filesystem - 2x SSD        | `zfs (RAID1)` | *Recommended build*                                                      |
| **Disk Setup - SATA**      |               |                                                                          |
| Harddisk 0                 | /dev/sdx      |                                                                          |
| Harddisk 1                 | /dev/sdx      |                                                                          |
| **Disk Setup - PCIe NVMe** |               |                                                                          |
| Harddisk 0                 | /dev/nvmeXn1  |                                                                          |
| Harddisk 1                 | /dev/nvmeXn1  |                                                                          |
| **Advanced Options**       |               |                                                                          |
| ashift                     | `12`          | *4K sector size. For 8K sectors use `13`*                                |
| compress                   | `lz4`         |                                                                          |
| checksum                   | `on`          |                                                                          |
| copies                     | `1`           |                                                                          |
| SSD size - 240GB           | `148`         | *Partition GB = (220 - 64 L2ARC - 8 ZIL ).  Over-provisioning to 220GB*  |
| SSD size - 480GB           | `332`         | *Partition GB = (460 - 120 L2ARC - 8 ZIL ).  Over-provisioning to 460GB* |

The above PVE partition `size` is calculated in the following table. The unallocated space is required for 2x partitions for L2ARC and ZIL logs cache. 

| Option                                                            | 480GB SSD | 240GB SSD |
|-------------------------------------------------------------------|-----------|-----------|
| Actual Capacity - *After over-provisioning (as rule deduct 20GB)* | 460GB     | 220GB     |
| PVE OS size                                                       | 332GB     | 148       |
| **Unallocated space**                                             |           |           |
| ZFS ZIL (Logs) GB size                                            | 8         | 8         |
| ZFS L2ARC GB size                                                 | 120       | 64        |

### 1.1.2. PVE OS Install - Primary Host - (1-2)x SSD OS & (1-2)x SSD ZFS Cache ( + ZFS File Server)

This build is for a dedicated ZFS Cache SSD(s) setup. Be careful NOT to set any of your ZFS Cache SSD disks as target disks during your Proxmox OS installation. The ZFS disks must be set as `-- do not use --` during the Proxmox installation.

The dedicated ZFS Cache SSD will be setup and partitioned at a later stage in the build guide.

Boot from the Proxmox installation USB stick and configure Proxmox VE as follows:

**Proxmox Virtualization Environment (PVE)** - At this stage you must select your PVE OS installation drives, Raid type and partition sizes. Click 'options' and complete as follows:

| Option                        | Value            | Notes                                     |
|-------------------------------|------------------|-------------------------------------------|
| Filesystem - 1x SSD           | `zfs (RAID0)`    |                                           |
| File System - 2x SSD          | `zfs (RAID1)`    | *Recommended build*                       |
| **Disk Setup - SATA**         |                  |                                           |
| Harddisk 0                    | /dev/sdx         |                                           |
| Harddisk 1                    | /dev/sdx         |                                           |
| Harddisk 2 - (ZFS cache SSDs) | -- do not use -- |                                           |
| Harddisk 3 - (ZFS cache SSDs) | -- do not use -- |                                           |
| **Disk Setup - PCIe NVMe**    |                  |                                           |
| Harddisk 0                    | /dev/nvmeXn1     |                                           |
| Harddisk 1                    | /dev/nvmeXn1     |                                           |
| Harddisk 2- (ZFS cache SSDs)  | -- do not use -- |                                           |
| Harddisk 3- (ZFS cache SSDs)  | -- do not use -- |                                           |
| **Advanced Options**          |                  |                                           |
| ashift                        | `12`             | *4K sector size. For 8K sectors use `13`* |
| compress                      | `lz4`            |                                           |
| checksum                      | `on`             |                                           |
| copies                        | `1`              |                                           |
| SSD size - 240GB              | `220`            | *Over-provisioning to 220GB*              |
| SSD size - 480GB              | `460`            | *Over-provisioning to 460GB*              |

### 1.1.3. PVE OS Install - Primary Host - 1x SSD OS

No PVE NAS or cache setup in this build.

PVE OS is installed in a ZFS Raid0 configuration. 

Boot from the Proxmox installation USB stick and configure PVE as follows:

**Proxmox Virtualization Environment (PVE)** - At this stage you must select your PVE OS installation drive, and Raid type. Click 'options' and complete as follows:

| Option                     | Value         | Notes                                     |
|----------------------------|---------------|-------------------------------------------|
| Filesystem                 | `zfs (RAID0)` |                                           |
| **Disk Setup - SATA**      |               |                                           |
| Harddisk 0                 | /dev/sdx      |                                           |
| **Disk Setup - PCIe NVMe** |               |                                           |
| Harddisk 0                 | /dev/nvmeXn1  |                                           |
| **Advanced Options**       |               |                                           |
| ashift                     | `12`          | *4K sector size. For 8K sectors use `13`* |
| compress                   | `lz4`         |                                           |
| checksum                   | `on`          |                                           |
| copies                     | `1`           |                                           |
| SSD size - 240GB           | `220`         | *Over-provisioning to 220GB*              |
| SSD size - 480GB           | `460`         | *Over-provisioning to 460GB*              |

### 1.1.4. PVE OS Install - Secondary Host

PVE secondary hosts are machines in a PVE cluster. If you have a Synology NAS with a Intel CPU you can save on hardware costs by creating a Synology Virtual Machine Proxmox VM build with these instructions [here](https://raw.githubusercontent.com/ahuacate/nas-oem-setup).

PVE OS is installed in a ZFS Raid0 configuration (Raid0 with 1x SSD is okay).

Boot from the Proxmox installation USB stick and configure Proxmox VE as follows:

**Proxmox Virtualization Environment (PVE)** - At this stage you must select your PVE OS installation drive, and Raid type. Click 'options' and complete as follows:

| Option                     | Value         | Notes                                     |
|----------------------------|---------------|-------------------------------------------|
| Filesystem                 | `zfs (RAID0)` |                                           |
| **Disk Setup - SATA**      |               |                                           |
| Harddisk 0                 | /dev/sdx      |                                           |
| **Disk Setup - PCIe NVMe** |               |                                           |
| Harddisk 0                 | /dev/nvmeXn1  |                                           |
| **Advanced Options**       |               |                                           |
| ashift                     | `12`          | *4K sector size. For 8K sectors use `13`* |
| compress                   | `on`          |                                           |
| checksum                   | `lz4`         |                                           |
| copies                     | `1`           |                                           |
| SSD size - 240GB           | `220`         | *Over-provisioning to 220GB*              |
| SSD size - 480GB           | `460`         | *Over-provisioning to 460GB*              |

### 1.1.5. Proxmox VE OS Install - Final Steps

The final step is to configure a basic network device. If you have multiple onboard ethernet LAN NIC devices, 10GbE ethernet or a multi port Intel PCIe LAN Card installed you must choose *only ONE device* to configure at this stage.

If you have 10GbE ethernet, on a primary or secondary PVE host, then always select and configure the 10GbE device.

If your PVE host has only 1GbE LAN NICs then you must choose the first ethernet device ID of either a onboard mainboard Intel NIC or if available the first device of your installed Intel PCIe LAN Card. Your decision is based on how many valid (Intel brand) ethernet devices are available ignoring all other brands if you can. For example, if you have a Intel I350-T4 PCIe x4 LAN Card 4x Port installed and 2x onboard **Realtek** NICs, always ignore the 2x **Realtek** devices from all selection criteria. Always use only Intel NICs whenever possible.

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

Primary PVE host must be assigned hostname `pve-01.localdomain` and preferably IPv4 `192.168.1.101` or at least denoted by xxx.xxx.xxx.`101`, and if your want to create a pfSense OpenVPN Gateway for your network clients then you must have a minimum of 3x Intel Ethernet LAN NICs available (i.e. PCIe Intel I350-T4 card installed) in your primary host. 

The remaining steps in configuring PVE are self explanatory.  Configure each PVE host as follows:

| Option               | Primary Host            | Secondary Host          | Secondary Host          | Notes                                                                                                                                                                                            |
|----------------------|-------------------------|-------------------------|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Country              | Type your Country       | Type your Country       | Type your Country       |                                                                                                                                                                                                  |
| Timezone             | Select                  | Select                  | Select                  |                                                                                                                                                                                                  |
| Keymap               | `en-us`                 | `en-us`                 | `en-us`                 |                                                                                                                                                                                                  |
| Password             | Enter your new password | Enter your new password | Enter your new password | *Same root password on all nodes*                                                                                                                                                                |
| E-mail               | Enter your Email        | Enter your Email        | Enter your Email        | *You best use a valid email address (recommended). It needs to be valid for PVE Postfix alerts and other email services to work. If you don't want to enter a valid email type mail@example.com* |
| Management interface | Leave Default           | Leave Default           | Leave Default           |                                                                                                                                                                                                  |
| Hostname             | `pve-01.localdomain`    | `pve-02.localdomain`    | `pve-03.local.domain`   | *Note the naming convention*                                                                                                                                                                     |
| IP Address           | `192.168.1.101`         | `192.168.1.102`         | `192.168.1.103`         | *Note the IP number assignments - XXX.XXX.XXX.101 > .102 > .103 >*                                                                                                                               |
| Netmask              | `255.255.255.0`         | `255.255.255.0`         | `255.255.255.0`         |                                                                                                                                                                                                  |
| Gateway              | `192.168.1.5`           | `192.168.1.5`           | `192.168.1.5`           |                                                                                                                                                                                                  |
| DNS Server           | `192.168.1.5`           | `192.168.1.5`           | `192.168.1.5`           |                                                                                                                                                                                                  |

## 1.2. Primary Host - Creating SSD partitions for ZFS Cache 

This section only applies to builds, shown in 1.1.1 and 1.1.2, where PVE-01 is hosting a backend ZFS storage for a PVE NAS frontend.

ZFS Cache requires you to make two partitions for ZFS L2ARC and ZIL logs cache on cache SSDs. You options are:

- partition your PVE OS SSDs
- use a dedicated SSD exclusively for ZFS Cache

In both scenarios the SSD must be enterprise grade for use as ZFS Cache.

### 1.2.1. Primary Host - Partition PVE OS SSD(s) for ZFS Cache ( + ZFS File Server)

This section applies to primary hosts for section 1.1.1 builds only. 

If your primary PVE host is to be configured with partitioned SSDs for ZFS Cache then you must have unallocated SSD space for L2ARC and ZIL logs cache on your SSDs.  

This unallocated needs to be partitioned as follows:

| Option                                           | 480GB SSD | 240GB SSD |
|--------------------------------------------------|-----------|-----------|
| Useable Capacity ( *Over-provisioning* )         | 460GB     | 220GB     |
| PVE OS size                                      | 332       | 148       |
| **Unallocated space - Partitioning Scheme** (GB) | 72        | 72        |
| Partition 1 - ZFS L2ARC GB size                  | 120       | 64        |
| Partition 2 - ZFS ZIL (Logs) GB size             | 8         | 8         |

First identify which drive devices are used for your Proxmox VE OS. If you chose ZFS Raid1 during the Proxmox install then you have two drives to partition. To identify the drives to partition first SSH into `pve-01`(ssh root@192.168.1.101) or use the Proxmox web interface CLI shell `pve-01` > `>_ Shell` and type the following into the CLI terminal window:

```bash
fdisk -l 2>/dev/null | grep -E 'BIOS boot|EFI System'| awk '{ print $1 }' | sort | sed 's/[0-9]*//g' | awk '!seen[$0]++'
```

```bash
# Command Results will show something like:
/dev/sda
/dev/sdb
```

The above means you must partition devices /dev/sda and /dev/sdb. If only one device shows that's okay as it means you installed PVE OS on one drive only (i.e. ZFS Raid0).

To create the partitions we again need a SSH terminal. SSH into `pve-01`(ssh root@192.168.1.101) or use the Proxmox web interface CLI shell `pve-01` > `>_ Shell` and type the following into the CLI terminal window. Repeat steps 1 to 8 for the above device ID(s) (i.e `cfdisk /dev/sda` and `cfdisk /dev/sdb`).

1.  Type `cfdisk /dev/sdx` in the CLI. Replace the `x` with the correct ID (i.e. /dev/sda). The cfdisk window dialogue will appear in the terminal.
2.  Highlight row `Free Space` and option `New` and press `ENTER`.
3.  Set the `Partition Size` to 64G and press `ENTER`.
4.  Repeat highlighting the row `Free Space` and option `New` and press `ENTER`.
5.  Set the `Partition Size` to 8G and press `ENTER`.

At this stage you should have created: 2x new partitions sized 64G and 8G with type set to Linux filesystem.

6.  Highlight option `Write` and press `ENTER`.
7.  Type `yes` to prompt "Are you sure you want to write the partition table to disk?"
8.  Highlight option `Quit` and press `ENTER`.

### 1.2.2. Primary Host - Partition Dedicated ZFS Cache SSD ( + ZFS File Server)

This section applies to primary hosts shown in section 1.1.2 builds only.

You must create two partitions on all of the dedicated ZFS Cache SSDs for ZFS L2ARC and ZIL logs.

The partitioning scheme is as follows:

| Option                                   | 480GB SSD | 240GB SSD (Recommended) |
|------------------------------------------|-----------|-------------------------|
| Useable Capacity ( *Over-provisioning* ) | 460GB     | 220GB                   |
| **Partitioning Scheme** (GB)             |           |                         |
| Partition 1 - ZFS L2ARC GB size          | 452       | 232                     |
| Partition 2 - ZFS ZIL (Logs) GB size     | 8         | 8                       |

First identify which drive devices are to be used for your dedicated ZFS Cache. To identify the drives to partition first SSH into `pve-01`(ssh root@192.168.1.101) or use the Proxmox web interface CLI shell `pve-01` > `>_ Shell` and type the following into the CLI terminal window:

```bash
fdisk -l 2>/dev/null | grep -E 'BIOS boot|EFI System' | awk '{ print $1 }' | sort | sed 's/[0-9]*//g' | awk '!seen[$0]++' > /tmp/disk_os && lsblk -o PATH,SIZE,TYPE | grep 'disk' | awk '{print $1,$2}' > /tmp/disk_all && grep -vf /tmp/disk_os /tmp/disk_all
```

```bash
# Command Results will show something like:
/dev/sdc 240.0G
/dev/sdd 240.0G
/dev/sde 3.7T
/dev/sdf 3.7T
/dev/sdg 3.7T
```

The above suggests your dedicated ZFS Cache SSD devices are `/dev/sdc` and `/dev/sdd`. Use the CLI disk size to help you identify which disks are your ZFS Cache SSDs.

To partition your SSDs we need a SSH terminal. SSH into `pve-01`(ssh root@192.168.1.101) or use the Proxmox web interface CLI shell pve-01` > `>_ Shell` and type the following into the CLI terminal window. Repeat steps 1 to 8 for the above device ID(s) (i.e `cfdisk /dev/sda` and `cfdisk /dev/sdb`).

1. Type `sgdisk --zap /dev/sdx` in the CLI. Replace the `x` with the correct ID (i.e. /dev/sdc). Repeat on all ZFS Cache SSD devices.

2. Type `dd if=/dev/zero of=/dev/sdx count=1 bs=512 conv=notrunc` in the CLI. Replace the `x` with the correct ID (i.e. /dev/sdc). Repeat on all ZFS Cache SSD devices.

3. Type `wipefs --all --force /dev/sdx` in the CLI. Replace the `x` with the correct ID (i.e. /dev/sdc). Repeat on all ZFS Cache SSD devices.

4. Type `cfdisk /dev/sdx` in the CLI. Replace the `x` with the correct ID (i.e. /dev/sdc). The cfdisk window dialogue will appear in the terminal.

5. Highlight row `Free Space` and option `New` and press `ENTER`. Next input the partition sizes for L2ARC and ZIL partitions. When calculating the sizes always over-provision your SSD by 20GB. ZIL is always sized at 8GB and the remainder can be your L2ARC partition. 

   | Option                                               | 480GB SSD | 240GB SSD (Recommended) |
   |------------------------------------------------------|-----------|-------------------------|
   | Useable Capacity ( *Always over-provision by 20GB* ) | 460GB     | 220GB                   |
   | **Partitioning Scheme** (GB)                         |           |                         |
   | Partition 1 - ZFS L2ARC GB                           | 452       | 232                     |
   | Partition 2 - ZFS ZIL (Logs) GB                      | 8         | 8                       |

6. Set the `Partition Size` to `ZFS L2ARC GB` and press `ENTER`.

7. Repeat highlighting the row `Free Space` and option `New` and press `ENTER`.

8. Set the `Partition Size` to `ZFS ZIL (Logs) GB` and press `ENTER`.

9. At this stage you should have created: 2x new partitions L2ARC and ZIL with type set to Linux filesystem.

10. Highlight option `Write` and press `ENTER`.

11. Type `yes` to prompt "Are you sure you want to write the partition table to disk?"

12. Highlight option `Quit` and press `ENTER`.

13. Repeat cfdisk tasks for all ZFS Cache SSDs steps 4-13.

# 2. File Server (NAS)

You must have a running network accessible File Server (NAS) with NFS and/or CIFS shares. Proxmox can add storage by creating a CIFS or NFS backend storage pool from your NAS mount points.

Your NAS server CIFS or NFS properties must be configured so your PVE host backend can mount these NAS shares automatically.

Your options are:
**NAS Appliance** - A NAS of any brand or type, Synology, QNap, FreeNAS, Windows or Linux server, available on your network preferably with IPv4 address `XXX.XXX.XXX.10` ( *default is 192.168.1.10* ). The NAS must be installed with Samba and NFSv4.1 services. This guide details what you must to do to setup your NAS NAS File sharing and permissions. 
**PVE NAS** (ZFS) - A PVE ZFS RaidZ storage pool (backend) can be hosted on PVE-01. Management of the backend storage is by a PVE Ubuntu CT (labelled NAS-01) frontend also hosted on PVE-01. NAS-01 CT is installed with NFSv4.1 and Samba services. Our detailed guide includes an Easy Scripts to setup a [PVE NAS](https://github.com/ahuacate/pve-zfs-nas/blob/master/README.md).


# 3. Network Switch Setup - VLANs, 802.3ad, PfSense, OpenVPN Gateway

If you've chosen to install a PfSense and OpenVPN Gateway server on PVE-01 then you must make additional network modifications. Your LAN network switches must be L2/L3 compatible because you need to setup VLANs.

If you followed our guide then your primary host PVE-01 will have a minimum of 3x Ethernet LAN 1GbE NICs. Builds with 5x Ethernet LAN 1GbE NICs enables you to use 802.3ad Dynamic link aggregation to increase performance and reliability.

Secondary hosts only require 1x Ethernet LAN NIC. If you have more NICs available then use 802.3ad Dynamic link aggregation on these hosts too to increase bandwidth.

You should by now have at least your primary host PVE-01 ready and running. In the next steps we need to configure your LAN network switches to match your PVE hosts needs.

## 3.1. Network Options - Ready PVE-01 for pfSense

First decide how may LAN ports you are going configure on your PVE hosts and network switches. For our PVE-01 pfSense build a minimum of 3x NICs and switch LAN ports is required.

Its important to note there is a PVE Linux Bridge, Bond and VLAN naming convention which must be adhered to. This naming convention is used in all our Proxmox builds and Easy Scripts.

On PVE-01 we create the following PVE Linux Bridges which are associated with their own VLAN ID. The Linux Network Device name varies because it's determined by the hosts mainboard (here we use *enp0s0-enp0s3*). The sample below shows a 3x Ethernet LAN NIC configuration, with a optional 4x NIC configuration for a VPN Local Gateway service,  with no PVE Linux Bonds (LAG-802.3ad). 

| PVE Linux Bridge    | Network Devices | Description                                                                   | VLAN ID |
|---------------------|-----------------|-------------------------------------------------------------------------------|---------|
| vmbr0               | enp0s0          | PVE HOST NIC ( i.e. 192.168.1.101 )                                           | vlan1   |
| vmbr2               | enp0s1          | VPN Gateway Egress (WAN encrypted link to the internet)                       | vlan2   |
| vmbr30              | enp0s2          | VPN World Gateway (LAN gateway for clients to random world VPN servers)       | vlan30  |
| *Below is optional* |                 |                                                                               |         |
| vmbr40              | enp0s3          | VPN Local Gateway (LAN gateway for clients to a local in-country VPN servers) | vlan40  |

The next table illustrates using PVE Linux Bonds (LAG) of 1GbE slaves and a 10GbE SFP+ NIC. Whenever a 10GbE NIC is available always assigned it to PVE host Linux Bridge vmbr0.

Note: Shown below *enp0s0~5* are the hosts 1GbE ethernet NIC devices (Intel PCIe LAN Card 6x Port) and *enp68s0f0* is the 10GbE NIC. Always first create the PVE Linux Bonds and then create the PVE Linux Bridges using the PVE Linux Bonds as the slaves. 

| GbE Type     | PVE Linux Bond Name  | Ports/Slaves (network devices)     | Description and Purpose               | Vlan ID     |
|--------------|----------------------|------------------------------------|---------------------------------------|-------------|
| 2GbE         | Bond2                | enp0s0, enp0s1                     |                                       |             |
| 2GbE         | Bond30               | enp0s2, enp0s3                     |                                       |             |
| 2GbE         | Bond40               | enp0s4, enp0s5                     |                                       |             |
|              |                      |                                    |                                       |             |
| **GbE Type** | **PVE Linux Bridge** | **Ports/Slaves (network devices)** | **Description and Purpose**           | **Vlan ID** |
| 10GbE        | vmbr0                | *enp68s0f0 (no bond)*              | VLAN1 - PVE HOST LAN                  | vlan1       |
| 2GbE         | vmbr2                | Bond2                              | VLAN2 - VPN Gateway Egress (VPN Exit) | vlan2       |
| 2GbE         | vmbr30               | Bond30                             | VPN World Gateway                     | vlan30      |
| 2GbE         | vmbr40               | Bond40                             | VPN Local Gateway                     | vlan40      |

The above tables is an example of the many combinations of network bonds and slaves available to you. But always remember to assign any available 10GbE or the first available PVE Linux Bond to PVE Linux Bridge vmbr0 which is your PVE-01 host LAN.

So with a PVE network configuration plan you must configure your PVE-01 connected network switch to use VLANs and in a pfSense environment you must also assign specific network switch ports to specific VLAN numbers and in the case of vmbr2 you must assign a IPv4 address. 

Our network is configured to use VLANs in accordance to the network road map shown [here](https://github.com/ahuacate/network-roadmap). 

When PVE hosts have multiple 1GbE NICs you can use NIC bonding (also called NIC teaming or Link Aggregation, LAG and in PVE Linux Network Bond) which is a technique for binding multiple NIC’s to a single network device. By doing link aggregation, two NICs can appear as one logical interface, resulting in double speed. This is a native Linux kernel feature that is supported by most smart L2/L3 switches with IEEE 802.3ad support.

On the network switch appliance side you are going to use 802.3ad Dynamic link aggregation (802.3ad)(LACP) so your switch must be 802.3ad compliant. This creates aggregation groups of NICs which share the same speed and duplex settings as each other. A link aggregation group (LAG) combines a number of physical ports together to make a single high-bandwidth data path, so as to implement the traffic load sharing among the member ports in the group and to enhance the connection reliability.

## 3.2. Network Options - Basic (no pfSense)

This is easy. Simply configure PVE Linux Bridge vmbr0 with a single 1GbE, 10GbE or a PVE Linux Bond for PVE Linux Bridge vmbr0. Nothing more to do. In our Easy Script you will be prompted for such configurations with no pfSense available.

## 3.3. Configure your Network Switch - pfSense

These instructions are based on a UniFi US-24 port switch. Just transpose the settings to UniFi US-48 or whatever brand of Layer 2/3 switch you use. The examples are guides for setting up the following network switch configurations:

- 3x LAN 1GbE
- 4x LAN 1Gb PLUS 10GbE SFP+
- 4x LAN 1GbE
- 6x LAN 1GbE

### 3.3.1. Set Network Switch port profiles and LAG groups - pfSense

For ease of port management I always use switch ports 1 - (4 or 6) for my primary PVE-01. Configure your network switch port profiles and LAG groups as follows:

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

The above table, based on a UniFi US-24 model, shows port 1+2 are link aggregated (LAG), port 3+4 are another LAG and ports 5 and 6 are NOT LAG'd. So ports 1 to 6 numbering on your switch correspond with the PVE-01 NIC devices (i.e. enp1s0 -  enp1s5) .

### 3.3.2. Create Network Switch VLANs - pfSense

Three VLANs are required.

1. VLAN2 - *WAN/VPN-egress (VLAN2)*
2. VLAN30 - *LAN-vpngate-world (VLAN30)*
3. VLAN40 - *LAN-vpngate-local (VLAN40)*

These instructions are specifically for UniFi controller `Settings` > `Networks` > `Create New Network`.

*  Create a new network to be used for Egress of encrypted traffic out of network to your VPN servers.

| Description    | Value                   | Notes                                                                                                                      |
|----------------|-------------------------|----------------------------------------------------------------------------------------------------------------------------|
| Name           | `VPN-egress`            | *This network will be used as the WAN for pfSense OpenVPN clients (encrypted exit).*                                       |
| Purpose        | `Guest`                 | *Network Guest security policies.*                                                                                         |
| VLAN           | `2`                     | *A dedicated VLAN for the WAN used by OpenVPN client(s) for network paths and firewall rules use Guest security policies.* |
| Gateway/Subnet | `192.168.2.5/28`        | *Only 2 addresses on this subnet so /29 is ideal*                                                                          |
| DHCP Server    | `Enabled`               | *Just use default range 192.168.2.1 -- 192.168.2.14*                                                                       |
| Other Settings | *Just leave as Default* |                                                                                                                            |

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

The pfSense VM is a fully functional independent OS with its own virtual networking. This pfSense virtual networking connects via bridges to your PVE-01 host computer PVE Linux Bridges (vmbr0, vmbr2,vmbr30 and optional vmbr40). So in summary its from one *bridge* to another *bridge*.

On creation of your PVE pfSense VM you will create a PVE VirtIO (paravirtualized) network devices inside the VM. Each pfSense VM Virtio device is bridged to a PVE Linux Bridge (i.e. vmbr0 etc). Your pfSense PVE VM hardware configuration, subject to your hosts networking capabilities, will resemble the following table:

| pfSense Network Device ID    | Settings                                          |
|------------------------------|---------------------------------------------------|
| <> Network Device (net0)     | virtio=3A:33:39:66:31:35,bridge=vmbr0,firewall=1  |
| <> Network Device (net1)     | virtio=1A:14:AE:3B:7B:35,bridge=vmbr2,firewall=1  |
| <> Network Device (net2)     | virtio=9E:1F:F9:5A:69:D1,bridge=vmbr30,firewall=1 |
| *Optional 4x LAN NIC below:* |                                                   |
| <> Network Device (net3)     | virtio=42:09:A0:3F:8C:8A,bridge=vmbr40,firewall=1 |

So when you configure and setup pfSense your pfSense Interfaces Assignments in the pfSense web management frontend will show:

| pfSense Interface                 | Network port               |
|-----------------------------------|----------------------------|
| LAN                               | vtnet0 (3A:33:39:66:31:35) |
| WAN ( *i.e VLAN2* )               | vtnet1 (1A:14:AE:3B:7B:35) |
| OPT1 ( *i.e Gateway for VLAN30* ) | vtnet2 (9E:1F:F9:5A:69:D1) |
| *Optional 4x LAN NIC below:*      |                            |
| OPT2 ( *i.e Gateway for VLAN40* ) | vtnet3 (42:09:A0:3F:8C:8A) |

When you install pfSense on host PVE-01 you must be assigned a LAN, WAN and your VPN gateway interfaces. Make sure the PVE VM Virtio MAC address corresponds with PVE Linux Bridge vmbr(x) ad is correctly assigned to the pfSense vtnet(x) assignments.

The pfSense WAN interface must be VLAN2 which is labelled in your UniFi controller (switch) as `VPN-egress`. Because it's configured with network `Guest security policies` in the UniFi controller it has no access to other network VLANs. The reason for this is explained build recipe for `VPN-egress` shown [here](#332-create-network-switch-vlans---pfsense).

For HAProxy to work you must authorize UniFi VLAN2 (WAN in pfSense addon service HAProxy) to have access to your Proxmox LXCs, CTs or VMs static container IPv4 addresses. These instructions are for a UniFi controller `Settings` > `Guest Control`  and look under the `Access Control` section. Under `Pre-Authorization Access` click`**+** Add IPv4 Hostname or subnet` to add the following IPv4 addresses to authorize access for VLAN2 clients. Fill out the form details as shown below:

| \+ Add IPv4 Hostname or subnet | Value          | Notes                  |
|--------------------------------|----------------|------------------------|
| IPv4                           | 192.168.50.111 | *Jellyfin Server*      |
| IPv4                           | 192.168.30.112 | *Nzbget Server*        |
| IPv4                           | 192.168.30.113 | *Deluge Server*        |
| IPv4                           | 192.168.50.114 | *Flexget Server*       |
| IPv4                           | 192.168.50.115 | *Sonarr Server*        |
| IPv4                           | 192.168.50.116 | *Radarr Server*        |
| IPv4                           | 192.168.50.117 | *Lidarr Server*        |
| IPv4                           | 192.168.50.118 | *Lazylibrarian Server* |
| IPv4                           | 192.168.50.119 | *Ombi Server*          |
| IPv4                           | 192.168.80.122 | *Syncthing Server*     |
| IPv4                           | 192.168.50.123 | *Media-rsync Server*   |

And click `Apply Changes`.

As you've probably concluded you must add any new HAProxy backend server IPv4 address(s) to the UniFi Pre-Authorization Access list for HAProxy frontend to have access to these servers.


# 4. Easy Script

Our single Easy Script can be used on both primary and secondary PVE hosts. Your user input is required. The script will create, edit and/or change system files on your PVE host. When an optional default setting is provided you can accept our default (recommended) by pressing ENTER on your keyboard. Or overwrite our default value by typing in your own value and then pressing ENTER to accept and to continue to the next step.

After executing the Easy Script in your PVE host SSH terminal you will asked or prompted for input about:

- Verify PVE enterprise subscription status - A patch will be applied if you do not have a valid PVE subscription
- Fully update your PVE host OS
- Install prerequisite software - nbtscan, ifupdown2
- Update PVE turnkey appliance list
- Increase the PVE inotify limits
- Perform PVE host UID/GID mapping for unprivileged CTs
- Select PVE host type - Primary or Secondary
- Configure your PVE host network interface card (NIC) 
- Optional - Create NFS and/or CIFS backend storage mounts for your PVE hosts (Recommended - Must be done at some stage)
- Optional - Install and configure Postfix SMTP email server and alerts (Recommended - requires a valid email & Mailgun credentials)
- Optional - Install and configure SSH Authorized Keys (Recommended)
- Optional - Install and configure Fail2Ban (Recommended)

The available options are different between primary and secondary hosts. Its best to perform all the recommended tasks. For example, by setting up the default Postfix SMTP server you will receive email copies of not only PVE alerts but also copies of newly created SSH keys pairs for your convenience.

## 4.1. Prerequisite Credentials and Input Requirements

During the Easy Script installation you will be required to provide some inputs. You will have the option to use our default variables on most variable inputs. It's best to have details like your SMTP server account login credentials and other input information readily available prior to running our Easy Script.

### 4.1.1. SMTP Server Credentials

You will have the option to install a SSMTP Email server. SSMTP is Mail Transfer Agent (MTA) used to send email alerts about your machine like details about new user accounts, unwarranted login attempts and system critical alerts to the system's designated administrator.

You will be asked for the credentials of a SMTP Server. You can use Gmail, Godaddy, AWS or any SMTP server credentials (i.e address, port, username and password, encryption type etc.

But we recommend you create a account at mailgun.com to relay your NAS system emails to your designated administrator. With mailgun you are not potentially exposing your private email server credentials held within a text file on your PVE host. This is a added layer of security.

## 4.2. Run our Easy Script

To execute a Easy Script SSH into your PVE host  (i.e. `ssh root@192.168.1.101`) or use the Proxmox web interface CLI shell `pve-0x` > `>_ Shell` and cut & paste the following into the CLI terminal window and press ENTER:

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/proxmox-node/master/scripts/typhoon-01-sfp_4x_NIC-setup-01.sh)"
```

On completion you will see on your CLI terminal words **"Success"** and your PVE host login credentials.



# 5. Other PVE Host Stuff

## 5.1. Create a PVE Cluster

Proxmox requires a  minimum of three PVE hosts on the same network to form a cluster - PVE-01, PVE-02 and PVE-03.

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

Using the PVE web interface on the OTHER hosts, PVE-02/03/04 etc, go to `Datacenter` > `Cluster` > `Join Cluster` and a new window will appear showing `Cluster Join` with the option to paste the `Cluster Join Information` into a `Information` field. Paste the information, enter your root password into the `Password` field and the other fields will automatically be filled.

And  Click `Join`. Repeat for on all nodes.

All PVE management can be done from the PVE-01 node.  Using the PVE web management WebGUI (https://192.168.1.101:8006) all added cluster hosts should be listed below `Datacenter (pve-cluster)`. Or type `pvecm status` into any host `pve-01` > `>_Shell`:

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

### 5.1.3. How to delete a existing cluster on a node

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

# 6. Patches and Fixes

## 6.1. pfSense – disable firewall with pfctl -d

If for whatever reason you have lost access to the pfSense web management console then go to the Proxmox web interface `pve-01` > `251 (pfsense)` > `>_ Console` and `Enter an option` numerical `8` to open a shell.

Then type and execute `pfctl -d` where the -d will temporally disable the firewall (you should see the confirmation in the shell `pf disabled`, where pf is the packet filter = FIREWALL)

Now you can log into the WAN side IP address (192.168.2.1) and govern the pfSense again to fix the problem causing pfSense web management console to cease working on 192.168.1.253.

## 6.2. Proxmox Backup Error - Permissions

If you get this error:

```
INFO: tar:  '/mnt/pve/nas-01-backup/dump/vzdump-lxc-111-2017_01_27-16_54_45.tmp: Cannot open: Permission denied
```

Fix is go to Proxmox `nas-01` > `>_Shell` and type the following:

```bash
chmod 755 /mnt/pve/nas-01-backup/dump
```

## 6.3. Simple bash script to APT update all LXC containers which are stopped or running status

The script will start stopped containers, update them and then shut them down in the background before moving on to next container.

To run script:

```
bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-build/master/scripts/update_all_containers.sh)"
```
