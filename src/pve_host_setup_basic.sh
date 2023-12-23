#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_setup_basic.sh
# Description:  Basic mods for Proxmox (PVE) Host machines
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------
#---- Source -----------------------------------------------------------------------
#---- Dependencies -----------------------------------------------------------------
#---- Static Variables -------------------------------------------------------------

# Easy Script Section Header Body Text
SECTION_HEAD='PVE Host Basic Setup'

#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------

#---- Prerequisites

# First update
apt-get update -y > /dev/null

# nbtscan SW
if [[ ! $(dpkg -s nbtscan 2> /dev/null) ]]
then
  msg "Installing nbtscan..."
  apt-get install -y nbtscan >/dev/null
  info "nbtscan status: ${GREEN}active${NC}"
  echo
fi


#---- Introduction
section "Introduction"

msg_box "#### PLEASE READ CAREFULLY - PVE HOST BASICS ####\n
This setup script is for configuring 'new' PVE hosts only. Tasks to be performed include:

      PREREQUISITES BASICS
  --  Update Proxmox
  --  Check and set Proxmox subscription key (free or enterprise)
  --  Install nbtscan SW
  --  Adjust sysctl parameters
  --  Set PVE boot delay to 300 sec ( allows for NAS to start/online on power outage )
  --  Perform PVE container (CT) mapping ( required for all our PVE VM or CT builds )"
echo
while true
do
  read -p "Perform PVE host basic tuning ( Recommended ) [y/n]?: " -n 1 -r YN
  echo
  case $YN in
    [Yy]*)
      info "The User has chosen to proceed."
      echo
      break
      ;;
    [Nn]*)
      info "You have chosen to skip this step."
      echo
      return
      ;;
    *)
      warn "Error! Entry must be 'y' or 'n'. Try again..."
      echo
      ;;
  esac
done

#---- Performing PVE Host Prerequisites
section "PVE Host Basics"

# Verify subscription key
msg "Verifying PVE host subscription status..."
if [ $(pvesubscription get | grep "status:.*" | awk '{ print $2 }' | tr '[:upper:]' '[:lower:]') != 'active' ] && [[ ! $(cat /etc/apt/sources.list | grep '^deb.*pve-no-subscription$') ]]; then
  msg_box "#### PLEASE READ CAREFULLY - PROXMOX SUBSCRIPTION KEYS ####\n\nNo paid Proxmox 'pve-enterprise' or 'pve-no-subscription' key is installed. A paid PVE subscription key is needed to access the Proxmox pve-enterprise level update repository. This costs money. But its not required for personal or home use.\n\nThe Proxmox 'pve-no-subscription' key is free for personal or home use only (Recommended)."

  OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE02" "TYPE00")
  OPTIONS_LABELS_INPUT=( "Free Version - Proxmox with no subscription key (Recommended)" "Paid Enterprise version - You have a valid license key" "None. Return to the Toolbox" )
  makeselect_input2
  singleselect SELECTED "$OPTIONS_STRING"

  if [ "$RESULTS" = 'TYPE01' ]
  then
    # pve-no-subscription
    msg "Setting PVE host to PVE to 'pve-no-subscription'..."
    if [ -f "/etc/apt/sources.list.d/pve-enterprise.list" ]
    then
      rm /etc/apt/sources.list.d/pve-enterprise.list > /dev/null
    fi
    # Remove any old 'pve-no-subscription'
    sed -i '/^.*pve-no-subscription$/d' /etc/apt/sources.list
    # Add debian 'pve-no-subscription' deb
    PVE_CODENAME=$(cat /etc/os-release | awk -F'=' '/VERSION_CODENAME/ { print $2 }')
    echo "deb http://download.proxmox.com/debian/pve $PVE_CODENAME pve-no-subscription" >> /etc/apt/sources.list
    # Update new list
    apt-get update -yqq
    info "PVE subscription status is: ${YELLOW}pve-no-subscription${NC}"
  elif [ "$RESULTS" = 'TYPE02' ]
  then
    # pve-enterprise
    msg "Use the Proxmox enterprise key guide to install and activate your key. Once complete re-run this installer. This script will exit in 3 seconds. Bye..."
    sleep 3
    return
  elif [ "$RESULTS" = 'TYPE00' ]
  then
    return
  fi
elif [ "$(pvesubscription get | grep "status:.*" | awk '{ print $2 }' | tr '[:upper:]' '[:lower:]')" = 'active' ]
then
  info "PVE subscription status: ${YELLOW}pve-enterprise edition${NC}"
elif [[ $(cat /etc/apt/sources.list | grep '^deb.*pve-no-subscription$') ]]
then
  info "PVE subscription status: ${YELLOW}pve-no-subscription${NC}"
else
  # Fail msg
  FAIL_MSG="Cannot determine the PVE hosts subscription key status:\n
    Possible causes
    --  PVE subscription key has have expired (enterprise edition/paid version).
    --  PVE host cannot connect to the Proxmox key validation server (enterprise edition/paid version).
    Resolution
    --  Reinstall subscription key.
    --  Perform CLI 'apt-get update' and 'apt-get upgrade' and check for errors.
    --  Try restarting the PVE host.
    --  Use the PVE WebGUI to set the update repository setting.
    This script will exit in 3 seconds. Complete the above tasks and try again..."
  warn "$FAIL_MSG"
  sleep 3
  return
fi
echo


# Update PVE OS
msg "Performing PVE update..."
apt-get -y update > /dev/null 2>&1
msg "Performing PVE upgrade..."
apt-get -yqq upgrade > /dev/null 2>&1
msg "Performing PVE full upgrade (Linux Kernel if required)..."
apt-get -y full-upgrade > /dev/null 2>&1
msg "Performing PVE clean..."
apt-get -y clean > /dev/null 2>&1
msg "Performing PVE autoremove..."
apt-get -y autoremove > /dev/null 2>&1

# Update turnkey appliance list
msg "Performing turnkey appliance list updates..."
pveam update >/dev/null

# PVE sysctl tunes
msg "Adjusting sysctl parameters..."
# Increase the inotify limits
# Max Queued Ecents
if [[ $(cat /etc/sysctl.conf | grep "fs.inotify.max_queued_events =.*") ]];
then
  sed -i -r '/^#?fs.inotify.max_queued_events =.*/c\fs.inotify.max_queued_events = 16384' /etc/sysctl.conf
else
  echo "fs.inotify.max_queued_events = 16384" >> /etc/sysctl.conf
fi
# Max User Instances
if [[ $(cat /etc/sysctl.conf | grep "fs.inotify.max_user_instances =.*") ]]
then
  sed -i -r '/^#?fs.inotify.max_user_instances =.*/c\fs.inotify.max_user_instances = 512' /etc/sysctl.conf
else
  echo "fs.inotify.max_user_instances = 512" >> /etc/sysctl.conf
fi
# Max User Watches
if [[ $(cat /etc/sysctl.conf | grep "fs.inotify.max_user_watches =.*") ]]
then
  sed -i -r '/^#?fs.inotify.max_user_watches =.*/c\fs.inotify.max_user_watches = 8192' /etc/sysctl.conf
else
  echo "fs.inotify.max_user_watches = 8192" >> /etc/sysctl.conf
fi

# Set /etc/vzdump.conf tmp dir
msg "Setting vzdump temporary dir variable..."
sed -i -r '/^#?tmpdir:.*/c\tmpdir: \/tmp' /etc/vzdump.conf
echo

# Edit /etc/default/grub boot delay
if [ -e /etc/default/grub ]; then
  sed -i 's/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=300/' /etc/default/grub
  update-grub
fi


#---- PVE Container Mapping
if [[ ! $(grep -qxF 'root:65604:100' /etc/subgid) ]] && [[ ! $(grep -qxF 'root:100:1' /etc/subgid) ]] && [[ ! $(grep -qxF 'root:1605:1' /etc/subuid) ]] && [[ ! $(grep -qxF 'root:1606:1' /etc/subuid) ]] && [[ ! $(grep -qxF 'root:1607:1' /etc/subuid) ]]
then
  section "PVE Container UID & GID Mapping"

  msg_box "#### PLEASE READ CAREFULLY - UID & GID HOST MAPPING ####
  
  Unprivileged LXC containers have a issue with UIDs (User ID) and GIDs (Group ID) permissions and bind mounted shared data. With PVE VM/CTs the UIDs and GIDs are mapped to a different number range than that used on the host machine, where root (uid 0) becomes uid 100000, 1 will be 100001 and so on. Our default Users and Groups used on our NAS, PVE VMs and CTs are:

    --  GROUP: medialab (gid 65605) > USER: media (uid 1605)
        APPS: JellyFin, NZBGet, Deluge, Sonarr, Radarr, LazyLibrarian, Flexget etc

    --  GROUP: homelab (gid 65606) > USER: home (uid 1606)
        APPS: Syncthing, NextCloud, UniFi, Home Assistant, CCTV

    --  GROUP: privatelab (gid 65607) > USER: private (uid 1607)
        APPS: All things private.
    
  Our high GID number (Group ID) is to cater for the Synology GID creation scheme. To maintain user permissions and rights to a NAS file system the fix is to create UID and GID mapping on all PVE hosts. We need to define two ranges:
    
    1. One where the system IDs (i.e root uid 0) of the container can be mapped to an arbitrary range on the host for security reasons.
    
    2. And where NAS and notably Synology UID/GIDs above 65536 inside a container can be mapped to the same UID/GIDs on the PVE host.
    
    The following lines are added:
    
      --  EDITS TO /etc/subuid
          root:65604:100 root:1605:1 root:1606:1 root:1607:1
      --  EDITS TO /etc/subgid
          root:65604:100 root:100:1

  This modification is mandatory when using our PVE VM or CT builds."
  echo
  # UID and GID maps
  msg "Performing UID & GID host mapping..."
  grep -qxF 'root:65604:100' /etc/subuid || echo 'root:65604:100' >> /etc/subuid
  grep -qxF 'root:65604:100' /etc/subgid || echo 'root:65604:100' >> /etc/subgid
  info "Group GID mapping status: ${YELLOW}set${NC}"
  grep -qxF 'root:100:1' /etc/subgid || echo 'root:100:1' >> /etc/subgid
  info "User root uid mapping status: ${YELLOW}set${NC}"
  grep -qxF 'root:1605:1' /etc/subuid || echo 'root:1605:1' >> /etc/subuid
  info "User media uid mapping status: ${YELLOW}set${NC}"
  grep -qxF 'root:1606:1' /etc/subuid || echo 'root:1606:1' >> /etc/subuid
  info "User home uid mapping status: ${YELLOW}set${NC}"
  grep -qxF 'root:1607:1' /etc/subuid || echo 'root:1607:1' >> /etc/subuid
  info "User private uid mapping status: ${YELLOW}set${NC}"
  echo
fi


#---- Finish Line ------------------------------------------------------------------

section "Completion Status"
msg "Success. Task complete."
echo
#-----------------------------------------------------------------------------------