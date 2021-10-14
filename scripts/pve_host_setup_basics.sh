#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_setup_basics.sh
# Description:  Basic mods for Proxmox (PVE) Host machines
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------

#bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-setup/master/scripts/pve_host_setup_basics.sh)"

#---- Source -----------------------------------------------------------------------

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
PVE_SOURCE="$DIR/../../common/pve/source"
BASH_SOURCE="$DIR/../../common/bash/source"

#---- Dependencies -----------------------------------------------------------------

# Check for Internet connectivity
if nc -zw1 google.com 443; then
  echo
else
  echo "Checking for internet connectivity..."
  echo -e "Internet connectivity status: \033[0;31mDown\033[0m\n\nCannot proceed without a internet connection.\nFix your PVE hosts internet connection and try again..."
  echo
  exit 0
fi

# First update
apt-get update -y > /dev/null

# Run Bash Header
source $PVE_SOURCE/pvesource_bash_defaults.sh

#---- Static Variables -------------------------------------------------------------

# Easy Script Section Header Body Text
SECTION_HEAD='PVE Host Basic Setup'

#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------

#---- Introduction
section "Introduction"

msg_box "#### PLEASE READ CAREFULLY - PVE HOST BASICS ####\n
This setup script is for configuring 'new' PVE hosts only. Tasks to be performed include:

      PREREQUISITES BASICS
  --  Set Proxmox subscription status
  --  Install Nbtscan, ifupdown2 SW
  --  Adjust sysctl parameters
  --  Adjust swappiness
  --  PVE Container (CT) Mapping ( A MUST if you want to use any of our PVE VM or CT builds )"

echo
while true; do
  read -p "Perform PVE host basic tuning ( Must do - Recommended ) [y/n]?: " -n 1 -r YN
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
      exit 0
      break
      ;;
    *)
      warn "Error! Entry must be 'y' or 'n'. Try again..."
      echo
      ;;
  esac
done

#---- Performing PVE Host Prerequisites
section "PVE Host Basics"

# Update PVE OS
while true; do
  msg "Verifying PVE host subscription status-.."
  if [ $(pvesubscription get | grep "status:.*" | awk '{ print $2 }' | tr '[:upper:]' '[:lower:]') = "notfound" ]; then
    msg "No valid Proxmox (PVE) subscription key is installed. A valid PVE subscription key is needed to access the Proxmox pve-enterprise level update repository. This costs money. ${WHITE}But its not required (for home use).${NC}

    If the User has a valid PVE subscription then enter '${WHITE}Y/y${NC}' at the next prompt. If not, then enter '${WHITE}N/n${NC}' at the next prompt (RECOMMENDED)."
    echo
    while true; do
      read -p "Does the User possess a valid PVE enterprise subscription key [y/n]?: " -n 1 -r YN
      echo
      case $YN in
        [Yy]*)
          msg "The Proxmox subscription key must be installed before proceeding. Take the following steps:

            Go to PVE web interface: ${YELLOW}https://`hostname -i`:8006${NC}
            Default login username: ${YELLOW}root${NC}
            Password: ${YELLOW}You must have it.${NC}
                      
          The root user password is what the installer specified during the PVE installation process. This script will exit in 3 seconds. Complete the above tasks and try again..."
          sleep 3
          exit 0
          ;;
        [Nn]*)
          if [ -f "/etc/apt/sources.list.d/pve-enterprise.list" ]; then
            rm /etc/apt/sources.list.d/pve-enterprise.list > /dev/null
          fi
          echo 'deb http://download.proxmox.com/debian/pve buster pve-no-subscription' > /etc/apt/sources.list.d/pve-no-subscription.list
          #sed -i -r '/^#?deb https:\/\/enterprise.proxmox.com\/debian\/pve buster pve-enterprise/c\#deb https:\/\/enterprise.proxmox.com\/debian\/pve buster pve-enterprise' /etc/apt/sources.list.d/pve-enterprise.list
          info "PVE subscription status is: ${YELLOW}$(pvesubscription get | grep "status:.*" | awk '{ print $2 }')${NC}\nProceeding with PVE updates and upgrades. None Subscription edition."
          break 2
          ;;
        *)
          warn "Error! Entry must be 'y' or 'n'. Try again..."
          echo
          ;;
      esac
    done
  elif [ $(pvesubscription get | grep "status:.*" | awk '{ print $2 }' | tr '[:upper:]' '[:lower:]') = "active" ]; then
    info "PVE subscription status: ${YELLOW}$(pvesubscription get | grep "status:.*" | awk '{ print $2 }')${NC}\nProceeding with PVE updates and upgrades. Subscription edition."
    break
  elif [ $(pvesubscription get | grep "status:.*" | awk '{ print $2 }' | tr '[:upper:]' '[:lower:]') != "active" ] || [ $(pvesubscription get | grep "status:.*" | awk '{ print $2 }' | tr '[:upper:]' '[:lower:]') != "notfound" ]; then
    msg "Cannot validate the PVE hosts subscription key status. The PVE subscription key may have expired or the PVE host cannot connect to the Proxmox key validation server. The User has two choices to solve this problem:"
    # Set PVE subscription key fix
    TYPE01="${YELLOW}Key Delete${NC} - Delete any existing PVE subscription key and try again."
    TYPE02="${YELLOW}Exit${NC} - Exit this script, manually fix the problem & try again."
    PS3="Select the steps to be taken (entering numeric) : "
    msg "Available options:"
    options=("$TYPE01" "$TYPE02")
    select menu in "${options[@]}"; do
      case $menu in
        "$TYPE01")
          pvesubscription delete >/dev/null
          pvesubscription update >/dev/null
          msg "PVE subscription key has been deleted. Try again..."
          echo
          sleep 1
          ;;
        "$TYPE02")
          info "The User has chosen to skip this step. Aborting configuration."
          sleep 1
          exit 0
          ;;
        *) warn "Invalid entry. Try again.." >&2
      esac
    done
  fi
done
echo

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

# nbtscan SW
if [ $(dpkg -s nbtscan >/dev/null 2>&1; echo $?) = 0 ]; then
  msg "Checking nbtscan status..."
  info "nbtscan status: ${GREEN}active (running).${NC}"
  echo
else
  msg "Installing nbtscan..."
  apt-get install -y nbtscan >/dev/null
  if [ $(dpkg -s nbtscan >/dev/null 2>&1; echo $?) = 0 ]; then
    info "nbtscan status: ${GREEN}active (running).${NC}"
  fi
  echo
fi

# ifupdown2 SW
if [ $(dpkg -s ifupdown2 >/dev/null 2>&1; echo $?) = 0 ]; then
  msg "Checking ifupdown2 status..."
  info "ifupdown2 status: ${GREEN}active (running).${NC}"
  echo
else
  msg "Installing ifupdown2..."
  apt-get install -y ifupdown2 >/dev/null
  if [ $(dpkg -s ifupdown2 >/dev/null 2>&1; echo $?) = 0 ]; then
    info "ifupdown2 status: ${GREEN}active (running).${NC}"
  fi
  echo
fi

# Update turnkey appliance list
msg "Performing turnkey appliance list updates..."
pveam update >/dev/null

# PVE sysctl tunes
msg "Adjusting sysctl parameters..."
# Increase the inotify limits
# Max Queued Ecents
if [[ $(cat /etc/sysctl.conf | grep "fs.inotify.max_queued_events =.*") ]]; then
  sed -i -r '/^#?fs.inotify.max_queued_events =.*/c\fs.inotify.max_queued_events = 16384' /etc/sysctl.conf
else
  echo "fs.inotify.max_queued_events = 16384" >> /etc/sysctl.conf
fi
# Max User Instances
if [[ $(cat /etc/sysctl.conf | grep "fs.inotify.max_user_instances =.*") ]]; then
  sed -i -r '/^#?fs.inotify.max_user_instances =.*/c\fs.inotify.max_user_instances = 512' /etc/sysctl.conf
else
  echo "fs.inotify.max_user_instances = 512" >> /etc/sysctl.conf
fi
# Max User Watches
if [[ $(cat /etc/sysctl.conf | grep "fs.inotify.max_user_watches =.*") ]]; then
  sed -i -r '/^#?fs.inotify.max_user_watches =.*/c\fs.inotify.max_user_watches = 8192' /etc/sysctl.conf
else
  echo "fs.inotify.max_user_watches = 8192" >> /etc/sysctl.conf
fi

# Adjust Swappiness
if [ $(grep MemTotal /proc/meminfo | awk '{print $2 / 1024 / 1000}' | awk '{print int($1+0.5)}') -ge 16 ]; then
  msg "Adjusting PVE swappiness value to 10..."
  sysctl vm.swappiness=10 > /dev/null
  swapoff -a
  swapon -a
fi
echo


#---- PVE Container Mapping
if [[ ! $(grep -qxF 'root:65604:100' /etc/subgid) ]] && [[ ! $(grep -qxF 'root:100:1' /etc/subgid) ]] && [[ ! $(grep -qxF 'root:1605:1' /etc/subuid) ]] && [[ ! $(grep -qxF 'root:1606:1' /etc/subuid) ]] && [[ ! $(grep -qxF 'root:1607:1' /etc/subuid) ]]; then
  section "PVE Container UID/GID Mapping"
  msg_box "Unprivileged LXC containers have issues with UIDs (User ID) and GIDs (Group ID) permissions with bind mounted shared data. With PVE virtual machines the UIDs and GIDs are mapped to a different number range than on the host machine, where root (uid 0) becomes uid 100000, 1 will be 100001 and so on. Our default User and Groups used on our NAS server, PVE VMs and LXC/CTs are:

    --  GROUP: medialab (gid 65605) > USER: media (uid 1605) > APPS: JellyFin, NZBGet, Deluge, Sonarr, Radarr, LazyLibrarian, Flexget

    --  GROUP: homelab (gid 65606) > USER: home (uid 1606) > APPS: Syncthing, NextCloud, UniFi, Home Assistant, CCTV

    --  GROUP: privatelab (gid 65607) > USER: private (uid 1607) > APPS: All things private.
    
  Our high GID number (Group ID) is to cater for the Synology GID creation scheme. To maintain user permissions and rights to a NAS filse system the fix is to create UID and GID mapping on all PVE hosts. We need to define two ranges:
    
    1. One where the system IDs (i.e root uid 0) of the container can be mapped to an arbitrary range on the host for security reasons.
    
    2. And where NAS and notably Synology UID/GIDs above 65536 inside a container can be mapped to the same UID/GIDs on the PVE host.
    
    The following lines are added:
    
      --  EDITS TO /etc/subuid
          root:65604:100 root:1605:1 root:1606:1 root:1607:1
      --  EDITS TO /etc/subgid
          root:65604:100 root:100:1

  This modification ${UNDERLINE}must be performed${NC} if you want to use any of our PVE VM or CT builds."
  echo
  while true; do
    read -p "Create the PVE host UID/GID mapping ( HIGHLY RECOMMENDED ) [y/n]?: " -n 1 -r YN
    echo
    case $YN in
      [Yy]*)
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
        break
        ;;
      [Nn]*)
        info "You have chosen to skip this step."
        echo
        break
        ;;
      *)
        warn "Error! Entry must be 'y' or 'n'. Try again..."
        echo
        ;;
    esac
  done
fi

#---- Finish Line ------------------------------------------------------------------