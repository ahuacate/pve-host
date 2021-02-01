#!/usr/bin/env bash

set -Eeuo pipefail
shopt -s expand_aliases
alias die='EXIT=$? LINE=$LINENO error_exit'
trap die ERR
trap cleanup EXIT
function error_exit() {
  trap - ERR
  local DEFAULT='Unknown failure occured.'
  local REASON="\e[97m${1:-$DEFAULT}\e[39m"
  local FLAG="\e[91m[ERROR] \e[93m$EXIT@$LINE"
  msg "$FLAG $REASON"
  [ ! -z ${CTID-} ] && cleanup_failed
  exit $EXIT
}
function warn() {
  local REASON="\e[97m$1\e[39m"
  local FLAG="\e[93m[WARNING]\e[39m"
  msg "$FLAG $REASON"
}
function info() {
  local REASON="$1"
  local FLAG="\e[36m[INFO]\e[39m"
  msg "$FLAG $REASON"
}
function msg() {
  local TEXT="$1"
  echo -e "$TEXT"
}
function section() {
  local REASON="  \e[97m$1\e[37m"
  printf -- '-%.0s' {1..100}; echo ""
  msg "$REASON"
  printf -- '-%.0s' {1..100}; echo ""
  echo
}
function cleanup_failed() {
  if [ ! -z ${MOUNT+x} ]; then
    pct unmount $CTID
  fi
  if $(pct status $CTID &>/dev/null); then
    if [ "$(pct status $CTID | awk '{print $2}')" == "running" ]; then
      pct stop $CTID
    fi
    pct destroy $CTID
  elif [ "$(pvesm list $STORAGE --vmid $CTID)" != "" ]; then
    pvesm free $ROOTFS
  fi
}
function pushd () {
  command pushd "$@" &> /dev/null
}
function popd () {
  command popd "$@" &> /dev/null
}
function cleanup() {
  popd
  rm -rf $TEMP_DIR
  unset TEMP_DIR
}
function load_module() {
  if ! $(lsmod | grep -Fq $1); then
    modprobe $1 &>/dev/null || \
      die "Failed to load '$1' module."
  fi
  MODULES_PATH=/etc/modules
  if ! $(grep -Fxq "$1" $MODULES_PATH); then
    echo "$1" >> $MODULES_PATH || \
      die "Failed to add '$1' module to load at boot."
  fi
}
function box_out() {
  set +u
  local s=("$@") b w
  for l in "${s[@]}"; do
	((w<${#l})) && { b="$l"; w="${#l}"; }
  done
  tput setaf 3
  echo -e " -${b//?/-}-\n| ${b//?/ } |"
  for l in "${s[@]}"; do
	printf '| %s%*s%s |\n' "$(tput setaf 7)" "-$w" "$l" "$(tput setaf 3)"
  done
  echo -e "| ${b//?/ } |\n -${b//?/-}-"
  tput sgr 0
  set -u
}

# Colour
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
GREEN=$'\033[0;32m'
WHITE=$'\033[1;37m'
NC=$'\033[0m'

# Resize Terminal
printf '\033[8;40;120t'

# Detect modules and automatically load at boot
load_module aufs
load_module overlay

# Set Temp Folder
if [ -z "${TEMP_DIR+x}" ]; then
  TEMP_DIR=$(mktemp -d)
  pushd $TEMP_DIR >/dev/null
else
  if [ $(pwd -P) != $TEMP_DIR ]; then
    cd $TEMP_DIR >/dev/null
  fi
fi

# Checking for Internet connectivity
msg "Checking for internet connectivity..."
if nc -zw1 google.com 443; then
  info "Internet connectivity status: ${GREEN}Active${NC}"
  echo
else
  warn "Internet connectivity status: ${RED}Down${NC}\n          Cannot proceed without a internet connection.\n          Fix your PVE hosts internet connection and try again..."
  echo
  cleanup
  exit 0
fi

# Script Variables
SECTION_HEAD="PVE Host Build & Configure"

# Download external scripts
wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-build/master/scripts/pve_add_nfs_mounts.sh
wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-build/master/scripts/pve_add_cifs_mounts.sh
wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-build/master/scripts/pve_setup_postfix.sh
wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-build/master/scripts/pve_setup_sshkey.sh
wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-build/master/scripts/pve_setup_fail2ban.sh


#########################################################################################
# This script is for building and configuring your Proxmox Hosts                        #
#                                                                                       #
# Tested on Proxmox Version : pve-manager/6.1-3/37248ce6 (running kernel: 5.3.10-1-pve) #
#########################################################################################


# Command to run script
#bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-build/master/scripts/pve_host_build.sh)"

# Clear the screen
clear
sleep 2
echo

#### Performing PVE Host Prerequisites ####
section "$SECTION_HEAD - Performing Prerequisites"

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

# CIDR to netmask conversion
cdr2mask ()
{
   # Number of args to shift, 255..255, first non-255 byte, zeroes
   set -- $(( 5 - ($1 / 8) )) 255 255 255 255 $(( (255 < (8 - ($1 % 8))) & 255 )) 0 0 0
   [ $1 -gt 1 ] && shift $1 || shift
   echo ${1-0}.${2-0}.${3-0}.${4-0}
}


# Update PVE OS
while true; do
  msg "Verifying the PVE subscription status of this hardware node..."
  if [ $(pvesubscription get | grep "status:.*" | awk '{ print $2 }' | tr '[:upper:]' '[:lower:]') = "notfound" ]; then
    msg "You do not have a valid installed Proxmox (PVE) subscription key. You\nneed a valid PVE subscription key to access Proxmox pve-enterprise level update\nrepository. This costs money. ${WHITE}But its not required (for home use).${NC}\n\nIf you have a valid Proxmox subscription key but have not installed it then its\nbest to do so. Enter '${WHITE}y${NC}' at the next prompt.\n\nIf you do NOT have a valid PVE subscription key then enter '${WHITE}n${NC}' at the\nnext prompt (RECOMMENDED)."
    echo
    read -p "Do you have a valid Proxmox enterprise subscription key [y/n]? " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      msg "You need to install your Proxmox subscription key before proceeding using the\nPVE web interface. Take the following steps:\n\n    PVE web interface: ${YELLOW}https://`hostname -i`:8006${NC}\n    Default login username: ${YELLOW}root${NC}\n    Password: ${YELLOW}You must have it.${NC}\n\nThe root user password is what you specified during the PVE installation process.\n\nThis script will exit in 3 seconds. Complete the above tasks and try again..."
      sleep 3
      cleanup
      exit 0
    else
      sed -i -r '/^#?deb https:\/\/enterprise.proxmox.com\/debian\/pve buster pve-enterprise/c\#deb https:\/\/enterprise.proxmox.com\/debian\/pve buster pve-enterprise' /etc/apt/sources.list.d/pve-enterprise.list
      info "PVE subscription status is: ${YELLOW}$(pvesubscription get | grep "status:.*" | awk '{ print $2 }')${NC}\nProceeding with PVE updates and upgrades. No Subscription edition."
      break
    fi
  elif [ $(pvesubscription get | grep "status:.*" | awk '{ print $2 }' | tr '[:upper:]' '[:lower:]') = "active" ]; then
    info "PVE subscription status is: ${YELLOW}$(pvesubscription get | grep "status:.*" | awk '{ print $2 }')${NC}\nProceeding with PVE updates and upgrades. Subscription edition."
  elif [ $(pvesubscription get | grep "status:.*" | awk '{ print $2 }' | tr '[:upper:]' '[:lower:]') != "active" ] || [ $(pvesubscription get | grep "status:.*" | awk '{ print $2 }' | tr '[:upper:]' '[:lower:]') != "notfound" ]; then
    msg "Cannot validate your Proxmox (PVE) subscription key status. Your PVE\nsubscription key may have expired or your PVE host cannot connect to the Proxmox\nkey validation server. You have two choices to solve this problem:"
    # Set PVE subscription key fix
    TYPE01="${YELLOW}Key Delete${NC} - Delete any existing PVE subscription key and try again."
    TYPE02="${YELLOW}Exit${NC} - Exit this script, fix the problem & try again."
    PS3="Select the steps to be taken (entering numeric) : "
    msg "Available options:"
    options=("$TYPE01" "$TYPE02")
    select menu in "${options[@]}"; do
      case $menu in
        "$TYPE01")
          pvesubscription delete >/dev/null
          pvesubscription update >/dev/null
          msg "PVE scubscription key has been deleted. Try again..."
          echo
          sleep 1
          ;;
        "$TYPE02")
          info "You have chosen to skip this step. Aborting configuration."
          sleep 1
          cleanup
          exit 0
          ;;
        *) warn "Invalid entry. Try again.." >&2
      esac
    done
  fi
done
echo

msg "Performing PVE update..."
apt -y update > /dev/null 2>&1
msg "Performing PVE upgrade..."
apt -y upgrade > /dev/null 2>&1
msg "Performing PVE full upgrade (Linux Kernel if required)..."
apt -y full-upgrade > /dev/null 2>&1
msg "Performing PVE clean..."
apt -y clean > /dev/null 2>&1
msg "Performing PVE autoremove..."
apt -y autoremove > /dev/null 2>&1

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



#### Introduction ####
section "$SECTION_HEAD - Introduction."

box_out '#### PLEASE READ CAREFULLY - INTRODUCTION ####' '' 'This script is for configuring your PVE hosts. User input is required.' 'The script will create, edit and/or change system files on your PVE host.' 'When an optional default setting is provided you can accept our' 'default (Recommended) by pressing ENTER on your keyboard. Or overwrite our' 'default value by typing in your own value and then pressing ENTER to' 'accept and to continue to the next step.' '' 'In the next steps you will asked to build, create or configure:' '  --  Configure your PVE host network interface card (NIC).' '  --  Create NFS and/or CIFS backend storage pools for your PVE hosts.' '' '      OPTIONAL TASKS' '  --  Configure PVE mail alerts.' '  --  Install and configure Fail2Ban.'

echo
read -p "Proceed to setup your PVE host $HOSTNAME [y/n]? " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  PVE_BUILD=0 >/dev/null
else
  PVE_BUILD=1 >/dev/null
  info "You have chosen to skip this step. Aborting configuration."
  cleanup
  exit 0
fi
echo

#### PVE Container Mapping ####
if [[ $(grep -qxF 'root:65604:100' /etc/subgid) ]] && [[ $(grep -qxF 'root:100:1' /etc/subgid) ]] && [[ $(grep -qxF 'root:1605:1' /etc/subuid) ]] && [[ $(grep -qxF 'root:1606:1' /etc/subuid) ]] && [[ $(grep -qxF 'root:1607:1' /etc/subuid) ]]; then
  section "$SECTION_HEAD - Unprivileged LXC Containers and file permissions"
  while true; do
    box_out 'With unprivileged LXC containers you will have issues with UIDs (user id) and' 'GIDs (group id) permissions with bind mounted shared data. With PVE the UIDs' 'and GIDs are mapped to a different number range than on the host machine,' 'usually root (uid 0) became uid 100000, 1 will be 100001 and so on.' '' 'Our default user and groups used on our NAS server, PVE VMs and LXC/CTs are:' '' '  --  GROUP: medialab (gid 65605)' '      USER: media (uid 1605)' '      APPS: JellyFin, NZBGet, Deluge, Sonarr, Radarr, LazyLibrarian, Flexget' '' '  --  GROUP: homelab (gid 65606)' '      USER: home (uid 1606)' '      APPS: Syncthing, NextCloud, UniFi, Home Assistant, CCTV' '' '  --  GROUP: privatelab (gid 65607)' '      USER: private (uid 1607)' '      APPS: All things private.' 'The high GID number (group ID) is to cater for a Synology GID creation scheme.' '' 'So we do not get permission and denied access errors to the NAS the fix is to' 'create UID and GID mapping on all PVE hosts. So we need to define two ranges:' '      1. One where the system IDs (i.e root uid 0) of the container can be' '         mapped to an arbitrary range on the host for security reasons.' '      2. And where NAS and notably Synology UID/GIDs above 65536 inside a' '         container can be mapped to the same UID/GIDs on the PVE host.' '' 'The following lines are added:' '' '  --  EDITS TO /etc/subuid' '      root:65604:100' '      root:1605:1' '      root:1606:1' '      root:1607:1' '  --  EDITS TO /etc/subgid' '      root:65604:100' '      root:100:1' '' 'You MUST perform this fix if you want to use any of our VM or CT builds.'
    echo
    read -p "Proceed to setup your PVE host UID/GID mapping (RECOMMENDED) [y/n]? " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
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
    else
      read -p "Please confirm. Are you sure (IT IS RECOMMENDED) [y/n]? " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "You have chosen to skip this step. Proceeding with no UID & GID mapping."
        echo
        break
      else
        info "Good decision. Try again..."
        echo
      fi
    fi
  done
fi

#### Setting PVE Host Variables ####
section "$SECTION_HEAD - Setting Variables"

box_out '#### PLEASE READ CAREFULLY - PVE BUILD TYPE ####' '' 'We need to determine the type of PVE host you are building. There are two' 'types of PVE builds:' '' '      PRIMARY TYPE' '  --  Primary PVE host is your first Proxmox machine.' '  --  Primary PVE hostnames are denoted by "-01".' '  --  Default hostname is pve-01.' '  --  Default primary host IPv4 address is 192.168.1.101.' '' '      SECONDARY TYPE' '  --  Secondary PVE hosts are cluster machines.' '  --  Proxmox requires a minimum of 3x PVE hosts to form a cluster.' '  --  Secondary PVE hostnames are denoted by "-02" onwards.' '  --  Default hostname naming convention begins from pve-02 (i.e 03,0x).' '  --  Default secondary host IPv4 addresses begin from 192.168.1.102.'

# Set PVE Build Type
TYPE01="${YELLOW}Primary${NC} - Primary PVE host."
TYPE02="${YELLOW}Secondary${NC} - Secondary PVE host, cluster machine."
PS3="Select the PVE host type you are building (entering numeric) : "
msg "Available options:"
options=("$TYPE01" "$TYPE02")
select menu in "${options[@]}"; do
  case $menu in
    "$TYPE01")
      info "PVE host type is set as : $(echo $menu | awk '{print $1}')"
      PVE_TYPE=0
      echo
      break
      ;;
    "$TYPE02")
      info "PVE host type is set as : $(echo $menu | awk '{print $1}')"
      PVE_TYPE=1
      echo
      break
      ;;
    *) warn "Invalid entry. Try again.." >&2
  esac
done


# Network Setup
msg "You have the option to modify your PVE host network setup.\nYour PVE host machine is installed with the following NICs:"
# Show Available NICs
if [[ $(ip -o link show | awk -F': ' '$0 ~ "eno[0-9]"{print $2}') ]]; then
  msg "      ONBOARD ETHERNET NIC"
  IFS='|'
  while read -r VAR1 VAR2; do
    msg "  --  ${VAR1}x Onboard (Mainboard) Ethernet NIC"
    echo "${VAR1}x $VAR2 - ${VAR1} Port Onboard Ethernet NIC" >> pve_enabled_nics_var01
  done < <(ip -o link show | awk -F': ' '$0 ~ "eno[0-9]"{print $2}' | cut -c-6 | uniq -c | sed 's/^ *//' | sed 's/ /|/' 2> /dev/null)
else
  msg "      ONBOARD ETHERNET NIC"
  msg "  --  None. No onboard ethernet NICs available."
fi
if [[ $(ip -o link show | awk -F': ' '$0 ~ "enp[0-9]"{print $2}') ]]; then
  msg "      PCI ETHERNET NIC"
  IFS='|'
  while read -r VAR1 VAR2; do
    if [ $VAR1 == 1 ]; then msg "  --  ${VAR1}x Port PCI Ethernet NIC (maybe a onboard NIC)";echo "${VAR1}x $VAR2 - ${VAR1} Port PCI Ethernet NIC" >> pve_enabled_nics_var01; fi
    if [ $VAR1 -gt 1 ]; then msg "  --  ${VAR1}x Port PCI Ethernet NIC Card";echo "${VAR1}x $VAR2 - ${VAR1} Port PCI Ethernet NIC" >> pve_enabled_nics_var01; fi
  done < <(ip -o link show | awk -F': ' '$0 ~ "enp[0-9]"{print $2}' | cut -c-6 | uniq -c | sed 's/^ *//' | sed 's/ /|/' 2> /dev/null)
else
  msg "      PCI ETHERNET NIC"
  msg "  --  None."
fi
echo
read -p "Setup or change your PVE host networking [y/n]?: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  PVE_NET=0
  # Create list of every available NIC Port
  while read -r VAR1; do
    if [ -z "$(ip -o link show | awk -F': ' '$0 ~ "enp[0-9]"{print $2}' | grep -i $VAR1)" ]; then
      echo "$VAR1 Onboard Ethernet NIC" >> pve_nic_selection_var01
    else
      echo $(lspci | grep -i 'Ethernet controller:' | sed 's/ Ethernet controller: /|/g' | awk -F'[:.|]' 'BEGIN { OFS="" }{$1=sprintf("enp%1.0f",$1)}{$2=sprintf("s%1.0f",$2)}{if ($3 >= 0) $3=sprintf("f%1.0f|",$3)}1' | grep -i $VAR1 | awk '{print} END {if (NR == 0) print "0"}') | awk '{$1=substr($1,1,6)}1' >> pve_nic_selection_var01
    fi
  done < <(ip -o link show | awk -F': ' '$0 ~ "eno[0-9]|enp[0-9]"{print $2}' 2> /dev/null)

  # Create index of available NIC cards
  while IFS=" " read -r VAR1 VAR2 VAR3; do
    echo "${VAR1}x $VAR2 -- $VAR3" >> pve_nic_selection_var02
  done < <(cat pve_nic_selection_var01 | uniq -c | sed 's/^ *//' 2> /dev/null)

  ENO_CNT=$(if [ -z "$(ip -o link show | awk -F': ' '$0 ~ "eno[0-9]"{print $2}')" ]; then echo "0"; else ip -o link show | awk -F': ' '$0 ~ "eno[0-9]"{print $2}' | wc -l; fi)
  ENP_CNT=$(if [ -z "$(ip -o link show | awk -F': ' '$0 ~ "enp[0-9]"{print $2}')" ]; then echo "0"; else ip -o link show | awk -F': ' '$0 ~ "enp[0-9]"{print $2}' | wc -l; fi)
  msg "Select the ethernet NICs to enable..."
  msg "Your PVE host has ${WHITE}$(($ENO_CNT+$ENP_CNT))x NICs${NC} ($(echo "$ENO_CNT")x onboard, $(echo "$ENP_CNT")x PCI) available for configuration."
  if [ $(($ENO_CNT+$ENP_CNT)) = 3 ]; then msg "You also have enough NICs to create a single pfSense OpenVPN gateway."; elif [ $(($ENO_CNT+$ENP_CNT)) -ge 4 ]; then msg "You also have enough NICs to create dual pfSense OpenVPN gateways."; fi
  msg "Now select which ethernet NICs and/or PCI Cards you want to enable.\nWe recommend you select ONLY Intel brand NICs whenever possible."

  set +Eeuo pipefail #Required BEFORE menu shell script
  menu() {
    echo "Available options:"
    for i in ${!options[@]}; do 
        printf "%3d%s) %s\n" $((i+1)) "${choices[i]:- }" "${options[i]}"
    done
    if [[ "$msg" ]]; then echo "$msg"; fi
  }
  mapfile -t options < pve_nic_selection_var02
  prompt="Check an option to select ethernet NICs (again to uncheck, ENTER when done): "
  while menu && read -rp "$prompt" num && [[ "$num" ]]; do
    echo
    [[ "$num" != *[![:digit:]]* ]] &&
    (( num > 0 && num <= ${#options[@]} )) ||
    { msg="Invalid option: $num"; continue; }
    ((num--)); msg="${options[num]} was ${choices[num]:+un}checked"
    [[ "${choices[num]}" ]] && choices[num]="" || choices[num]="${GREEN}+${NC}"
  done
  echo
  printf "Your selected ethernet NICs are:\n"; msg=" nothing"
  for i in ${!options[@]}; do
    [[ "${choices[i]}" ]] && { printf "${YELLOW}NIC(s):${NC} %s\n" "${options[i]}"; msg=""; } && echo $({ printf "%s" "${options[i]}"; msg=""; }) | awk '{print $2}' | while read line; do grep $line <(ip -o link show | awk -F': ' '$0 ~ "eno[0-9]|enp[0-9]"{print $2}'); done >> pve_nic_selection_var03
  done
  echo
  set -Eeuo pipefail #Required AFTER menu shell script 

  # Prepare for pfSense OpenVPN Gateway
  if [ $(($ENO_CNT+$ENP_CNT)) -ge 3 ]; then
    if [ $(($ENO_CNT+$ENP_CNT)) = 3 ] && [ ! -z "$(sort -u /proc/crypto | grep module | grep -i 'aesni_intel\|aes_x86_64')" ]; then
      msg "Prepare network for a pfSense OpenVPN Gateway..."
      msg "This host can be made ready for hosting a pfSense OpenVPN Gateway server LXC.\nYour PVE host networking configuration would be:\n      PVE Management & Guest Bridge\n      --  vmbr0\n      pfSense OpenVPN Gateway\n      --  vmbr2 (WAN vlan2 for OpenVPN)\n      --  vmbr30 (VPN Gateway vlan30/40)"
    elif [ $(($ENO_CNT+$ENP_CNT)) = 3 ] && [ -z "$(sort -u /proc/crypto | grep module | grep -i 'aesni_intel\|aes_x86_64')" ]; then
      msg "Prepare network for a pfSense OpenVPN Gateway..."
      msg "This host can be made ready for hosting a pfSense OpenVPN Gateway server LXC.\nYour PVE host networking configuration would be:\n      PVE Management & Guest Bridge\n      --  vmbr0\n      pfSense OpenVPN Gateway\n      --  vmbr2 (WAN vlan2 for OpenVPN)\n      --  vmbr30 (VPN Gateway vlan30/40)"
      warn "This hosts CPU does NOT support Intel Advanced Encryption Standard\nNew Instructions (AES-NI). Without AES-NI all OpenVPN connection will be slow.\nIt is NOT recommended you install a pfSense OpenVPN Gateway server on this host."
    elif [ $(($ENO_CNT+$ENP_CNT)) -ge 4 ] && [ ! -z "$(sort -u /proc/crypto | grep module | grep -i 'aesni_intel\|aes_x86_64')" ]; then
      msg "Prepare network for a pfSense OpenVPN Gateway..."
      msg "This host can be made ready for hosting a pfSense OpenVPN Gateway server LXC.\nYour PVE host networking configuration would be:\n      PVE Management & Guest Bridge\n      --  vmbr0\n      pfSense OpenVPN Gateway\n      --  vmbr2 (WAN vlan2 for OpenVPN)\n      --  vmbr30 (VPN Gateway vlan30 - vpnworld)\n      --  vmbr40 (VPN Gateway vlan40 - vpnlocal)\nYour hosts networking can support two secure internet VPN Gateway exit points."
    elif [ $(($ENO_CNT+$ENP_CNT)) -ge 4 ] && [ -z "$(sort -u /proc/crypto | grep module | grep -i 'aesni_intel\|aes_x86_64')" ]; then
      msg "Prepare network for a pfSense OpenVPN Gateway..."
      msg "This host can be made ready for hosting a pfSense OpenVPN Gateway server LXC.\nYour PVE host networking configuration would be:\n      PVE Management & Guest Bridge\n      --  vmbr0\n      pfSense OpenVPN Gateway\n      --  vmbr2 (WAN vlan2 for OpenVPN)\n      --  vmbr30 (VPN Gateway vlan30 - vpnworld)\n      --  vmbr40 (VPN Gateway vlan40 - vpnlocal)\nYour hosts networking can support two secure internet VPN Gateway exit points."
      warn "This hosts CPU does NOT support Intel Advanced Encryption Standard\nNew Instructions (AES-NI). Without AES-NI all OpenVPN connection will be slow.\nIt is NOT recommended you install a pfSense OpenVPN Gateway server on this host."
    fi
    echo
    read -p "Prepare this PVE host network for a pfSense OpenVPN Gateway LXC [y/n]?: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      PVE_PFSENSE=0
      info "A pfSense OpenVPN Gateway network setup will be created."
      echo
    else
      PVE_PFSENSE=1
      info "You have chosen to skip this step."
      echo
    fi
  fi

  # Ethernet Adapter Speeds
  if [[ $(dmesg | grep ixgbe) ]]; then
    msg "Select ethernet NIC speeds..."
    msg "We need to determine the ethernet speed of your selected integrated onboard\nand/or PCI card network NICs.\nWe have identified your PVE host may have ${WHITE}10GbE ethernet${NC} capability."
  else
    msg "Select ethernet NIC speeds..."
    msg "We need to determine the ethernet speed of your selected integrated onboard\nand/or PCI card network NICs."
  fi
  read -p "Do you have 10GbE/10G/SFP+ ethernet capability [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Identifying each NIC speed
    echo
    TYPE01="${YELLOW}1GbE${NC} - 1GbE/SFP ethernet."
    TYPE02="${YELLOW}10GbE${NC} - 10GbE/10G/SFP+ ethernet."
    while IFS=" " read -r VAR01 VAR02 VAR03
    do
      PS3="Select the ethernet speed for NIC device:"$'\n'"${WHITE}$VAR01 port $VAR02${NC} $VAR03 (entering numeric) : "
      msg "Available options:"
      select speed_type in "$TYPE01" "$TYPE02"
      do
      echo
      msg "You have chosen a speed of $(echo $speed_type | awk '{print $1}')."
      read -p "Confirm your selection is correct: [y/n]?: " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo $VAR02 | while read line; do grep $line <(ip -o link show | awk -F': ' '$0 ~ "eno[0-9]|enp[0-9]"{print $2}'); done | sed "s/$/ $(echo $speed_type | awk '{print $1}' | sed "s/\x1B\[\([0-9]\{1,2\}\(;[0-9]\{1,2\}\)\?\)\?[mGK]//g")/" >> pve_nic_selection_var04
        info "NIC ${WHITE}$VAR02${NC} is set at : $(echo $speed_type | awk '{print $1}')"
        echo
        break
      else
        echo
        warn "No good. No problem. Try again."
        sleep 2
        echo
      fi
      done < /dev/tty
    done < <(cat pve_nic_selection_var03 | awk '{$1=substr($1,1,6)}1' | uniq | while read line; do grep $line <(cat pve_nic_selection_var02); done)
  else
    while read -r VAR1; do
      echo "$VAR1 1GbE" >> pve_nic_selection_var04
    done < <(cat pve_nic_selection_var03 2> /dev/null)
    info "All ethernet NICs are set at: 1GbE."
    echo
  fi

  # Set PVE Host IP Address
  msg "Set PVE host IPv4 address..."
  while true; do
  read -p "Enter your new PVE host IPv4 address: " -e -i `hostname -i`/$(ip addr show |grep -w inet |grep -v 127.0.0.1|awk '{ print $2}'| cut -d "/" -f 2) PVE_HOST_IP
  if [ $PVE_TYPE = 0 ] || [ $PVE_TYPE = 1 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g') != $(hostname -i) ] && [ $(ping -s 1 -c 2 "$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')" > /dev/null; echo $?) = 0 ]; then
    if [ $(echo "$PVE_HOST_IP" | sed  's/.*\///') -ge 1 ] && [ $(echo "$PVE_HOST_IP" | sed  's/.*\///') -le 32 ]; then
      warn "There are problems with your input:\n1. Your IP address $(echo "$PVE_HOST_IP" | sed  's/\/.*//g') is in use by another network device."
      echo
    else
      warn "There are problems with your input:\n1. Your IP address $(echo "$PVE_HOST_IP" | sed  's/\/.*//g') is in use by another network device.\n2. Your netmask /$(echo "$PVE_HOST_IP" | sed  's/.*\///') is NOT within CIDR range (1-32).\nTry again..."
      echo
    fi
  elif [ $(expr "$PVE_HOST_IP" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\/[0-9][0-9]*$' >/dev/null; echo $?) == 0 ] && [ $(echo "$PVE_HOST_IP" | sed  's/.*\///') -ge 1 ] && [ $(echo "$PVE_HOST_IP" | sed  's/.*\///') -le 32 ]; then
    if [ $PVE_TYPE = 0 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g' | cut -d . -f 4) -eq 101 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g') != $(hostname -i) ] && [ $(ping -s 1 -c 2 "$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')" > /dev/null; echo $?) != 0 ]; then
      info "Primary PVE host IP address is set: ${YELLOW}$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')${NC}.\n       PVE host netmask is set: ${YELLOW}$(cdr2mask $(echo "$PVE_HOST_IP" | sed  's/.*\///'))${NC}"
      echo
      break
    elif [ $PVE_TYPE = 0 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g' | cut -d . -f 4) -eq 101 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g') = $(hostname -i) ]; then
      info "Primary PVE host IP address is set: ${YELLOW}$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')${NC}\n       (Note: Your host IP is unchanged.)\n       PVE host netmask is set: ${YELLOW}$(cdr2mask $(echo "$PVE_HOST_IP" | sed  's/.*\///'))${NC}"
      echo
      break
    elif [ $PVE_TYPE = 0 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g' | cut -d . -f 4) -ne 101 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g') != $(hostname -i) ] && [ $(ping -s 1 -c 2 "$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')" > /dev/null; echo $?) != 0 ]; then
      msg "Primary PVE host IP address ${WHITE}$PVE_HOST_IP${NC} is non-standard.\nStandard formatting is XXX.XXX.XXX.101."
      read -p "Accept your non-standard primary PVE host IP ${WHITE}"$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')"${NC} [y/n]?: " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "Primary PVE host IP address is set: ${YELLOW}$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')${NC}.\n       PVE host netmask is set: ${YELLOW}$(cdr2mask $(echo "$PVE_HOST_IP" | sed  's/.*\///'))${NC}"
        echo
        break
      else
        msg "Try again..."
        echo
      fi
    elif [ $PVE_TYPE = 0 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g' | cut -d . -f 4) -ne 101 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g') = $(hostname -i) ]; then
      msg "Primary PVE host IP address ${WHITE}$PVE_HOST_IP${NC} is non-standard.\nStandard formatting is XXX.XXX.XXX.101."
      read -p "Accept your non-standard primary PVE host IP ${WHITE}"$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')"${NC} [y/n]?: " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "Primary PVE host IP address is set: ${YELLOW}$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')${NC}.\n       (Note: Your host IP is unchanged.)\n       PVE host netmask is set: ${YELLOW}$(cdr2mask $(echo "$PVE_HOST_IP" | sed  's/.*\///'))${NC}"
        echo
        break
      else
        msg "Try again..."
        echo
      fi
    elif [ $PVE_TYPE = 1 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g' | cut -d . -f 4) -ge 102 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g' | cut -d . -f 4) -le 109 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g') != $(hostname -i) ] && [ $(ping -s 1 -c 2 "$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')" > /dev/null; echo $?) != 0 ]; then
      info "Secondary PVE host IP address is set: ${YELLOW}$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')${NC}\n       PVE host netmask is set: ${YELLOW}$(cdr2mask $(echo "$PVE_HOST_IP" | sed  's/.*\///'))${NC}"
      echo
      break
    elif [ $PVE_TYPE = 1 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g' | cut -d . -f 4) -ge 102 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g' | cut -d . -f 4) -le 109 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g') = $(hostname -i) ]; then
      info "Secondary PVE host IP address is set: ${YELLOW}$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')${NC}\n       (Note: Your host IP is unchanged.)\n       PVE host netmask is set: ${YELLOW}$(cdr2mask $(echo "$PVE_HOST_IP" | sed  's/.*\///'))${NC}"
      echo
      break
    elif [ $PVE_TYPE = 1 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g' | cut -d . -f 4) -le 101 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g' | cut -d . -f 4) -ge 110 ]&& [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g') != $(hostname -i) ] && [ $(ping -s 1 -c 2 "$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')" > /dev/null; echo $?) != 0 ]; then
      msg "Secondary PVE host IP address ${WHITE}$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')${NC} is non-standard.\nStandard formatting is in the range XXX.XXX.XXX.102-XXX.XXX.XXX.109."
      read -p "Accept your non-standard secondary PVE host IP ${WHITE}"$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')"${NC} [y/n]?: " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "Secondary PVE host IP address is set: ${YELLOW}$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')${NC}\n       PVE host netmask is set: ${YELLOW}$(cdr2mask $(echo "$PVE_HOST_IP" | sed  's/.*\///'))${NC}"
        echo
        break
      else
        msg "Try again..."
        echo
      fi
    elif [ $PVE_TYPE = 1 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g' | cut -d . -f 4) -le 101 ] && [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g' | cut -d . -f 4) -ge 110 ]&& [ $(echo "$PVE_HOST_IP" | sed  's/\/.*//g') = $(hostname -i) ]; then
      msg "Secondary PVE host IP address ${WHITE}$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')${NC} is non-standard.\nStandard formatting is in the range XXX.XXX.XXX.102-XXX.XXX.XXX.109."
      read -p "Accept your non-standard secondary PVE host IP ${WHITE}"$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')"${NC} [y/n]?: " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "Secondary PVE host IP address is set: ${YELLOW}$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')${NC}\n       (Note: Your host IP is unchanged.)\n       PVE host netmask is set: ${YELLOW}$(cdr2mask $(echo "$PVE_HOST_IP" | sed  's/.*\///'))${NC}"
        echo
        break
      else
        msg "Try again..."
        echo
      fi
    fi
  elif [ $(expr "$(echo $PVE_HOST_IP | sed  's/\/.*//g')" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) != 0 ] && [ $(echo "$PVE_HOST_IP" | sed  's/.*\///') -ge 1 ] && [ $(echo "$PVE_HOST_IP" | sed  's/.*\///') -le 32 ]; then
    warn "There are problems with your input:\n1.  Your IP address is incorrectly formatted. It must be in the IPv4 format\nincluding a subnet mask (i.e xxx.xxx.xxx.xxx/xx ).\nTry again..."
    echo
  elif [ $(expr "$(echo $PVE_HOST_IP | sed  's/\/.*//g')" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) = 0 ] && [ $(echo "$PVE_HOST_IP" | sed  's/.*\///') -eq 0 ] || [ $(echo "$PVE_HOST_IP" | sed  's/.*\///') -gt 32 ]; then
    warn "There are problems with your input:\n1. Your IP address $(echo "$PVE_HOST_IP" | sed  's/\/.*//g') meets the IPv4 standard, BUT\n2. Your netmask /$(echo "$PVE_HOST_IP" | sed  's/.*\///') is NOT within CIDR range (1-32).\nTry again..."
    echo
  fi
  done
  
  # Set PVE host Gateway
  msg "Set your PVE host gateway...\nExisting PVE host Gateway is: ${WHITE}$(ip route show | grep default | awk '{print $3}')${NC}."
  while true; do
  read -p "Enter a Gateway IPv4 address: " -e -i $(ip route show | grep default | awk '{print $3}') PVE_GW
  if [ $(expr "$PVE_GW" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) == 0 ] && [ $(ping -s 1 -c 2 "$(echo "$PVE_GW")" > /dev/null; echo $?) = 0 ]; then
    info "The PVE host gateway is set: ${YELLOW}$PVE_GW${NC}"
    echo
    break
  elif [ $(expr "$PVE_GW" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) == 0 ] && [ $(ping -s 1 -c 2 "$(echo "$PVE_GW")" > /dev/null; echo $?) = 1 ]; then
    warn "There are problems with your input:\n1. The IP address meets the IPv4 standard, BUT\n2. The IP address $PVE_GW is NOT reachable (cannot ping)."
    read -p "Accept gateway IP ${WHITE}"$PVE_GW"${NC} anyway [y/n]?: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      info "The PVE host gateway is set: ${YELLOW}$PVE_GW${NC}"
      echo
      break
    else
      msg "Try again..."
      echo
    fi
  fi
  done
    
  # # Set PVE host Netmask
  # msg "Set your PVE host netmask..."
  # #ip route | awk 'NR==2{print $1}'
  # function linux cdr2mask
  # () {
    # # Number of args to shift, 255..255, first non-255 byte, zeroes
    # set -- $(( 5 - ($1 / 8) )) 255 255 255 255 $(( (255 < (8 - ($1 % 8))) & 255 )) 0 0 0
    # [ $1 -gt 1 ] && shift $1 || shift
    # echo ${1-0}.${2-0}.${3-0}.${4-0}
  # }
  # # Convert Network CIDR to Netmask
  # while true; do
  # read -p "Enter your PVE host netmask: " -e -i $(cdr2mask $(ip addr show |grep -w inet |grep -v 127.0.0.1|awk '{ print $2}'| cut -d "/" -f 2)) PVE_NETMASK
  # echo
  # echo $PVE_NETMASK | grep -w -E -o '^(254|252|248|240|224|192|128)\.0\.0\.0|255\.(254|252|248|240|224|192|128|0)\.0\.0|255\.255\.(254|252|248|240|224|192|128|0)\.0|255\.255\.255\.(254|252|248|240|224|192|128|0)' > /dev/null
  # if [ $? -eq 0 ]; then
    # info "The PVE host netmask is set: ${YELLOW}$PVE_NETMASK${NC}."
    # echo
    # break
  # else
    # warn "There are problems with your input:\n1. The netmask does not meet IPv4 standards\n2. $PVE_NETMASK is invalid."
    # msg "Try again..."
    # echo
  # fi
  # done

  # Set PVE Hostname
  msg "Set your PVE hostname...\nExisting PVE hostname is: ${WHITE}$HOSTNAME${NC}."
  read -p "Do you want to change your hostname [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo
    # Check for running QM or LXC or cluster member
    if [[ $(pct list) ]] || [[ $(qm list) ]] && [[ $(pvecm nodes 2>/dev/null | grep $HOSTNAME) ]]; then
      warn "PVE host $HOSTNAME is reporting to be hosting $(qm list | awk 'NR>1 { print $1 }' | wc -l)x virtual machines (VMs)\nand $(pct list | awk 'NR>1 { print $1 }' | wc -l)x LXC containers (CTs).\n\nIf you want to proceed to configure or make system changes to this PVE host\n$HOSTNAME you must first take the following steps:\n      FOR SINGLE OR PRIMARY NODES - REMOVE ALL CONTAINERS\n      --  Stop all VMs and CTs.\n      --  Create a backup archive of all VMs and CTs.\n      --  REMOVE all VMs and CTs.\nA backup archive can be restored through the Proxmox VE web GUI or through\nthe PVE CLI tools.\n\nPVE host $HOSTNAME is also reporting as a member of a PVE cluster.\nTo proceed you must first remove this node ($HOSTNAME) from the PVE cluster.\n      REMOVE NODE FROM CLUSTER\n      --  Migrate all VMs and CTs to another active node.\n      --  Remove $HOSTNAME from the PVE cluster."
      echo
      msg "This script will exit in 5 seconds. Complete the above tasks and try again..."
      sleep 5
      cleanup
      exit 0
    elif [[ $(pct list) ]] || [[ $(qm list) ]] && [[ ! $(pvecm nodes 2>/dev/null | grep $HOSTNAME) ]]; then
      warn "PVE host $HOSTNAME is reporting to be hosting $(qm list | awk 'NR>1 { print $1 }' | wc -l)x virtual machines (VMs)\nand $(pct list | awk 'NR>1 { print $1 }' | wc -l)x LXC containers (CTs).\n\nIf you want to proceed to configure or make system changes to this PVE host\n$HOSTNAME you must first take the following steps:\n      FOR SINGLE OR PRIMARY NODES - REMOVE ALL CONTAINERS\n      --  Stop all VMs and CTs.\n      --  Create a backup archive of all VMs and CTs.\n      --  REMOVE all VMs and CTs.\nA backup archive can be restored through the Proxmox VE web GUI or through\nthe PVE CLI tools."
      echo
      msg "This script will exit in 5 seconds. Complete the above tasks and try again..."
      sleep 5
      cleanup
      exit 0
    elif [[ ! $(pct list) ]] || [[ ! $(qm list) ]] && [[ $(pvecm nodes 2>/dev/null | grep $HOSTNAME) ]]; then
      warn "PVE host $HOSTNAME is reporting as a member of a PVE cluster.\nTo proceed you must first remove this node ($HOSTNAME) from the PVE cluster.\n      REMOVE NODE FROM CLUSTER\n      --  Migrate all VMs and CTs to another active node.\n      --  Remove $HOSTNAME from the PVE cluster."
      echo
      msg "This script will exit in 5 seconds. Complete the above tasks and try again..."
      sleep 5
      cleanup
      exit 0
    fi
    if [ $PVE_TYPE = 0 ] && [[ $HOSTNAME =~ ^[A-Za-z]+\-"01"$ ]];then
      PVE_HOSTNAME_VAR01=$HOSTNAME
    elif [ $PVE_TYPE = 0 ] && ! [[ $HOSTNAME =~ ^[A-Za-z]+\-"01"$ ]];then
      PVE_HOSTNAME_VAR01=pve-01
    elif [ $PVE_TYPE = 1 ] && [[ $HOSTNAME =~ ^[A-Za-z]+\-0[2-9]{1}$ ]];then
      PVE_HOSTNAME_VAR01=$HOSTNAME
    elif [ $PVE_TYPE = 1 ] && ! [[ $HOSTNAME =~ ^[A-Za-z]+\-0[2-9]{1}$ ]];then
      PVE_HOSTNAME_VAR01=pve-02
    fi
    while true; do
    read -p "Enter your new PVE hostname: " -e -i $PVE_HOSTNAME_VAR01 PVE_HOSTNAME
    PVE_HOSTNAME=${PVE_HOSTNAME,,}
    if [ $PVE_TYPE == 0 ] && ! [[ "$PVE_HOSTNAME" =~ ^[A-Za-z]+\-[0-9]{2}$ ]]; then
      warn "There are problems with your input:\n1. The hostname denotation is missing (i.e must be hostname-01).\n   Try again..."
      echo
    elif [ $PVE_TYPE == 0 ] && [ $PVE_HOSTNAME == "pve-01" ]; then
      info "PVE hostname is set: ${YELLOW}$PVE_HOSTNAME${NC}"
      echo
      break
    elif [ $PVE_TYPE == 0 ] && [ $(echo "$PVE_HOSTNAME" | cut -d'-' -f 1 ) != 'pve' ] && [ $(echo "$PVE_HOSTNAME" | rev | cut -d'-' -f 1 | rev) -eq 01 ]; then
      msg "PVE hostname ${WHITE}$PVE_HOSTNAME${NC} is:\n1. Correctly denoted for primary PVE hosts (i.e -01).\n2. The name ${WHITE}$PVE_HOSTNAME${NC} is non-standard but acceptable (i.e pve-01)."
      read -p "Accept your non-standard primary PVE hostname ${WHITE}"$PVE_HOSTNAME"${NC} [y/n]?: " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "PVE hostname is set: ${YELLOW}$PVE_HOSTNAME${NC}"
        echo
        break
      else
        msg "Try again..."
        echo
      fi
    elif [ $PVE_TYPE == 0 ] && [ $(echo "$PVE_HOSTNAME" | rev | cut -d'-' -f 1 | rev) -ne 01 ]; then
      warn "There are problems with your input:\n1. Primary PVE hosts must be denoted with 01.\n   Try again..."
      echo
    elif [ $PVE_TYPE == 1 ] && ! [[ "$PVE_HOSTNAME" =~ ^[A-Za-z]+\-0[2-9]{1}$ ]]; then
      warn "There are problems with your input:\n1. The hostname denotation is missing (i.e must be hostname-02/03/04 etc).\n   Try again..."
      echo
    elif [ $PVE_TYPE == 1 ] && [[ $PVE_HOSTNAME =~ "-01" ]]; then
      warn "There are problems with your input:\n1. Secondary PVE hosts cannot be denoted with 01 (i.e $PVE_HOSTNAME).\n2. Secondary PVE hosts must be denoted from 02 to 09.\n   Try again..."
      echo
    elif [ $PVE_TYPE == 1 ] && [ $(echo "$PVE_HOSTNAME" | cut -d'-' -f 1 ) == pve ] && [ $(echo "$PVE_HOSTNAME" | rev | cut -d'-' -f 1 | rev) -ge 02 ] && [ $(echo "$PVE_HOSTNAME" | rev | cut -d'-' -f 1 | rev) -le 09 ]; then
      info "PVE hostname is set: ${YELLOW}$PVE_HOSTNAME${NC}."
      echo
      break
    elif [ $PVE_TYPE == 1 ] && [ $(echo "$PVE_HOSTNAME" | cut -d'-' -f 1 ) != 'pve' ] && [ $(echo "$PVE_HOSTNAME" | rev | cut -d'-' -f 1 | rev) -ge 02 ] && [ $(echo "$PVE_HOSTNAME" | rev | cut -d'-' -f 1 | rev) -le 09 ]; then
      msg "PVE hostname ${WHITE}$PVE_HOSTNAME${NC} is:\n1. Correctly denoted for secondary PVE hosts (i.e -02,-03).\n2. The name ${WHITE}$PVE_HOSTNAME${NC} is non-standard but acceptable (i.e pve-$(echo "$PVE_HOSTNAME" | rev | cut -d'-' -f 1 | rev))."
      read -p "Accept your non-standard secondary PVE hostname ${WHITE}"$PVE_HOSTNAME"${NC} [y/n]?: " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "PVE hostname is set: ${YELLOW}$PVE_HOSTNAME${NC}."
        echo
        break
      else
        msg "Try again..."
        echo
      fi
    elif [ $PVE_TYPE == 1 ] && [ $(echo "$PVE_HOSTNAME" | rev | cut -d'-' -f 1 | rev) -le 01 ] && [ $(echo "$PVE_HOSTNAME" | rev | cut -d'-' -f 1 | rev) -ge 10 ]; then
      warn "There are problems with your input:\n1. Secondary PVE hosts must be denoted from 02 to 09.\n   Try again..."
      echo
    fi
    done
  else
    PVE_HOSTNAME=$HOSTNAME
    info "PVE hostname is set: ${YELLOW}$PVE_HOSTNAME${NC} (Unchanged)."
  fi
else
  info "You have chosen to skip this step."
  echo
  PVE_NET=1
  PVE_PFSENSE=1
  PVE_HOSTNAME=$HOSTNAME
fi


#### Configuring PVE Host Ethernet ####
if [ $PVE_NET = 0 ]; then
  section "$SECTION_HEAD - Configuring PVE Host Ethernet"

  # Setting Ethernet VAR
  ETH_10GBE_CNT=$(cat pve_nic_selection_var04 | awk -F' ' '{if($2 == "10GbE"){print}}' | wc -l)
  ETH_1GBE_CNT=$(cat pve_nic_selection_var04 | awk -F' ' '{if($2 == "1GbE"){print}}' | wc -l)
  ETH_10GBE_LIST=$(cat pve_nic_selection_var04 | awk '{if($2 == "10GbE"){print $0}}' | sort | awk '{ print $2 " " $1}')
  ETH_1GBE_LIST=$(cat pve_nic_selection_var04 | awk '{if($2 == "1GbE"){print $0}}' | sort | awk '{ print $2 " " $1}')

  # PVE Node VMBR bridges (No pfSense)
  if [ $PVE_PFSENSE = 1 ]; then
    msg "Creating PVE Ethernet NIC bridges (VMBR)..."
    if [ $ETH_10GBE_CNT -eq 0 ] && [ $ETH_1GBE_CNT -eq 1 ]; then
      # Now read from 1Gbe list file
      while read -r line1; do
        echo "vmbr0 1 1 $line1" >> pve_nic_selection_var05
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}"$ETH_1GBE_CNT"x vmbr0${NC}"
      done < <(echo "$ETH_1GBE_LIST")
    elif [ $ETH_10GBE_CNT -eq 0 ] && [ $ETH_1GBE_CNT -eq 2 ]; then
      # Now read from 1Gbe list file
      while read -r line1; read -r line2; do
        echo "vmbr0 bond0 802.3ad $line1" >> pve_nic_selection_var05
        echo "vmbr0 bond0 802.3ad $line2" >> pve_nic_selection_var05
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}"$ETH_1GBE_CNT"x bond0 (802.3ad) vmbr0${NC}"
      done < <(echo "$ETH_1GBE_LIST")
    elif [ $ETH_10GBE_CNT -eq 0 ] && [ $ETH_1GBE_CNT -eq 3 ]; then
      # Now read from 1Gbe list file
      while read -r line1; read -r line2; read -r line3; do
        echo "vmbr0 bond0 802.3ad $line1" >> pve_nic_selection_var05
        echo "vmbr0 bond0 802.3ad $line2" >> pve_nic_selection_var05
        echo "vmbr0 bond0 802.3ad $line3" >> pve_nic_selection_var05
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}"$ETH_1GBE_CNT"x bond0 (802.3ad) vmbr0${NC}"
      done < <(echo "$ETH_1GBE_LIST")
    elif [ $ETH_10GBE_CNT -eq 0 ] && [ $ETH_1GBE_CNT -ge 4 ]; then
      # Now read from 1Gbe list file
      while read -r line1; read -r line2; read -r line3; read -r line4; do
        echo "vmbr0 bond0 802.3ad $line1" >> pve_nic_selection_var05
        echo "vmbr0 bond0 802.3ad $line2" >> pve_nic_selection_var05
        echo "vmbr0 bond0 802.3ad $line3" >> pve_nic_selection_var05
        echo "vmbr0 bond0 802.3ad $line4" >> pve_nic_selection_var05
        if [ $ETH_1GBE_CNT -eq 4 ]; then
          info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}"$ETH_1GBE_CNT"x bond0 (802.3ad) vmbr0${NC}"
        elif [ $ETH_1GBE_CNT -ge 4 ]; then
          info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}4x bond0 (802.3ad) vmbr0${NC}"
          warn "$(($ETH_1GBE_CNT-4))x 1GbE NICs have been excluded. You can always\nmodify your PVE host network using the PVE management webGUI."
        fi
      done < <(echo "$ETH_1GBE_LIST")
    elif [ $ETH_10GBE_CNT -eq 1 ] && [ $ETH_1GBE_CNT -ge 0 ]; then
      # Now read from 10Gbe list file
      while read -r line1; do
        echo "vmbr0 1 1 $line1" >> pve_nic_selection_var05
        info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}"$ETH_10GBE_CNT"x vmbr0${NC}"
        if [ $ETH_1GBE_CNT -ge 1 ]; then
          warn ""$ETH_1GBE_CNT"x 1GbE NICs have been excluded because they are not required\nwhen 10GbE ethernet is available.\nYou can always modify your PVE host network using the PVE management webGUI."
        fi
      done < <(echo "$ETH_10GBE_LIST")
    elif [ $ETH_10GBE_CNT -ge 2 ] && [ $ETH_1GBE_CNT -ge 0 ]; then
      # Now read from 10Gbe list file
      while read -r line1; read -r line2; do
        echo "vmbr0 bond0 802.3ad $line1" >> pve_nic_selection_var05
        echo "vmbr0 bond0 802.3ad $line2" >> pve_nic_selection_var05
        info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}2x bond0 (802.3ad) vmbr0${NC}"
        if [ $ETH_10GBE_CNT -ge 3 ] && [ $ETH_1GBE_CNT -ge 1 ]; then
        warn "$(($ETH_10GBE_CNT-2))x 10GbE NICs have been excluded because they are not required.\n"$ETH_1GBE_CNT"x 1GbE NICs have been excluded because they are not required\nwhen 10GbE ethernet is available.\nYou can always modify your PVE host network using the PVE management webGUI."
        fi
      done < <(echo "$ETH_10GBE_LIST")
    fi
  echo
  fi

  # PVE Node VMBR assignment (With pfSense)
  if [ $PVE_PFSENSE = 0 ]; then
    echo
    msg "Creating PVE Ethernet NIC bridges (VMBR)..."
    if [ $ETH_10GBE_CNT -eq 0 ] && [ $ETH_1GBE_CNT -eq 3 ]; then
      # Now read from 1Gbe list file
      while read -r line1; read -r line2; read -r line3; do
        echo "vmbr0 1 1 $line1" >> pve_nic_selection_var05
        echo "vmbr2 1 1 $line2" >> pve_nic_selection_var05
        echo "vmbr30 1 1 $line3" >> pve_nic_selection_var05
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}\n"
      done < <(echo "$ETH_1GBE_LIST")
    elif [ $ETH_10GBE_CNT -eq 0 ] && [ $ETH_1GBE_CNT -eq 4 ]; then
      # Now read from 1Gbe list file
      while read -r line1; read -r line2; read -r line3; read -r line4; do
        echo "vmbr0 1 1 $line1" >> pve_nic_selection_var05
        echo "vmbr2 1 1 $line2" >> pve_nic_selection_var05
        echo "vmbr30 1 1 $line3" >> pve_nic_selection_var05
        echo "vmbr40 1 1 $line4" >> pve_nic_selection_var05
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}\n      --  ${YELLOW}1x vmbr40${NC}"
      done < <(echo "$ETH_1GBE_LIST")
    elif [ $ETH_10GBE_CNT -eq 0 ] && [ $ETH_1GBE_CNT -eq 5 ]; then
      # Now read from 1Gbe list file
      while read -r line1; read -r line2; read -r line3; read -r line4; read -r line5; do
        echo "vmbr0 bond0 802.3ad $line1" >> pve_nic_selection_var05
        echo "vmbr0 bond0 802.3ad $line2" >> pve_nic_selection_var05
        echo "vmbr2 1 1 $line3" >> pve_nic_selection_var05
        echo "vmbr30 1 1 $line4" >> pve_nic_selection_var05
        echo "vmbr40 1 1 $line5" >> pve_nic_selection_var05
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}2x bond0 (802.3ad) vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}\n      --  ${YELLOW}1x vmbr40${NC}"
      done < <(echo "$ETH_1GBE_LIST")
    elif [ $ETH_10GBE_CNT -eq 0 ] && [ $ETH_1GBE_CNT -ge 6 ]; then
      # Now read from 1Gbe list file
      while read -r line1; read -r line2; read -r line3; read -r line4; read -r line5; read -r line6; do
        echo "vmbr0 bond0 802.3ad $line1" >> pve_nic_selection_var05
        echo "vmbr0 bond0 802.3ad $line2" >> pve_nic_selection_var05
        echo "vmbr2 bond2 802.3ad $line3" >> pve_nic_selection_var05
        echo "vmbr2 bond2 802.3ad $line4" >> pve_nic_selection_var05
        echo "vmbr30 1 1 $line5" >> pve_nic_selection_var05
        echo "vmbr40 1 1 $line6" >> pve_nic_selection_var05
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}2x bond0 (802.3ad) vmbr0${NC}\n      --  ${YELLOW}2x bond2 (802.3ad) vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}\n      --  ${YELLOW}1x vmbr40${NC}"
        if [ $ETH_10GBE_CNT -eq 0 ] && [ $ETH_1GBE_CNT -ge 7 ]; then
          warn "$(($ETH_1GBE_CNT-6))x 1GbE NICs have been excluded because they are not required.\nYou can always modify your PVE host network using the PVE management webGUI."
        fi
      done < <(echo "$ETH_1GBE_LIST")
    elif [ $ETH_10GBE_CNT -eq 1 ] && [ $ETH_1GBE_CNT -eq 2 ]; then
      # Now read from 10Gbe list file
      while read -r line1; do
        echo "vmbr0 1 1 $line1" >> pve_nic_selection_var05
        info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}"
      done < <(echo "$ETH_10GBE_LIST")
      # Now read from 1Gbe list file
      while read -r line1; read -r line2; do
        echo "vmbr2 1 1 $line1" >> pve_nic_selection_var05
        echo "vmbr30 1 1 $line2" >> pve_nic_selection_var05
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}"
      done < <(echo "$ETH_1GBE_LIST")
    elif [ $ETH_10GBE_CNT -eq 1 ] && [ $ETH_1GBE_CNT -eq 3 ]; then
      # Now read from 10Gbe list file
      while read -r line1; do
        echo "vmbr0 1 1 $line1" >> pve_nic_selection_var05
        info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}"
      done < <(echo "$ETH_10GBE_LIST")
      # Now read from 1Gbe list file
      while read -r line1; read -r line2; read -r line3; do
        echo "vmbr2 1 1 $line1" >> pve_nic_selection_var05
        echo "vmbr30 1 1 $line2" >> pve_nic_selection_var05
        echo "vmbr40 1 1 $line3" >> pve_nic_selection_var05
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}\n      --  ${YELLOW}1x vmbr40${NC}"
      done < <(echo "$ETH_1GBE_LIST")
    elif [ $ETH_10GBE_CNT -eq 1 ] && [ $ETH_1GBE_CNT -ge 4 ]; then
      # Now read from 10Gbe list file
      while read -r line1; do
        echo "vmbr0 1 1 $line1" >> pve_nic_selection_var05
        info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}"
      done < <(echo "$ETH_10GBE_LIST")
      # Now read from 1Gbe list file
      while read -r line1; read -r line2; read -r line3; read -r line4; do
        echo "vmbr2 bond2 802.3ad $line1" >> pve_nic_selection_var05
        echo "vmbr2 bond2 802.3ad $line2" >> pve_nic_selection_var05
        echo "vmbr30 1 1 $line3" >> pve_nic_selection_var05
        echo "vmbr40 1 1 $line4" >> pve_nic_selection_var05
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}2x bond2 (802.3ad) vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}\n      --  ${YELLOW}1x vmbr40${NC}"
        if [ $ETH_10GBE_CNT -eq 1 ] && [ $ETH_1GBE_CNT -ge 5 ]; then
          warn "$(($ETH_1GBE_CNT-4))x 1GbE NICs have been excluded because they are not required.\nYou can always modify your PVE host network using the PVE management webGUI."
        fi
      done < <(echo "$ETH_1GBE_LIST")
    elif [ $ETH_10GBE_CNT -eq 2 ] && [ $ETH_1GBE_CNT -eq 1 ]; then
      # Now read from 10Gbe list file
      while read -r line1; read -r line2; do
        echo "vmbr0 1 1 $line1" >> pve_nic_selection_var05
        echo "vmbr2 1 1 $line2" >> pve_nic_selection_var05
        info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}"
      done < <(echo "$ETH_10GBE_LIST")
      # Now read from 1Gbe list file
      while read -r line1; do
        echo "vmbr30 1 1 $line1" >> pve_nic_selection_var05
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}1x vmbr30${NC}"
      done < <(echo "$ETH_1GBE_LIST")
    elif [ $ETH_10GBE_CNT -eq 2 ] && [ $ETH_1GBE_CNT -ge 2 ]; then
      # Now read from 10Gbe list file
      while read -r line1; read -r line2; do
        echo "vmbr0 1 1 $line1" >> pve_nic_selection_var05
        echo "vmbr2 1 1 $line2" >> pve_nic_selection_var05
        info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}"
      done < <(echo "$ETH_10GBE_LIST")
      # Now read from 1Gbe list file
      while read -r line1; read -r line2; do
        echo "vmbr30 1 1 $line1" >> pve_nic_selection_var05
        echo "vmbr40 1 1 $line2" >> pve_nic_selection_var05
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}1x vmbr30${NC}\n      --  ${YELLOW}1x vmbr40${NC}"
        if [ $ETH_10GBE_CNT -eq 2 ] && [ $ETH_1GBE_CNT -ge 3 ]; then
          warn "$(($ETH_1GBE_CNT-2))x 1GbE NICs have been excluded because they are not required.\nYou can always modify your PVE host network using the PVE management webGUI."
        fi
      done < <(echo "$ETH_1GBE_LIST")
    elif [ $ETH_10GBE_CNT -eq 3 ] && [ $ETH_1GBE_CNT -eq 0 ]; then
      # Now read from 10Gbe list file
      while read -r line1; read -r line2; read -r line3; do
        echo "vmbr0 1 1 $line1" >> pve_nic_selection_var05
        echo "vmbr2 1 1 $line2" >> pve_nic_selection_var05
        echo "vmbr30 1 1 $line3" >> pve_nic_selection_var05
        info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}"
      done < <(echo "$ETH_10GBE_LIST")
    elif [ $ETH_10GBE_CNT -eq 3 ] && [ $ETH_1GBE_CNT -eq 1 ]; then
      # Now read from 10Gbe list file
      while read -r line1; read -r line2; read -r line3; do
        echo "vmbr0 1 1 $line1" >> pve_nic_selection_var05
        echo "vmbr2 1 1 $line2" >> pve_nic_selection_var05
        echo "vmbr30 1 1 $line3" >> pve_nic_selection_var05
        info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}"
      done < <(echo "$ETH_10GBE_LIST")
      # Now read from 1Gbe list file
      while read -r line1; do
        echo "vmbr40 1 1 $line1" >> pve_nic_selection_var05
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}1x vmbr40${NC}"
      done < <(echo "$ETH_1GBE_LIST")
    elif [ $ETH_10GBE_CNT -eq 3 ] && [ $ETH_1GBE_CNT -ge 2 ]; then
      # Now read from 10Gbe list file
      while read -r line1; read -r line2; read -r line3; do
        echo "vmbr0 1 1 $line1" >> pve_nic_selection_var05
        echo "vmbr2 1 1 $line2" >> pve_nic_selection_var05
        echo "vmbr30 1 1 $line3" >> pve_nic_selection_var05
        info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}"
      done < <(echo "$ETH_10GBE_LIST")
      # Now read from 1Gbe list file
      while read -r line1; read -r line2; do
        echo "vmbr40 bond40 802.3ad $line1" >> pve_nic_selection_var05
        echo "vmbr40 bond40 802.3ad $line2" >> pve_nic_selection_var05
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}2x bond4 (802.3ad) vmbr40${NC}"
        if [ $ETH_10GBE_CNT -eq 3 ] && [ $ETH_1GBE_CNT -ge 3 ]; then
          warn "$(($ETH_1GBE_CNT-2))x 1GbE NICs have been excluded because they are not required.\nYou can always modify your PVE host network using the PVE management webGUI."
        fi
      done < <(echo "$ETH_1GBE_LIST")
    elif [ $ETH_10GBE_CNT -ge 4 ] && [ $ETH_1GBE_CNT -ge 0 ]; then
      # Now read from 10Gbe list file
      while read -r line1; read -r line2; read -r line3; read -r line4; do
        echo "vmbr0 1 1 $line1" >> pve_nic_selection_var05
        echo "vmbr2 1 1 $line2" >> pve_nic_selection_var05
        echo "vmbr30 1 1 $line3" >> pve_nic_selection_var05
        echo "vmbr40 1 1 $line4" >> pve_nic_selection_var05
        info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}\n      --  ${YELLOW}1x vmbr40${NC}"
        if [ $ETH_10GBE_CNT -ge 5 ] && [ $ETH_1GBE_CNT -eq 0 ]; then
          warn "$(($ETH_10GBE_CNT-4))x 10GbE NICs have been excluded because they are not required.\nYou can always modify your PVE host network using the PVE management webGUI."
        elif [ $ETH_10GBE_CNT -ge 5 ] && [ $ETH_1GBE_CNT -ge 1 ]; then
          warn "$(($ETH_10GBE_CNT-4))x 10GbE NICs have been excluded because they are not required.\n"$ETH_1GBE_CNT"x 1GbE NICs have been excluded because they are not required\nwhen 10GbE ethernet is available.\nYou can always modify your PVE host network using the PVE management webGUI."
        fi
      done < <(echo "$ETH_10GBE_LIST")
    fi
  echo
  fi
fi

# Building /etc/network/interfaces.new
if [ $PVE_NET = 0 ]; then
msg "Creating /etc/network/interfaces.new..."
PVE_NET_INTERFACES=/etc/network/interfaces.new
# Checking for older /etc/network/interfaces.new
if [ -f $PVE_NET_INTERFACES ]; then
  rm $PVE_NET_INTERFACES >/dev/null
fi
cp pve_nic_selection_var05 pve_nic_selection_input

# Create /etc/network/interfaces.new file
eval cat << EOF > $PVE_NET_INTERFACES
# Please do NOT modify this file directly, unless you know what
# you're doing.
#
# If you want to manage parts of the network configuration manually,
# please utilize the 'source' or 'source-directory' directives to do
# so.
# PVE will preserve these directives, but will NOT read its network
# configuration from sourced files, so do not attempt to move any of
# the PVE managed interfaces into external files!

auto lo
iface lo inet loopback

#### Settings for $(if [ $(cat pve_nic_selection_input | awk -F' ' '{if($4 == "10GbE"){print}}' | wc -l) -gt 0 ]; then echo "$(cat pve_nic_selection_input | awk -F' ' '{if($4 == "1GbE"){print}}' | wc -l)x10GbE:"; fi)$(if [ $(cat pve_nic_selection_input | awk -F' ' '{if($4 == "1GbE"){print}}' | wc -l) -gt 0 ]; then echo "$(cat pve_nic_selection_input | awk -F' ' '{if($4 == "1GbE"){print}}' | wc -l)x1GbE"; fi) ####
  
EOF

# Build iface list
while IFS=" " read -r VAR1 VAR2 VAR3 VAR4 VAR5; do
  echo "iface $VAR5 inet manual" >> $PVE_NET_INTERFACES
  echo >> $PVE_NET_INTERFACES
done < pve_nic_selection_input

# Build ethernet bond list
if [[ $(cat pve_nic_selection_input | awk -F' ' '{if($2 ~ "bond"){print}}') ]]; then
while IFS=" " read -r VAR1 VAR2 VAR3 VAR4 VAR5; do
(( i= $(echo $VAR4 | sed 's/GbE//') * $(echo $VAR5 | wc -w) ))
eval cat << EOF >> $PVE_NET_INTERFACES
# Linux Bond $VAR2 - ${i}GbE
auto $VAR2
iface $VAR2 inet manual
        bond-slaves $VAR5
        bond-miimon 100
        bond-mode $VAR3
        bond-xmit-hash-policy layer2+3

EOF
done < <(cat pve_nic_selection_input | awk -F' ' '{if($2 ~ "bond"){print}}' | awk '{if (a!=$2) {a=$2; printf "\n%s",$0,FS} else {a=$2; printf " %s",$5 }} END {printf "\n" }' | sed '/^$/d')
fi

# Build bonded bridges
if [[ $(cat pve_nic_selection_input | awk -F' ' '{if($2 ~ "bond"){print}}') ]]; then
while IFS=" " read -r VAR1 VAR2 VAR3 VAR4 VAR5; do
(( i= $(echo $VAR4 | sed 's/GbE//') * $(echo $VAR5 | wc -w) ))
if [ $VAR1 = "vmbr0" ]; then
eval cat << EOF >> $PVE_NET_INTERFACES
# Linux Bridge $VAR1 - ${i}GbE Linux Bond
auto $VAR1
iface $VAR1 inet static
        address $PVE_HOST_IP
        gateway $PVE_GW
        bridge-ports $VAR2
        bridge-stp off
        bridge-fd 0
        bridge-vlan-aware yes
        bridge-vids 2-4094

EOF
elif [ $VAR1 != "vmbr0" ]; then
eval cat << EOF >> $PVE_NET_INTERFACES
# Linux Bridge $VAR1 - ${i}GbE Linux Bond
auto $VAR1
iface $VAR1 inet manual
        bridge-ports $VAR2
        bridge-stp off
        bridge-fd 0
        bridge-vlan-aware yes
        bridge-vids 2-4094

EOF
fi
done < <(cat pve_nic_selection_input | awk -F' ' '{if($2 ~ "bond"){print}}' | awk '{if (a!=$2) {a=$2; printf "\n%s",$0,FS} else {a=$2; printf " %s",$5 }} END {printf "\n" }' | sed '/^$/d')
fi

# Build standard bridges
if [[ $(cat pve_nic_selection_input | awk -F' ' '{if($2 == "1"){print}}') ]]; then
while IFS=" " read -r VAR1 VAR2 VAR3 VAR4 VAR5; do
if [ $VAR1 = "vmbr0" ]; then
eval cat << EOF >> $PVE_NET_INTERFACES
# Linux Bridge $VAR1 - $VAR4
auto $VAR1
iface $VAR1 inet static
        address $PVE_HOST_IP
        gateway $PVE_GW
        bridge-ports $VAR5
        bridge-stp off
        bridge-fd 0
        bridge-vlan-aware yes
        bridge-vids 2-4094

EOF
elif [ $VAR1 != "vmbr0" ]; then
eval cat << EOF >> $PVE_NET_INTERFACES
# Linux Bridge $VAR1 - $VAR4
auto $VAR1
iface $VAR1 inet manual
        bridge-ports $VAR5
        bridge-stp off
        bridge-fd 0
        bridge-vlan-aware yes
        bridge-vids 2-4094

EOF
fi
done < <(cat pve_nic_selection_input | awk -F' ' '{if($2 == "1"){print}}' | awk '{if (a!=$2) {a=$2; printf "\n%s",$0,FS} else {a=$2; printf " %s",$5 }} END {printf "\n" }' | sed '/^$/d')
fi
echo
fi


#### Adding NFS or CIFS Storage Mounts ####
if [ $PVE_TYPE = 0 ]; then
  section "$SECTION_HEAD - Adding NFS & CIFS Storage Mounts"

  box_out '#### PLEASE READ CAREFULLY - NAS NFS & CIFS SERVER EXPORTS ####' '' 'Proxmox can add storage by creating NFS and/or CIFS backend storage pools.' 'Your NAS server NFS/CIFS properties must be configured so your PVE NFS/CIFS' 'backend (client) can mount the NAS shares automatically. Your NAS server' 'should support:' '' '  NFS VERSION' '  --  NFS v3/v4.' '  --  NAS NFS exports to all PVE nodes (i.e 192.168.1.101-192.168.1.109).' '  CIFS VERSION' '  --  SMB3 (SMB1 is NOT supported).' '  --  NAS CIFS shares to all PVE nodes (i.e 192.168.1.101-192.168.1.109).' '' 'We need to set some variables. The next steps requires your input. You can' 'accept our default values by pressing ENTER on your keyboard. Or overwrite our' 'default value by typing in your own value and then pressing ENTER to' 'accept and to continue to the next step.'
  echo
  read -p "Create PVE NFS storage mounts [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    export ADD_NFS_MOUNTS=0 >/dev/null
    export PARENT_EXEC_PVE_ADD_NFS_MOUNTS=0 >/dev/null
    export PVE_HOSTNAME >/dev/null
    chmod +x pve_add_nfs_mounts.sh
    ./pve_add_nfs_mounts.sh
  else
    ADD_NFS_MOUNTS=1 >/dev/null
    info "You have chosen to skip this step."
  fi
  echo
  echo
  read -p "Create PVE CIFS storage mounts [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    export ADD_CIFS_MOUNTS=0 >/dev/null
    export PARENT_EXEC_PVE_ADD_CIFS_MOUNTS=0 >/dev/null
    export PVE_HOSTNAME >/dev/null
    chmod +x pve_add_cifs_mounts.sh
    ./pve_add_cifs_mounts.sh
  else
    ADD_CIFS_MOUNTS=1 >/dev/null
    info "You have chosen to skip this step."
  fi
  echo
fi

#### Install and Configure SSMTP Email Alerts ####
if [ $PVE_TYPE = 0 ] || [ $PVE_TYPE = 1 ]; then
  section "$SECTION_HEAD - Configuring Postfix & Email Alerts."

  box_out '#### PLEASE READ CAREFULLY - POSTFIX & EMAIL ALERTS ####' '' 'Send email alerts about your PVE host to the system’s designated administrator.' 'Be alerted about unwarranted login attempts and other system critical alerts.' 'Proxmox is preinstalled with Postfix SMTP server which we use for sending your' 'PVE nodes critical alerts.' '' 'SMTP is a simple Mail Transfer Agent (MTA) while easy to setup it' 'requires the following prerequisites and credentials:' '' '  --  SMTP SERVER' '      You require a SMTP server that can receive the emails from your machine' '      and send them to the designated administrator. ' '      If you use Gmail SMTP server its best to enable "App Passwords". An "App' '      Password" is a 16-digit passcode that gives an app or device permission' '      to access your Google Account.' '      Or you can use a mailgun.com flex account relay server (Recommended).' '' '  --  REQUIRED SMTP SERVER CREDENTIALS' '      1. Designated administrator email address' '         (i.e your working admin email address)' '      2. SMTP server address' '         (i.e smtp.gmail.com or smtp.mailgun.org)' '      3. SMTP server port' '         (i.e gmail port is 587 and mailgun port is 587)' '      4. SMTP server username' '         (i.e MyEmailAddress@gmail.com or postmaster@sandboxa6ac6.mailgun.org)' '      5. SMTP server default password' '         (i.e your Gmail App Password or mailgun SMTP password)' '' 'If you choose to proceed have your SMTP server credentials available.' 'This script will configure your PVE nodes Postfix SMTP server.'
  echo
  while true; do
    read -p "Install and configure Postfix and email alerts [y/n]?: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      echo
      read -p "Do you have your Gmail App or Mailgun credentials ready [y/n]?: " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        msg "Setting up Postfix..."
        export SETUP_POSTFIX=0 >/dev/null
        export PARENT_EXEC_PVE_SETUP_POSTFIX=0 >/dev/null
        export PVE_HOSTNAME >/dev/null
        chmod +x pve_setup_postfix.sh
        ./pve_setup_postfix.sh
        echo
        break
      else
        warn "In the next steps you must have your 16 digit Gmail App Password OR Mailgun\ncredentials ready for input to continue.\nTry again..."
        echo
      fi
    else
      SETUP_POSTFIX=1 >/dev/null
      info "You have chosen to skip this step."
      echo
      break
    fi
    echo
  done
  # Activate E-Mail Notification & Email Alerts
  if [ $SETUP_POSTFIX = 0 ]; then
    # zfs-zed SW
    if [ $(dpkg -s zfs-zed >/dev/null 2>&1; echo $?) = 0 ]; then
      msg "Checking zfs-zed status..."
      info "zfs-zed status: ${GREEN}active (running).${NC}"
      echo
    else
      msg "Installing zfs-zed..."
      apt-get install -y zfs-zed >/dev/null
      if [ $(dpkg -s zfs-zed >/dev/null 2>&1; echo $?) = 0 ]; then
        info "zfs-zed status: ${GREEN}active (running).${NC}"
      fi
      echo
    fi
    sed -i 's|#ZED_EMAIL_ADDR.*|ZED_EMAIL_ADDR="root"|g' /etc/zfs/zed.d/zed.rc
  fi
fi

#### Activate E-Mail Notification & Email Alerts ####
if [ $PVE_TYPE = 0 ] || [ $PVE_TYPE = 1 ] && [ $SETUP_POSTFIX=0 ]; then
  section "$SECTION_HEAD - Activate E-Mail Notification & Email Alerts."

  box_out '#### PLEASE READ CAREFULLY - POSTFIX & EMAIL ALERTS ####' '' 'Send email alerts about your PVE host to the system’s designated administrator.' 'Be alerted about unwarranted login attempts and other system critical alerts.' 'Proxmox is preinstalled with Postfix SMTP server which we use for sending your' 'PVE nodes critical alerts.' '' 'SMTP is a simple Mail Transfer Agent (MTA) while easy to setup it' 'requires the following prerequisites and credentials:' '' '  --  SMTP SERVER' '      You require a SMTP server that can receive the emails from your machine' '      and send them to the designated administrator. ' '      If you use Gmail SMTP server its best to enable "App Passwords". An "App' '      Password" is a 16-digit passcode that gives an app or device permission' '      to access your Google Account.' '      Or you can use a mailgun.com flex account relay server (Recommended).' '' '  --  REQUIRED SMTP SERVER CREDENTIALS' '      1. Designated administrator email address' '         (i.e your working admin email address)' '      2. SMTP server address' '         (i.e smtp.gmail.com or smtp.mailgun.org)' '      3. SMTP server port' '         (i.e gmail port is 587 and mailgun port is 587)' '      4. SMTP server username' '         (i.e MyEmailAddress@gmail.com or postmaster@sandboxa6ac6.mailgun.org)' '      5. SMTP server default password' '         (i.e your Gmail App Password or mailgun SMTP password)' '' 'If you choose to proceed have your SMTP server credentials available.' 'This script will configure your PVE nodes Postfix SMTP server.'
  echo
  while true; do
    read -p "Install and configure Postfix and email alerts [y/n]?: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      echo
      read -p "Do you have your Gmail App or Mailgun credentials ready [y/n]?: " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        msg "Setting up Postfix..."
        export SETUP_POSTFIX=0 >/dev/null
        export PARENT_EXEC_PVE_SETUP_POSTFIX=0 >/dev/null
        export PVE_HOSTNAME >/dev/null
        chmod +x pve_setup_postfix.sh
        ./pve_setup_postfix.sh
        echo
        break
      else
        warn "In the next steps you must have your 16 digit Gmail App Password OR Mailgun\ncredentials ready for input to continue.\nTry again..."
        echo
      fi
    else
      SETUP_POSTFIX=1 >/dev/null
      info "You have chosen to skip this step."
      echo
      break
    fi
    echo
  done
fi



####  Install and Configure SSH Authorised Keys  ####
if [ $PVE_TYPE = 0 ]; then
  section "$SECTION_HEAD - Configuring SSH Authorized Keys."

  box_out '#### PLEASE READ CAREFULLY - CONFIGURING SSH AUTHORIZED KEYS ####' '' 'You can use a SSH key for connecting to the PVE root account over SSH.' 'PVE requires all SSH keys to be in the OpenSSH format. Your SSH key choices are:' '' '      1. Append or add your existing SSH Public Key to your PVE hosts' '         authorized keys file.' '      2. Generate a a new set of SSH key pairs.' '' 'If you choose to append your existing SSH Public Key to your PVE host you will' 'be prompted to paste your Public Key into this terminal console. Use your' 'mouse right-click to paste.'
  echo
  read -p "Configure your PVE host for SSH key access [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo
    export SETUP_SSHKEY=0 >/dev/null
    export PARENT_EXEC_PVE_SETUP_SSHKEY=0 >/dev/null
    export PVE_HOSTNAME >/dev/null
    chmod +x pve_setup_sshkey.sh
    ./pve_setup_sshkey.sh
  else
    SETUP_SSHKEY=1 >/dev/null
    info "You have chosen to skip this step."
  fi
  echo
fi

####  Install and Configure Fail2Ban  ####
if [ $PVE_TYPE = 0 ] || [ $PVE_TYPE = 1 ]; then
  section "$SECTION_HEAD - Install and Configure Fail2Ban."

  box_out '#### PLEASE READ CAREFULLY - CONFIGURING FAIL2BAN ####' '' 'Fail2Ban is an intrusion prevention software framework that protects computer' 'servers from brute-force attacks.' '' 'Most commonly this is used to block selected IP addresses that may belong to' 'hosts that are trying to breach the systems security. It can ban any host' 'IP address that makes too many login attempts or performs any other unwanted' 'action within a time frame defined by the PVE administrator.' '' 'Our default Fail2ban configuration sets the following rulesets:' '  --  PVE WEBGUI HTTP(S) ACCESS' '      Maximum HTTP retry 3 attempts.' '      PVE HTTP(S) ban time is 1 hour.' 'If your PVE Postfix SMTP server is configured and working Fail2ban will' 'configured to send email alerts.' '  --  PVE EMAIL ALERTS' '      Send email alerts of banned login attempts.' '      (requires working PVE Postfix SMTP server.)'
  echo
  read -p "Install and configure Fail2ban [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo
    export SETUP_FAIL2BAN=0 >/dev/null
    export PARENT_EXEC_PVE_SETUP_FAIL2BAN=0 >/dev/null
    export PVE_HOSTNAME >/dev/null
    chmod +x pve_setup_fail2ban.sh
    ./pve_setup_fail2ban.sh
  else
    SETUP_FAIL2BAN=1 >/dev/null
    info "You have chosen to skip this step."
  fi
  echo
fi


### Applying changes to PVE Host ####
section "$SECTION_HEAD - Applying changes to PVE Host."
if [ "$PVE_HOSTNAME" != "$HOSTNAME" ]; then
  msg "Applying new hostname to PVE host system..."
  hostnamectl set-hostname $PVE_HOSTNAME
  msg "Updating new hostname in /etc/hosts file..."
  sed -i "s/$HOSTNAME/$PVE_HOSTNAME/g" /etc/hosts >/dev/null
  msg "Updating new hostname in /etc/postfix/main.cf..."
  sed -i "s/$HOSTNAME/$PVE_HOSTNAME/g" /etc/postfix/main.cf >/dev/null
  msg "Updating new hostname in /etc/pve/storage.cfg file..."
  sed -i "s/$HOSTNAME/$PVE_HOSTNAME/g" /etc/pve/storage.cfg 2>/dev/null
  msg "Waiting for PVE to create a new $PVE_HOSTNAME node...\n  (be patient, this might take a while!)"
  while [ ! -d /etc/pve/nodes/$PVE_HOSTNAME ]; do sleep 1; done
  msg "Creating backup of $HOSTNAME configuration files..."
  cp -r /etc/pve/nodes/$HOSTNAME . 2>/dev/null
  msg "Copying $HOSTNAME configuration files to new $PVE_HOSTNAME node..."
  cp $(pwd)/$HOSTNAME/qemu-server/* /etc/pve/nodes/$PVE_HOSTNAME/qemu-server 2>/dev/null
  # msg "Copying $HOSTNAME lxc configuration files to new $PVE_HOSTNAME node..."
  # cp $(pwd)/$HOSTNAME/lxc/* /etc/pve/nodes/$PVE_HOSTNAME/lxc 2>/dev/null
  msg "Removing old $HOSTNAME configuration files from /etc/pve/nodes..."
  rm -R /etc/pve/nodes/$HOSTNAME >/dev/null
fi


#### Finish Status ####
section "$SECTION_HEAD - Completion Status."
if [ $PVE_NET = 0 ] && [ "$PVE_HOSTNAME" != "echo $HOSTNAME" ] || [ "$PVE_HOST_IP" != "`hostname -i`/$(ip addr show |grep -w inet |grep -v 127.0.0.1|awk '{ print $2}'| cut -d "/" -f 2)" ]; then
  # New hostname, IP address
  info "Success. Your PVE host is nearly fully configured. Because your PVE host\nis scheduled for a change in hostname and ethernet IP address this host\nrequires a reboot. On reboot this SSH connection will be lost.\n\nTo reconnect a SSH connection your login credentials are:\n    Username: ${YELLOW}root${NC}\n$(if [[ $(cat /etc/ssh/sshd_config | grep "^PasswordAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PubkeyAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PermitRootLogin prohibit-password") ]]; then echo "    SSH security method: ${YELLOW}SSH private key only.${NC}\n    SSH Private Key: ${YELLOW}You must have it.${NC}\n    Password: ${YELLOW}Not Permitted${NC} (SSH Private Key only).";elif [[ $(cat /etc/ssh/sshd_config | grep "^PasswordAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PubkeyAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PermitRootLogin yes") ]]; then echo "    SSH security method: ${YELLOW}SSH private key & Password.${NC}\n    SSH Private Key: ${YELLOW}You must have it.${NC}\n    Password: ${YELLOW}You must have it.${NC}";elif [[ $(cat /etc/ssh/sshd_config | grep "^PasswordAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PubkeyAuthentication no") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PermitRootLogin yes") ]]; then echo "    SSH security method: ${YELLOW}Password only.${NC}";fi)\n    PVE Server LAN IP Address: ${YELLOW}$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')${NC}\n    Terminal SSH CLI command: ${YELLOW}ssh root@$(echo "$PVE_HOST_IP" | sed  's/\/.*//g')${NC}\n\nThe PVE web interface can be reached via ${YELLOW}https://$(echo "$PVE_HOST_IP" | sed  's/\/.*//g'):8006${NC}\n    Default login username: ${YELLOW}root${NC}\n    Password: ${YELLOW}You must have it.${NC}\nThe root user password is what you specified during the PVE installation process."
  echo
  msg "If you cannot connect to your PVE host after rebooting check the following:\n      1. The ethernet LAN cable is connected to correct PVE hardware NIC(s). You\n      may have re-assigned PVE default LAN vmbr0 to a different hardware NIC."
  echo
  msg "You will now be prompted to reboot this PVE host (RECOMMENDED). If you\nchoose NOT to reboot now then you MUST at a later stage."
  read -p "Reboot this PVE host now (RECOMMENDED) [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    msg "Performing a reboot in 3 seconds...\n(your ssh connection will be lost)"
    # Cleanup
    cleanup
    sleep 3
    reboot
  else
    info "You have chosen NOT to perform a PVE system reboot. Remember you\nMUST perform a system reboot at some stage to invoke the changes!"
    # Cleanup
    cleanup
  fi
elif [ $PVE_NET = 1 ]; then
  # Same hostname, IP address
  info "Success. Your PVE host is nearly fully configured.\n\nTo make a SSH connection your login credentials are:\n    Username: ${YELLOW}root${NC}\n$(if [[ $(cat /etc/ssh/sshd_config | grep "^PasswordAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PubkeyAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PermitRootLogin prohibit-password") ]]; then echo "    SSH security method: ${YELLOW}SSH private key only.${NC}\n    SSH Private Key: ${YELLOW}You must have it.${NC}\n    Password: ${YELLOW}Not Permitted${NC} (SSH Private Key only).";elif [[ $(cat /etc/ssh/sshd_config | grep "^PasswordAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PubkeyAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PermitRootLogin yes") ]]; then echo "    SSH security method: ${YELLOW}SSH private key & Password.${NC}\n    SSH Private Key: ${YELLOW}You must have it.${NC}\n    Password: ${YELLOW}You must have it.${NC}";elif [[ $(cat /etc/ssh/sshd_config | grep "^PasswordAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PubkeyAuthentication no") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PermitRootLogin yes") ]]; then echo "    SSH security method: ${YELLOW}Password only.${NC}";fi)\n    PVE Server LAN IP Address: ${YELLOW}`hostname -i`${NC}\n    Terminal SSH CLI command: ${YELLOW}ssh root@`hostname -i`${NC}\n\nThe PVE web interface can be reached via ${YELLOW}https://`hostname -i`:8006${NC}\n    Default login username: ${YELLOW}root${NC}\n    Password: ${YELLOW}You must have it.${NC}\nThe root user password is what you specified during the PVE installation process.\n\n$(if [ $SETUP_SSHKEY=0 ]; then echo "To finish we need to restart some system services.\n    Restarting service: ${YELLOW}SSHd${NC}";service sshd restart >/dev/null 2>&1;fi)"
  # Cleanup
  cleanup
fi