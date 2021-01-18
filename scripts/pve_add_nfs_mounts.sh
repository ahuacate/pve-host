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

# Check PVE Hostname variable
if [ -z "${SETUP_FAIL2BAN+x}" ]; then
  PVE_HOSTNAME=$HOSTNAME
fi

# Script Variables
SECTION_HEAD="Proxmox NFS Storage Point Setup"


# Download external scripts

#########################################################################################
# This script is for creating your Proxmox Host NFS Storage Points                      #
#                                                                                       #
# Tested on Proxmox Version : pve-manager/6.1-3/37248ce6 (running kernel: 5.3.10-1-pve) #
#########################################################################################


# Command to run script
#bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/proxmox-node/master/scripts/pve_add_nfs_mounts.sh)"


#### About PVE NFS Storage Mounts ####
if [ -z "${ADD_NFS_MOUNTS+x}" ] && [ -z "${PARENT_EXEC_PVE_ADD_NFS_MOUNTS+x}" ]; then
section "$SECTION_HEAD - About PVE NFS Storage Mounts."

box_out '#### PLEASE READ CAREFULLY - NAS NFS SERVER EXPORTS ####' '' 'Proxmox can add storage by creating a NFS backend storage pool. Your NAS' 'server NFS properties must be configured so your PVE NFS backend (client)' 'can mount the NFS shares automatically. Your NFS server should support' 'NFSv3/v4. All NAS server exports must be permitted to your PVE nodes' 'IPv4 addresses (i.e 192.168.1.101-192.168.1.104).' '' 'We need to set some variables. The next steps requires your input. You can' 'accept our default values by pressing ENTER on your keyboard. Or overwrite our' 'default value by typing in your own value and then pressing ENTER to' 'accept and to continue to the next step.'
echo
read -p "Create PVE NFS storage mounts [y/n]? " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  ADD_NFS_MOUNTS=0 >/dev/null
else
  ADD_NFS_MOUNTS=1 >/dev/null
  info "You have chosen to skip this step."
  exit 0
fi
echo
fi


#### Checking PVE Host Prerequisites ####
section "$SECTION_HEAD - Checking Prerequisites"

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


#### Checking NFS Server exports ####
section "$SECTION_HEAD - Check NFS Server exports."

while true; do
  read -p "Enter your NFS Server IPv4 address: " -e -i 192.168.1.10 NAS_IP
  if [ $(expr "$NAS_IP" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) == 0 ] && [ $(ping -s 1 -c 2 "$(echo "$NAS_IP")" > /dev/null; echo $?) = 0 ]; then
  info "NFS Server IPv4 address is set: ${YELLOW}$NAS_IP${NC}."
  echo
  break
  elif [ $(expr "$NAS_IP" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) != 0 ]; then
  warn "There are problems with your input:\n1.  Your IP address is incorrectly formatted. It must be in the IPv4 format\n    (i.e xxx.xxx.xxx.xxx ).\nTry again..."
  echo
  elif [ $(expr "$NAS_IP" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) == 0 ] && [ $(ping -s 1 -c 2 "$(echo "$NAS_IP")" > /dev/null; echo $?) != 0 ]; then
  warn "There are problems with your input:\n1. The IP address meets the IPv4 standard, BUT\n2. The IP address $(echo "$NAS_IP") is not reachable by ping.\nTry again..."
  echo
  fi
done

msg "Checking NFS version..."
NFS_VER=$(rpcinfo -p $NAS_IP | grep nfs | awk '{ print $2 }' | sort -k2 -nr | head -1)
if [ $NFS_VER -ge 4 ]; then
  info "NFS version check: ${GREEN}PASS${NC}"
elif [ $NFS_VER -lt 4 ] && [ $NFS_VER -ge 3 ]; then
  info "NFS version check: ${GREEN}PASS${NC} (NFSv3 limited)"
elif [ $NFS_VER -lt 3 ]; then
  NFS_VER=1
  warn "Your NFS Server $NAS_IP is running NFSv2 or older. You must upgrade your\nNFS server to NFSv3 or higher. User intervention required.\nExiting installation script in 3 seconds."
  sleep 3
  exit 0
fi
echo

msg "Confirm your NAS hostname..."
NAS_HOSTNAME="$(nbtscan -q $NAS_IP | awk '{print $2}')"
NAS_HOSTNAME=${NAS_HOSTNAME,,}
read -p "Confirm your NAS hostname is ${WHITE}"$NAS_HOSTNAME"${NC} [y/n]?: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  info "NAS Hostname is set: ${YELLOW}$NAS_HOSTNAME${NC}."
else
  read -p "Enter a new NAS Hostname: " -e -i $NAS_HOSTNAME NAS_HOSTNAME
  info "NAS Hostname is set: ${YELLOW}$NAS_HOSTNAME${NC}."
fi
echo


#### Create PVE Storage Mounts ####
section "$SECTION_HEAD - Create PVE Storage Mounts."

# Scanning NFS Server for exports
msg "Creating a list of NFS Server $NAS_IP exports..."
pvesm nfsscan $NAS_IP | awk '{print $1}' | sort > pvesm_nfs_export_list_var01
# Removing /backup export
sed "/.*\/backup/d" pvesm_nfs_export_list_var01 > pvesm_nfs_export_list_var02
# Modifying /proxmox to /proxmox/backup
if [ $(cat pvesm_nfs_export_list_var02 | grep '/proxmox$' > /dev/null; echo $?) == 0 ]; then
  msg "Modifying $(cat pvesm_nfs_export_list_var02 | grep '/proxmox$') to $(cat pvesm_nfs_export_list_var02 | grep '/proxmox$')/backup..."
  sed -i 's/proxmox$/proxmox\/backup/g' pvesm_nfs_export_list_var02
fi
echo

# Selecting and identifying exports
msg "You have $(cat pvesm_nfs_export_list_var02 | wc -l)x NFS server mount points available on $NAS_HOSTNAME.\nNext you will be prompted to enter a numerical value (i.e 1-14) to identify\na media type for for each available $NAS_HOSTNAME NFS mount point.\nTo ignore or remove a NFS mount point select media type 1:\n  --  1) ${YELLOW}None${NC} - Ignore NFS share."
echo
TYPE01="${YELLOW}None${NC} - Ignore NFS share."
TYPE02="${YELLOW}Audio${NC} - Audiobooks and podcasts."
TYPE03="${YELLOW}Backup${NC} - PVE LXC settings backup storage."
TYPE04="${YELLOW}Books${NC} - Ebooks and Magazines"
TYPE05="${YELLOW}Cloudstorage${NC} - Private user cloud storage."
TYPE06="${YELLOW}Docker${NC} - Docker storage."
TYPE07="${YELLOW}Downloads${NC} - General Download folders."
TYPE08="${YELLOW}Git${NC} - Git and Github folders."
TYPE09="${YELLOW}Homes${NC} - Users home folders."
TYPE10="${YELLOW}Music${NC} - Music, Albums and Songs."
TYPE11="${YELLOW}Photo${NC} - Photographic image collection."
TYPE12="${YELLOW}Public${NC} - General public storage folder."
TYPE13="${YELLOW}SSHkey${NC} - SSH key pair storage."
TYPE14="${YELLOW}Timemachine${NC} - Apple Time machine folder."
TYPE15="${YELLOW}Transcode${NC} - Video transcoding disk (A must for transcoding)."
TYPE16="${YELLOW}Video${NC} - All video libraries (i.e movies, TV, homevideos)."

while IFS=, read -r line
do
  PS3="Select the media type for NFS share ${WHITE}$line${NC} (entering numeric) : "
  select media_type in "$TYPE01" "$TYPE02" "$TYPE03" "$TYPE04" "$TYPE05" "$TYPE06" "$TYPE07" "$TYPE08" "$TYPE09" "$TYPE10" "$TYPE11" "$TYPE12" "$TYPE13" "$TYPE14" "$TYPE15" "$TYPE16"
  do
  echo
  info "NFS share ${WHITE}$line${NC} is set as : $(echo $media_type | awk '{print $1}')"
  read -p "Confirm your selection is correct: [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo $(cat pvesm_nfs_export_list_var02 | grep $line) $(echo ${NAS_HOSTNAME,,})-$(echo ${media_type,,} | awk '{print $1}' | sed "s/\x1B\[\([0-9]\{1,2\}\(;[0-9]\{1,2\}\)\?\)\?[mGK]//g") >> pvesm_nfs_export_list_var03
    echo
    break
  else
    echo
    warn "No good. No problem. Try again."
    sleep 2
    echo
  fi
  done < /dev/tty
done < pvesm_nfs_export_list_var02
echo

# Removing all NFS shares identified as "none"
sed -i "/${NAS_HOSTNAME,,}-none/d" pvesm_nfs_export_list_var03

# Checking for existing PVE storage mounts
pvesm status | grep -E 'nfs|cifs' | awk '{print $1}' | grep -Ei "$NAS_HOSTNAME-audio|$NAS_HOSTNAME-books|$NAS_HOSTNAME-backup|$NAS_HOSTNAME-cloudstorage|$NAS_HOSTNAME-docker|$NAS_HOSTNAME-downloads|$NAS_HOSTNAME-git|$NAS_HOSTNAME-homes|$NAS_HOSTNAME-music|$NAS_HOSTNAME-photo|$NAS_HOSTNAME-public|$NAS_HOSTNAME-sshkey|$NAS_HOSTNAME-timemachine|$NAS_HOSTNAME-transcode|$NAS_HOSTNAME-video" | tr '[:upper:]' '[:lower:]' > pvesm_existing_mount_var01 || true

IFS=' '
while read -r w; do
  if [ $(grep $w pvesm_nfs_export_list_var03 >/dev/null; echo $?) == 0 ]; then
    msg "Checking PVE host for duplicate storage mounts..."
    info "Removing duplicate storage mount: ${YELLOW}$w${NC}"
    sed -i "/$w/d" pvesm_nfs_export_list_var03
    echo
  fi
done < pvesm_existing_mount_var01

# Create PVE Storage Mounts
IFS=' '
while read -r NFS_EXPORT PVE_MNT_LABEL; do
  if [ $PVE_MNT_LABEL == $(echo ${NAS_HOSTNAME,,}-backup) ]; then
    msg "Creating PVE storage mount..."
    pvesm add nfs $PVE_MNT_LABEL --path /mnt/pve/$PVE_MNT_LABEL --server $NAS_IP --export $NFS_EXPORT --content backup --maxfiles 3 --options vers=$NFS_VER
    info "PVE storage mount created: ${YELLOW}$PVE_MNT_LABEL${NC}\n       ($NAS_IP:$NFS_EXPORT)"
    echo
  else
    msg "Creating PVE storage mount..."
    pvesm add nfs $PVE_MNT_LABEL --path /mnt/pve/$PVE_MNT_LABEL --server $NAS_IP --export $NFS_EXPORT --content images --options vers=$NFS_VER
    info "PVE storage mount created: ${YELLOW}$PVE_MNT_LABEL${NC}\n       ($NAS_IP:$NFS_EXPORT)"
    echo    
  fi
done < pvesm_nfs_export_list_var03


#### Finish Status ####
section "$SECTION_HEAD - Completion Status."

echo
msg "${WHITE}Success.${NC}"
sleep 3

# Cleanup
if [ -z ${PARENT_EXEC_PVE_ADD_NFS_MOUNTS+x} ]; then
  cleanup
fi
