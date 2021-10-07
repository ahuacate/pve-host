#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_add_nfs_mounts.sh
# Description:  Source script for creating PVE Host NFS Mounts
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------

#bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-setup/master/scripts/pve_host_add_nfs_mounts.sh)"

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

# Run Bash Header
source $PVE_SOURCE/pvesource_bash_defaults.sh

#---- Static Variables -------------------------------------------------------------

# Easy Script Section Header Body Text
SECTION_HEAD='PVE Host NFS Storage Point'
# Check PVE Hostname variable
if [ -z "${SETUP_FAIL2BAN+x}" ]; then
  PVE_HOSTNAME=$HOSTNAME
  clear
fi

#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------

#---- About PVE NFS Storage Mounts
if [ -z "${ADD_NFS_MOUNTS+x}" ] && [ -z "${PARENT_EXEC_PVE_ADD_NFS_MOUNTS+x}" ]; then
  section "About PVE NFS Storage Mounts."

  msg_box "#### PLEASE READ CAREFULLY - NAS NFS & CIFS SERVER EXPORTS ####\n
  Proxmox can add storage by creating NFS and/or CIFS backend storage pools. Your NAS server NFS/CIFS properties must be configured so your PVE NFS/CIFS backend (client) can mount the NAS shares automatically. Your NAS server should support:

    NFS VERSION
      --  NFS v3/v4
    
      --  NAS NFS exports to all PVE nodes (i.e 192.168.1.101-192.168.1.109)

  We need to set some variables. The next steps requires your input. You can accept our default values by pressing ENTER on your keyboard. Or overwrite our default value by typing in your own value and then pressing ENTER to accept and to continue to the next step."
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


#---- Checking PVE Host Prerequisites
section "Check Prerequisites"

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


#---- Checking NFS Server exports
section "Check NFS Server exports"

while true; do
  read -p "Enter your NFS NAS Server IPv4 address: " -e -i 192.168.1.10 NAS_IP
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
  warn "Your NFS Server $NAS_IP is running NFSv2 or older. You must upgrade your NFS server to NFSv3 or higher. User intervention required. Exiting installation script in 3 seconds."
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


#---- Create PVE Storage Mounts
section "Create PVE Storage Mounts"

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
msg "You have $(cat pvesm_nfs_export_list_var02 | wc -l)x NFS server mount points available on $NAS_HOSTNAME.\nNext you will be prompted to enter a numerical value (i.e 1-$(cat $DIR/source/pve_host_source_nfs_mounts | wc -l)) to identify\na media type for for each available $NAS_HOSTNAME NFS mount point.\n\nTo ignore and remove a NFS mount point choose:\n  1) ${YELLOW}None${NC} - Ignore this share.\nTo exit and leave the selection task choose:\n  "$(cat $DIR/source/pve_host_source_nfs_mounts | wc -l)") ${YELLOW}Exit/Finished${NC} - Nothing more to add."
echo
mapfile -t options < $DIR/source/pve_host_source_nfs_mounts
while IFS=, read -r line
do
  PS3="Select the media type for NFS share ${WHITE}$line${NC} (entering numeric) : "
  select media_type in "${options[@]}"
  do
  echo
  if [[ "$(echo $media_type | awk '{print $1}')" == *"Exit/Finished"* ]]; then
    info "You have chosen to finish and exit this task. No more mount points to add."
    read -p "Are you sure: [y/n]?: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      echo
      break
    fi
  else
    info "NFS share ${WHITE}$line${NC} is set as : $(echo $media_type | awk '{print $1}')"
  fi
  read -p "Confirm your selection is correct: [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo $(cat pvesm_nfs_export_list_var02 | grep $line) $(echo ${NAS_HOSTNAME,,})-$(echo ${media_type,,} | awk '{print $1}' | sed "s/\x1B\[\([0-9]\{1,2\}\(;[0-9]\{1,2\}\)\?\)\?[mGK]//g") >> pvesm_nfs_export_list_var03
    echo
    break
  elif [[ $REPLY =~ ^[Nn]$ ]]; then
    echo
    warn "No good. No problem. Try again."
    sleep 2
    echo
  fi
  done < /dev/tty
  if [[ "$(echo $media_type | awk '{print $1}')" == *"Exit/Finished"* ]]; then
    break
  fi
done < pvesm_nfs_export_list_var02
echo

# Removing all NFS shares identified as "none"
sed -i "/${NAS_HOSTNAME,,}-none/d" pvesm_nfs_export_list_var03

# Checking for existing PVE storage mounts
pvesm status | grep -E 'nfs|cifs' | awk '{print $1}' | tr '[:upper:]' '[:lower:]' > pvesm_existing_mount_var01 || true
cat $DIR/source/pve_host_source_nfs_mounts | grep -Evi 'None|Exit/Finished' | awk -F' - ' '{print $1}' | tr '[:upper:]' '[:lower:]' | sed "s/^/$NAS_HOSTNAME-/" > pvesm_existing_mount_var02 || true
grep -i -E -f pvesm_existing_mount_var01 pvesm_existing_mount_var02 > pvesm_existing_mount_var03 || true

IFS=' '
while read -r w; do
  if [ $(grep $w pvesm_nfs_export_list_var03 >/dev/null; echo $?) == 0 ]; then
    msg "Checking PVE host for duplicate storage mounts..."
    info "Removing duplicate storage mount: ${YELLOW}$w${NC}"
    sed -i "/$w/d" pvesm_nfs_export_list_var03
    echo
  fi
done < pvesm_existing_mount_var03

# Create PVE Storage Mounts
if [ $(cat pvesm_nfs_export_list_var03 | wc -l) -ge 1 ]; then
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
else
  msg "There are no PVE storage mounts to create."
  echo
fi


#### Finish Status ####
section "Completion Status"

echo
msg "${WHITE}Success.${NC}"
sleep 3

# Cleanup
if [ -z ${PARENT_EXEC_PVE_ADD_NFS_MOUNTS+x} ]; then
  cleanup
fi