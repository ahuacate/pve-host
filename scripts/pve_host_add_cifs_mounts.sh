#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_add_cifs_mounts.sh
# Description:  Source script for creating PVE Host NFS Mounts
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------

#bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-setup/master/scripts/pve_host_add_cifs_mounts.sh)"

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
SECTION_HEAD='PVE Host CIFS Storage Point'
# Check PVE Hostname variable
if [ -z "${SETUP_FAIL2BAN+x}" ]; then
  PVE_HOSTNAME=$HOSTNAME
  clear
fi

#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------

#---- About PVE CIFS Storage Mounts
if [ -z "${ADD_CIFS_MOUNTS+x}" ] && [ -z "${PARENT_EXEC_PVE_ADD_CIFS_MOUNTS+x}" ]; then
  section "About PVE CIFS Storage Mounts."

  msg_box "#### PLEASE READ CAREFULLY - NAS SMB/CIFS SERVER EXPORTS ####\n
  Proxmox can add storage by creating a CIFS backend storage pool. Your NAS server CIFS properties must be configured so your PVE CIFS backend (client) can mount the SMB/CIFS shares automatically. Your CIFS server should support SMB3 protocol (PVE default). SMB1 is NOT supported. All NAS server exports must be permitted to PVE nodes IPv4 addresses (i.e 192.168.1.101-192.168.1.104). You will require a valid NAS SMB user with credentials (username and password) with suitable (i.e privatelab:rwx) permissions.

  We need to set some variables. The next steps requires your input. You can accept our default values by pressing ENTER on your keyboard. Or overwrite our default value by typing in your own value and then pressing ENTER to accept and to continue to the next step."
  echo
  read -p "Create PVE CIFS storage mounts [y/n]? " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    ADD_CIFS_MOUNTS=0 >/dev/null
  else
    ADD_CIFS_MOUNTS=1 >/dev/null
    info "You have chosen to skip this step."
    exit 0
  fi
echo
fi


#---- Checking PVE Host Prerequisites
section "Checking Prerequisites"

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


#---- Checking PVE Host Prerequisites
section "Checking Prerequisites"

# Set Server IP
while true; do
read -p "Enter your SMB/CIFS Server IPv4 address: " -e -i 192.168.1.10 NAS_IP
if [ $(expr "$NAS_IP" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) == 0 ] && [ $(ping -s 1 -c 2 "$(echo "$NAS_IP")" > /dev/null; echo $?) = 0 ]; then
info "CIFS Server IPv4 address is set: ${YELLOW}$NAS_IP${NC}."
echo
break
elif [ $(expr "$NAS_IP" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) != 0 ]; then
warn "There are problems with your input:
1.  Your IP address is incorrectly formatted. It must be in the IPv4 format
    (i.e xxx.xxx.xxx.xxx ).
Try again..."
echo
elif [ $(expr "$NAS_IP" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) == 0 ] && [ $(ping -s 1 -c 2 "$(echo "$NAS_IP")" > /dev/null; echo $?) != 0 ]; then
warn "There are problems with your input:
1. The IP address meets the IPv4 standard, BUT
2. The IP address $(echo "$NAS_IP") is not reachable by ping.
Try again..."
echo
fi
done
# Set Server hostname
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
# Set SMB version
msg "Confirm your NAS Samba version..."
SMB_VER_MIN=2.0
SMB_VER_MAX=3.0
while true; do
read -p "Enter your NAS Samba version number (default is 3.0): " -e -i 3.0 NAS_SMB_VER
if [[ $NAS_SMB_VER =~ ^[0-9]+\.?[0-9]$ ]] && [ $NAS_SMB_VER = 2.0 ] || [ $NAS_SMB_VER = 2.1 ] || [ $NAS_SMB_VER = 3.0 ]; then
  info "NAS SMB Version is set: ${YELLOW}SMB$NAS_SMB_VER${NC}."
  echo
  break
elif [[ ! $NAS_SMB_VER =~ ^[0-9]+\.?[0-9]$ ]]; then
warn "There are problems with your input:
1.  Invalid input. SMB versions are decimal fraction.
    Change your SMB version input to 2.0 or 2.1 or 3.0.
    Try again..."
echo
elif [[ $NAS_SMB_VER =~ ^[0-9]+\.?[0-9]$ ]] && [[ $NAS_SMB_VER < $SMB_VER_MIN ]]; then
warn "There are problems with your input:
1.  SMB versions lower than SMB$SMB_VER_MIN are not supported due to security issues.
    Upgrade your SMB server to SMB$SMB_VER_MIN or later.
    Try again..."
echo
elif [[ $NAS_SMB_VER =~ ^[0-9]+\.?[0-9]$ ]] && [[ $NAS_SMB_VER > $SMB_VER_MAX ]]; then
warn "There are problems with your input:
1.  SMB versions above SMB$SMB_VER_MAX are not valid.
    Change your SMB version input to 2.0 or 2.1 or 3.0.
    Try again..."
echo
elif [[ $NAS_SMB_VER =~ ^[0-9]+\.?[0-9]$ ]] && [[ $NAS_SMB_VER > $SMB_VER_MIN ]] && [[ $NAS_SMB_VER < $SMB_VER_MAX ]] && [ $NAS_SMB_VER != 2.0 ] || [ $NAS_SMB_VER != 2.1 ] || [ $NAS_SMB_VER != 3.0 ]; then
warn "There are problems with your input:
1.  SMB$NAS_SMB_VER version is not supported or valid.
    Change your SMB version input to 2.0 or 2.1 or 3.0.
    Try again..."
echo
fi
done


#---- SMB/CIFS Server Credentials
section "SMB/CIFS Server Credentials."

msg_box "#### PLEASE READ CAREFULLY - SMB/CIFS SERVER CREDENTIALS ####\n
Your NAS SMB/CIFS Server shares are likely to be password protected. To create PVE CIFS backend storage pools we require your SMB login credentials. The login user must have suitable permissions (i.e privatelab:rwx) to acccess, read, write and execute to the selected SMB server shares you wish to mount.

If you have more than one SMB/CIFS Server and/or SMB login username run this script again for each SMB/CIFS Server IP and SMB login username.

If your SMB/CIFS Server is password protected then you will need to input your NAS SMB login username and password in the next steps."
echo

read -p "Do you require SMB login credentials for ${NAS_HOSTNAME^} [y/n]? " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  SMB_CREDENTIALS=0
  # Enter SMB Server password
  while true; do
    read -p "Enter SMB Server login username : " SMB_USERNAME
    echo
    read -s -p "Enter Password: " SMB_PASSWORD
    echo
    read -s -p "Enter Password (again): " SMB_PASSWORD2
    echo
    [ "$SMB_PASSWORD" = "$SMB_PASSWORD2" ] && echo "$SMB_USERNAME $SMB_PASSWORD" > smb_login.txt && break
    warn "Passwords do not match. Please try again."
  done
  info "SMB server login credentials are set: ${YELLOW}$SMB_USERNAME${NC}"
else
  SMB_CREDENTIALS=1
  info "SMB server login credentials are set: ${YELLOW}$Not Required${NC}"
fi
echo


#---- Create PVE Storage Mounts
section "Create PVE Storage Mounts."

# Scanning SMB/CIFS Server for exports
msg "Creating a list of CIFS Server $NAS_IP exports..."
pvesm scan cifs $NAS_IP $(if [ $SMB_CREDENTIALS == 0 ]; then echo "--username $SMB_USERNAME --password $SMB_PASSWORD";fi) | awk '{print $1}' | sort > pvesm_cifs_export_list_var01
# Removing /backup export
sed "/.*\/backup/d" pvesm_cifs_export_list_var01 > pvesm_cifs_export_list_var02
# Modifying /proxmox to /proxmox/backup
if [ $(cat pvesm_cifs_export_list_var02 | grep '/proxmox$' > /dev/null; echo $?) == 0 ]; then
  msg "Modifying $(cat pvesm_cifs_export_list_var02 | grep '/proxmox$') to $(cat pvesm_cifs_export_list_var02 | grep '/proxmox$')/backup..."
  sed -i 's/proxmox$/proxmox\/backup/g' pvesm_cifs_export_list_var02
fi
echo

# Selecting and identifying exports
msg "You have $(cat pvesm_cifs_export_list_var02 | wc -l)x CIFS server mount points available on $NAS_HOSTNAME.\nNext you will be prompted to enter a numerical value (i.e 1-$(cat $DIR/source/pve_host_source_cifs_mounts | wc -l)) to identify\na media type for for each available $NAS_HOSTNAME CIFS mount point.\n\nTo ignore and remove a CIFS mount point choose:\n  1) ${YELLOW}None${NC} - Ignore this share.\nTo exit and leave the selection task choose:\n  "$(cat $DIR/source/pve_host_source_cifs_mounts | wc -l)") ${YELLOW}Exit/Finished${NC} - Nothing more to add."
echo
mapfile -t options < $DIR/source/pve_host_source_cifs_mounts
while IFS=, read -r line
do
  PS3="Select the media type for CIFS share ${WHITE}$line${NC} (entering numeric) : "
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
    info "CIFS share ${WHITE}$line${NC} is set as : $(echo $media_type | awk '{print $1}')"
  fi
  read -p "Confirm your selection is correct: [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo $(cat pvesm_cifs_export_list_var02 | grep $line) $(echo ${NAS_HOSTNAME,,})-$(echo ${media_type,,} | awk '{print $1}' | sed "s/\x1B\[\([0-9]\{1,2\}\(;[0-9]\{1,2\}\)\?\)\?[mGK]//g") >> pvesm_cifs_export_list_var03
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
done < pvesm_cifs_export_list_var02
echo

# Removing all CIFS shares identified as "none"
sed -i "/${NAS_HOSTNAME,,}-none/d" pvesm_cifs_export_list_var03
# Checking for existing PVE storage mounts
pvesm status | grep -E 'nfs|cifs' | awk '{print $1}' | tr '[:upper:]' '[:lower:]' > pvesm_existing_mount_var01 || true
cat $DIR/source/pve_host_source_cifs_mounts | grep -Evi 'None|Exit/Finished' | awk -F' - ' '{print $1}' | tr '[:upper:]' '[:lower:]' | sed "s/^/$NAS_HOSTNAME-/" > pvesm_existing_mount_var02 || true
grep -i -E -f pvesm_existing_mount_var01 pvesm_existing_mount_var02 > pvesm_existing_mount_var03 || true
IFS=' '
while read -r w; do
  if [ $(grep $w pvesm_cifs_export_list_var03 >/dev/null; echo $?) == 0 ]; then
    msg "Checking PVE host for duplicate storage mounts..."
    info "Removing duplicate storage mount: ${YELLOW}$w${NC}"
    sed -i "/$w/d" pvesm_cifs_export_list_var03
    echo
  fi
done < pvesm_existing_mount_var03

# Create PVE Storage Mounts
if [ $(cat pvesm_cifs_export_list_var03 | wc -l) -ge 1 ]; then
  IFS=' '
  while read -r SHARE PVE_MNT_LABEL; do
    if [ $PVE_MNT_LABEL == $(echo ${NAS_HOSTNAME,,}-backup) ]; then
      msg "Creating PVE storage mount..."
      pvesm add cifs $PVE_MNT_LABEL --server $NAS_IP --path /mnt/pve/$PVE_MNT_LABEL --share $SHARE --content backup --maxfiles 3 --smbversion $NAS_SMB_VER $(if [ $SMB_CREDENTIALS == 0 ]; then echo "--username $SMB_USERNAME --password $SMB_PASSWORD";fi)
      info "PVE storage mount created: ${YELLOW}$PVE_MNT_LABEL${NC}\n       ($NAS_IP:$SHARE)"
      echo
    else
      msg "Creating PVE storage mount..."
      pvesm add cifs $PVE_MNT_LABEL --server $NAS_IP --path /mnt/pve/$PVE_MNT_LABEL --share $SHARE --content images --smbversion $NAS_SMB_VER $(if [ $SMB_CREDENTIALS == 0 ]; then echo "--username $SMB_USERNAME --password $SMB_PASSWORD";fi)
      info "PVE storage mount created: ${YELLOW}$PVE_MNT_LABEL${NC}\n       ($NAS_IP:$SHARE)"
      echo    
    fi
  done < pvesm_cifs_export_list_var03
else
  msg "There are no PVE storage mounts to create."
  echo
fi


#---- Finish Status
section "$SECTION_HEAD - Completion Status."

echo
msg "${WHITE}Success.${NC}"
sleep 3

# Cleanup
if [ -z ${PARENT_EXEC_PVE_ADD_CIFS_MOUNTS+x} ]; then
  cleanup
fi