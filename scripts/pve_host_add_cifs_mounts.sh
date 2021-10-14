#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_add_cifs_mounts.sh
# Description:  Source script for creating PVE Host SMB/CIFS Mounts
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------

# bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-setup/master/scripts/pve_host_add_cifs_mounts.sh)"

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
SECTION_HEAD='PVE Host SMB/CIFS Storage Mount'

# Check for PVE Hostname mod
if [ -z "${HOSTNAME_FIX+x}" ]; then
  PVE_HOSTNAME=$HOSTNAME
fi

#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------

#---- Introduction
section "Introduction"

msg_box "#### PLEASE READ CAREFULLY - NAS NFS & CIFS SERVER EXPORTS ####\n
Your NAS server SMB/CIFS properties must be configured so your PVE CIFS backend (client) can mount the SMB/CIFS shares automatically. Your SMB/CIFS server should support SMB3 protocol (PVE default). SMB1 is NOT supported. Your NAS server should support:

  SMB VERSION
    --  SMB v2.02 minimum ( PVE default is v3.00 and above )
  
    --  NAS SMB shares to all PVE nodes (i.e default PVE nodes are 192.168.1.101-192.168.1.109)

The User is required to login a single NAS SMB user name and credentials (username and password). The login user must have suitable permissions (i.e privatelab:rwx) to acccess, read, write and execute to the SMB server shares you wish to mount. If you have more than one SMB/CIFS Server and/or SMB login username account then run this script again for each SMB/CIFS Server IP and SMB login username.

The next steps requires user input. You can accept our default values by pressing ENTER on your keyboard. Or overwrite our default value by typing in your own value and then pressing ENTER to accept and to continue to the next step."
echo
while true; do
  read -p "Create PVE SMB/CIFS storage mounts [y/n]?: " -n 1 -r YN
  echo
  case $YN in
    [Yy]*)
      info "The User has chosen to proceed."
      echo
      break
      ;;
    [Nn]*)
      info "The User has chosen to skip this step."
      exit 0
      break
      ;;
    *)
      warn "Error! Entry must be 'y' or 'n'. Try again..."
      echo
      ;;
  esac
done


#---- Checking PVE Host Prerequisites
section "Checking Prerequisites"

# nbtscan SW
if [ $(dpkg -s nbtscan >/dev/null 2>&1; echo $?) = 0 ]; then
  msg "Checking nbtscan status..."
  info "nbtscan status: ${GREEN}installed${NC}"
  echo
else
  msg "Installing nbtscan..."
  apt-get install -y nbtscan >/dev/null
  if [ $(dpkg -s nbtscan >/dev/null 2>&1; echo $?) = 0 ]; then
    info "nbtscan status: ${GREEN}installed${NC}"
  fi
  echo
fi


#---- Checking CIFS Server exports
section "Select CIFS server"

while true; do
  # Enter NAS IP
  while true; do
    read -p "Enter your SMB/CIFS Server IPv4 address: " -e -i 192.168.1.10 NAS_IP
    if [ $(expr "${NAS_IP}" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) == 0 ] && [ $(ping -s 1 -c 2 "$(echo "${NAS_IP}")" > /dev/null; echo $?) = 0 ]; then
      info "CIFS Server IPv4 address is set: ${YELLOW}${NAS_IP}${NC}."
      echo
      break
    elif [ $(expr "${NAS_IP}" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) != 0 ]; then
      warn "There are problems with your input:
      1.  Your IP address is incorrectly formatted. It must be in the IPv4 format
          (i.e xxx.xxx.xxx.xxx ).
      Try again..."
      echo
    elif [ $(expr "${NAS_IP}" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) == 0 ] && [ $(ping -s 1 -c 2 "$(echo "${NAS_IP}")" > /dev/null; echo $?) != 0 ]; then
      warn "There are problems with your input:
      1. The IP address meets the IPv4 standard, BUT
      2. The IP address $(echo "${NAS_IP}") is not reachable by ping.
      Try again..."
      echo
      fi
  done

  # Validate hostname
  while true; do
    NAS_HOSTNAME="$(nbtscan -q ${NAS_IP} | awk '{print $2}')"
    NAS_HOSTNAME=${NAS_HOSTNAME,,}
    read -p "Confirm NAS hostname is ${WHITE}'${NAS_HOSTNAME}'${NC}  [y/n]?: " -n 1 -r YN
    echo
    case $YN in
      [Yy]*)
        info "NAS Hostname is set: ${YELLOW}${NAS_HOSTNAME}${NC}."
        echo
        break 2
        ;;
      [Nn]*)
        while true; do
          read -p "Try entering another NAS IP address [y/n]?: " -n 1 -r YN
          echo
          case $YN in
            [Yy]*)
              info "Okay. Then try again..."
              echo
              break 2
              ;;
            [Nn]*)
              info "The User has chosen to skip this step."
              exit 0
              break
              ;;
            *)
              warn "Error! Entry must be 'y' or 'n'. Try again..."
              echo
              ;;
          esac
        done
        ;;
      *)
        warn "Error! Entry must be 'y' or 'n'. Try again..."
        echo
        ;;
    esac
  done
done

# Set SMB version
msg "Confirming NAS Samba version..."
SMB_VER_MIN='2.02'
SMB_VERS=$(nmap --script smb-protocols ${NAS_IP} | grep \| | sed 's/[^0-9]*//' | sed '/^$/d' | sort -n | tail -1)
if [[ ${SMB_VERS} > ${SMB_VER_MIN} ]]; then
  NAS_SMB_VER=${SMB_VERS}
  MAN_SET_SMB_VERS=1
  info "NAS SMB Version is set: ${YELLOW}SMB${NAS_SMB_VER}${NC}"
else
  MAN_SET_SMB_VERS=0
fi

if [ ${MAN_SET_SMB_VERS} == 0 ]; then
  msg_box "#### PLEASE READ CAREFULLY - SMB VERSION ####\n
  There are issues with determining the NAS server SMB protocol dialect (version). Proxmox requires a minimum SMB 2.02v. Check your NAS server SMB version support. If a firewall is blocking the SMB version broadcast then manually select the NAS SMB version."
  OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE02" "TYPE03" "TYPE04" "TYPE05" "TYPE06")
  OPTIONS_LABELS_INPUT=( "SMB 2.0" "SMB 2.1" "SMB 3.0" "SMB 3.02" "SMB 3.11 and above" "No idea. Need to upgrade NAS SMB. Exit this installer." )
  makeselect_input2
  singleselect SELECTED "$OPTIONS_STRING"
  # Manually set 
  if [ $(echo "${RESULTS[@]}") == TYPE01 ]; then
    NAS_SMB_VER='2.0'
  elif [ $(echo "${RESULTS[@]}") == TYPE02 ]; then
    NAS_SMB_VER='2.0'
  elif [ $(echo "${RESULTS[@]}") == TYPE03 ]; then
    NAS_SMB_VER='3.0'
  elif [ $(echo "${RESULTS[@]}") == TYPE04 ]; then
    NAS_SMB_VER='3.0'
  elif [ $(echo "${RESULTS[@]}") == TYPE05 ]; then
    NAS_SMB_VER='3.0'
  elif [ $(echo "${RESULTS[@]}") == TYPE06 ]; then
    info "Fix, upgrade or find your NAS SMB protocol dialect and try again. Exiting this script..."
    echo
    exit 0
  fi
fi


# SMB/CIFS Server Credentials
msg_box "#### PLEASE READ CAREFULLY - SMB/CIFS SERVER CREDENTIALS ####\n
Your NAS SMB/CIFS Server shares are likely to be password protected. To create PVE SMB/CIFS backend storage pools we require your SMB login credentials. The login user must have suitable permissions (i.e privatelab:rwx) to acccess, read, write and execute to the SMB server shares you wish to mount.

If you have more than one SMB/CIFS Server and/or SMB login username account then run this script again for each SMB/CIFS Server IP and SMB login username.

If your SMB/CIFS Server is password protected then you will need to input your NAS SMB login username and password in the next steps."
echo
while true; do
  read -p "Do you require SMB login credentials for '${NAS_HOSTNAME^}' [y/n]?: " -n 1 -r YN
  echo
  case $YN in
    [Yy]*)
      SMB_CREDENTIALS=0
      # Enter SMB Server password
      while true; do
        read -p "Enter SMB Server login username : " SMB_USERNAME
        echo
        read -p "Enter Password: " SMB_PASSWORD
        echo
        read -p "Enter Password (again): " SMB_PASSWORD2
        echo
        [ "${SMB_PASSWORD}" = "${SMB_PASSWORD2}" ] && echo "${SMB_USERNAME} ${SMB_PASSWORD}" > smb_login.txt && break
        warn "Passwords do not match. Please try again."
      done
      info "SMB server login credentials are set: ${YELLOW}${SMB_USERNAME}${NC} ( username )"
      echo
      break 
      ;;
    [Nn]*)
      SMB_CREDENTIALS=1
      info "SMB server login credentials are set: ${YELLOW}Not Required${NC}"
      echo
      break
      ;;
    *)
      warn "Error! Entry must be 'y' or 'n'. Try again..."
      echo
      ;;
  esac
done

#---- Create PVE Storage Mounts
section "Create PVE Storage Mounts."

# Scanning SMB/CIFS Server for exports
msg "Creating a list of SMB/CIFS Server ${NAS_IP} exports..."
pvesm scan cifs ${NAS_IP} $(if [ ${SMB_CREDENTIALS} == 0 ]; then echo "--username ${SMB_USERNAME} --password ${SMB_PASSWORD}";fi) | awk '{print $1}' | sort > pvesm_cifs_export_list_var01
# Removing /backup export
sed "/backup$/d" pvesm_cifs_export_list_var01 > pvesm_cifs_export_list_var02
# Modifying /proxmox to /proxmox/backup
if [ $(cat pvesm_cifs_export_list_var02 | grep 'proxmox$' > /dev/null; echo $?) == 0 ]; then
  msg "Modifying $(cat pvesm_cifs_export_list_var02 | grep 'proxmox$') to $(cat pvesm_cifs_export_list_var02 | grep 'proxmox$')/backup..."
  sed -i 's/proxmox$/proxmox\/backup/g' pvesm_cifs_export_list_var02
fi
# Check for Transcode export and create if not found
if [ $(pvesm scan cifs ${NAS_IP} $(if [ ${SMB_CREDENTIALS} == 0 ]; then echo "--username ${SMB_USERNAME} --password ${SMB_PASSWORD}";fi) | awk '{print $1}' | grep 'transcode$' > /dev/null; echo $?) != 0 ] && [ $(pvesm scan cifs ${NAS_IP} $(if [ ${SMB_CREDENTIALS} == 0 ]; then echo "--username ${SMB_USERNAME} --password ${SMB_PASSWORD}";fi) | awk '{print $1}' | grep 'video$' > /dev/null; echo $?) = 0 ]; then
  msg "No transcode export exists. Using '$(echo "$(pvesm scan cifs ${NAS_IP} $(if [ ${SMB_CREDENTIALS} == 0 ]; then echo "--username ${SMB_USERNAME} --password ${SMB_PASSWORD}";fi) | awk '{print $1}' | grep 'video$')/transcode")' instead..."
  echo "$(pvesm scan cifs ${NAS_IP} $(if [ ${SMB_CREDENTIALS} == 0 ]; then echo "--username ${SMB_USERNAME} --password ${SMB_PASSWORD}";fi) | awk '{print $1}' | grep 'video$')/transcode" >> pvesm_cifs_export_list_var02
fi
echo

# Easy Script auto list build
filelist1='pvesm_cifs_export_list_var02'
filelist2=$(cat ${DIR}/source/pve_host_source_cifs_mounts | sed '/^#/d' | awk -F'|' '$2 == "0" { print $1 }' | awk '{ print tolower ($1) }' | sed '/^$/d')
unset match_LIST
declare -a match_LIST
while IFS= read -r line; do
  if [ "$(grep -s "\.*$line$" ${filelist1} > /dev/null; echo $?)" == 0 ]; then
    match_LIST+=( "$(grep -s "\.*$line$" ${filelist1})|$(echo ${NAS_HOSTNAME,,}-$line)" )
  fi
done <<< ${filelist2}

# Select and label of exports
if [ $(printf '%s\n' "${match_LIST[@]}" | wc -l) = $(printf '%s\n' ${filelist2} | wc -l) ]; then
  # Auto selection and labelling of exports
  msg_box "Our Easy Script has discovered and matched all the required PVE storage mounts. Duplicates of existing PVE storage mount points will not be created.\n\n$(printf '%s\n' "${match_LIST[@]}" | sed  '1i NAS SERVER SHARE|PVE STORAGE MOUNT NAME' | indent2 | column -t -s "|")\n\nThe User can accept our Easy Script automatic list entering 'y' at the next prompt. Or proceed manually and individually select any PVE mount point(s) you want to add (entering 'n' at the next prompt)."
  echo
  while true; do
    read -p "Accept our Easy Script automatic list ( Recommended for new builds ) [y/n]?: " -n 1 -r YN
    echo
    case $YN in
      [Yy]*)
        AUTO_CREATE_LIST=0
        printf '%s\n' "${match_LIST[@]}" > pvesm_input
        info "The User had chosen the Easy Script automatic list."
        echo
        break 
        ;;
      [Nn]*)
        AUTO_CREATE_LIST=1
        info "The User has chosen to skip this step."
        break
        ;;
      *)
        warn "Error! Entry must be 'y' or 'n'. Try again..."
        echo
        ;;
    esac
  done
else
  AUTO_CREATE_LIST=1
fi

# Manual selection and labelling of exports
if [ ${AUTO_CREATE_LIST} == 1 ]; then
  msg "A total of $(cat pvesm_cifs_export_list_var02 | wc -l)x SMB/CIFS server mount points are available on '${NAS_HOSTNAME}'. Next you will be prompted to enter a numerical value (i.e 1-$(cat ${DIR}/source/pve_host_source_cifs_mounts | wc -l)) to identify a 'media type' for for each available '${NAS_HOSTNAME} SMB/CIFS mount point'.

  To ignore and remove a SMB?CIFS mount point choose:
    1) ${YELLOW}None${NC} - Ignore this share.
  To exit and leave the selection task choose ( after the User has selected ALL their required/wanted PVE storage mounts):
    "$(cat ${DIR}/source/pve_host_source_cifs_mounts | wc -l)") ${YELLOW}Exit/Finished${NC} - Nothing more to add."
  echo
  mapfile -t options < <( cat ${DIR}/source/pve_host_source_cifs_mounts | awk -F'|' '{ print $1 }' )
  touch pvesm_input
  while IFS=, read -r line; do
    PS3="Select the media type for SMB/CIFS share ${WHITE}$line${NC} (entering numeric) : "
    select media_type in "${options[@]}"; do
    echo
    if [[ "$(echo $media_type | awk '{print $1}')" == *"Exit/Finished"* ]]; then
      info "You have chosen to finish and exit this task. No more mount points to add."
      while true; do
        read -p "Finished. Are you sure [y/n]?: " -n 1 -r YN
        echo
        case $YN in
          [Yy]*)
            info "The User has completed the task."
            echo
            break 2
            ;;
          [Nn]*)
            msg "Okay. Keep adding more storage mounts..."
            echo
            break
            ;;
          *)
            warn "Error! Entry must be 'y' or 'n'. Try again..."
            echo
            ;;
        esac
      done
    else
      info "SMB/CIFS share ${WHITE}$line${NC} is set as : $(echo $media_type | awk '{print $1}')"
    fi
    while true; do
      read -p "Confirm your selection is correct [y/n]?: " -n 1 -r YN
      echo
      case $YN in
        [Yy]*)
          echo "$(cat pvesm_cifs_export_list_var02 | grep $line)|$(echo ${NAS_HOSTNAME,,})-$(echo ${media_type,,} | awk '{print $1}' | sed "s/\x1B\[\([0-9]\{1,2\}\(;[0-9]\{1,2\}\)\?\)\?[mGK]//g")" >> pvesm_input
          echo
          break 2
          ;;
        [Nn]*)
          warn "No good. No problem. Try again."
          echo
          sleep 1
          break
          ;;
        *)
          warn "Error! Entry must be 'y' or 'n'. Try again..."
          echo
          ;;
      esac
    done
    done < /dev/tty
    if [[ "$(echo $media_type | awk '{print $1}')" == *"Exit/Finished"* ]]; then
      break
    fi
  done < pvesm_cifs_export_list_var02
  echo

  # Removing shares identified as "none"
  sed -i "/${NAS_HOSTNAME,,}-none/d" pvesm_input
fi

# Checking for existing PVE storage mounts
pvesm status | grep -E 'nfs|cifs' | awk '{print $1}' | tr '[:upper:]' '[:lower:]' > pvesm_existing_mount_var01 || true
cat ${DIR}/source/pve_host_source_cifs_mounts | sed '/^#/d' | awk -F'|' '$2 == "0" { print $1 }' | awk '{ print tolower ($1) }' | sed '/^$/d' | sed "s/^/${NAS_HOSTNAME}-/" > pvesm_existing_mount_var02 || true
# cat ${DIR}/source/pve_host_source_nfs_mounts | grep -Evi 'None|Exit/Finished' | awk -F' - ' '{print $1}' | tr '[:upper:]' '[:lower:]' | sed "s/^/${NAS_HOSTNAME}-/" > pvesm_existing_mount_var02 || true
grep -i -E -f pvesm_existing_mount_var01 pvesm_existing_mount_var02 > pvesm_existing_mount_var03 || true

IFS=' '
while read -r w; do
  if [ $(grep $w pvesm_input >/dev/null; echo $?) == 0 ]; then
    msg "Checking PVE host for duplicate storage mounts..."
    info "Removing duplicate storage mount: ${YELLOW}$w${NC}"
    sed -i "/$w/d" pvesm_input
    echo
  fi
done < pvesm_existing_mount_var03

# Create PVE Storage Mounts
if [ $(cat pvesm_input | wc -l) -ge 1 ]; then
  IFS='|'
  while read -r SHARE PVE_MNT_LABEL; do
    if [ "${PVE_MNT_LABEL}" == $(echo ${NAS_HOSTNAME,,}-backup) ]; then
      msg "Creating PVE storage mount..."
      pvesm add cifs ${PVE_MNT_LABEL} --server ${NAS_IP} --path /mnt/pve/${PVE_MNT_LABEL} --share $SHARE --content backup --maxfiles 3 --smbversion ${NAS_SMB_VER} $(if [ ${SMB_CREDENTIALS} == 0 ]; then echo "--username ${SMB_USERNAME} --password ${SMB_PASSWORD}";fi)
      info "PVE storage mount created: ${YELLOW}${PVE_MNT_LABEL}${NC}\n       (${NAS_IP}:$SHARE)"
      echo
    else
      msg "Creating PVE storage mount..."
      pvesm add cifs ${PVE_MNT_LABEL} --server ${NAS_IP} --path /mnt/pve/${PVE_MNT_LABEL} --share $SHARE --content images --smbversion ${NAS_SMB_VER} $(if [ ${SMB_CREDENTIALS} == 0 ]; then echo "--username ${SMB_USERNAME} --password ${SMB_PASSWORD}";fi)
      info "PVE storage mount created: ${YELLOW}${PVE_MNT_LABEL}${NC}\n       (${NAS_IP}:$SHARE)"
      echo    
    fi
  done < pvesm_input
else
  msg "There are no PVE storage mounts to create."
  echo
fi


#---- Finish Line ------------------------------------------------------------------