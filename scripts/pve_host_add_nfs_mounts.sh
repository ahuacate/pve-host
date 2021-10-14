#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_add_nfs_mounts.sh
# Description:  Source script for creating PVE Host NFS Mounts
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------

# bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-setup/master/scripts/pve_host_add_nfs_mounts.sh)"

#---- Source -----------------------------------------------------------------------

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
PVE_SOURCE="${DIR}/../../common/pve/source"
BASH_SOURCE="${DIR}/../../common/bash/source"

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
SECTION_HEAD='PVE Host NFS Storage Mount'

# Check for PVE Hostname mod
if [ -z "${HOSTNAME_FIX+x}" ]; then
  PVE_HOSTNAME=$HOSTNAME
fi

#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------

#---- Introduction
section "Introduction"

msg_box "#### PLEASE READ CAREFULLY - NAS NFS SERVER EXPORTS ####\n
Proxmox can add storage by creating NFS and/or CIFS backend storage pools. Your NAS server NFS properties must be configured so your PVE NFS backend (client) can mount the NAS shares automatically. Your NAS server should support:

  NFS VERSION
    --  NFS v3/v4
  
    --  NAS NFS exports to all PVE nodes (i.e default PVE nodes are 192.168.1.101-192.168.1.109)

We need to set some variables. The next steps requires your input. You can accept our default values by pressing ENTER on your keyboard. Or overwrite our default value by typing in your own value and then pressing ENTER to accept and to continue to the next step."
echo
while true; do
  read -p "Create PVE NFS storage mounts [y/n]?: " -n 1 -r YN
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
section "Check Prerequisites"

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


#---- Checking NFS Server exports
section "Select NFS server"

while true; do
  # Enter NAS IP
  while true; do
    read -p "Enter your NFS NAS Server IPv4 address: " -e -i 192.168.1.10 NAS_IP
    if [ $(expr "${NAS_IP}" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) == 0 ] && [ $(ping -s 1 -c 2 "$(echo "${NAS_IP}")" > /dev/null; echo $?) = 0 ]; then
      info "NFS Server IPv4 address is set: ${YELLOW}${NAS_IP}${NC}."
      echo
      break
    elif [ $(expr "${NAS_IP}" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) != 0 ]; then
      warn "There are problems with your input:\n1.  Your IP address is incorrectly formatted. It must be in the IPv4 format\n    (i.e xxx.xxx.xxx.xxx ).\nTry again..."
      echo
    elif [ $(expr "${NAS_IP}" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' >/dev/null; echo $?) == 0 ] && [ $(ping -s 1 -c 2 "$(echo "${NAS_IP}")" > /dev/null; echo $?) != 0 ]; then
      warn "There are problems with your input:\n1. The IP address meets the IPv4 standard, BUT\n2. The IP address $(echo "${NAS_IP}") is not reachable by ping.\nTry again..."
      echo
    fi
  done

  # Check NFS version
  msg "Checking NFS version..."
  NFS_VER=$(rpcinfo -p ${NAS_IP} | grep nfs | awk '{ print $2 }' | sort -k2 -nr | head -1)
  if [ ${NFS_VER} -ge 4 ]; then
    info "NFS version check: ${GREEN}PASS${NC}"
  elif [ ${NFS_VER} -lt 4 ] && [ ${NFS_VER} -ge 3 ]; then
    info "NFS version check: ${GREEN}PASS${NC} (NFSv3 limited)"
  elif [ ${NFS_VER} -lt 3 ]; then
    NFS_VER=1
    warn "Your NFS Server ${NAS_IP} is running NFSv2 or older. You must upgrade your NFS server to NFSv3 or higher. User intervention required. Exiting installation script in 3 seconds."
    sleep 1
    exit 0
  fi
  echo

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



#---- Create PVE Storage Mounts
section "Create PVE Storage Mounts"

# Scanning NFS Server for exports
msg "Creating a list of NFS Server ${NAS_IP} exports..."
pvesm nfsscan ${NAS_IP} | awk '{print $1}' | sort > pvesm_nfs_export_list_var01
# Removing /backup export
sed "/.*\/backup/d" pvesm_nfs_export_list_var01 > pvesm_nfs_export_list_var02
# Modifying /proxmox to /proxmox/backup
if [ $(cat pvesm_nfs_export_list_var02 | grep '/proxmox$' > /dev/null; echo $?) == 0 ]; then
  msg "Modifying $(cat pvesm_nfs_export_list_var02 | grep '/proxmox$') to $(cat pvesm_nfs_export_list_var02 | grep '/proxmox$')/backup..."
  sed -i 's/proxmox$/proxmox\/backup/g' pvesm_nfs_export_list_var02
fi
# Check for Transcode export and create if not found
if [ $(pvesm nfsscan ${NAS_IP} | awk '{print $1}' | grep '/transcode$' > /dev/null; echo $?) != 0 ] && [ $(pvesm nfsscan ${NAS_IP} | awk '{print $1}' | grep '/video$' > /dev/null; echo $?) = 0 ]; then
  msg "Creating new folder $(echo "$(pvesm nfsscan ${NAS_IP} | awk '{print $1}' | grep '/video$')/transcode")..."
  mkdir -p $(echo "$(pvesm nfsscan ${NAS_IP} | awk '{print $1}' | grep '/video$')/transcode") > /dev/null
  echo "$(pvesm nfsscan ${NAS_IP} | awk '{print $1}' | grep '/video$')/transcode" >> pvesm_nfs_export_list_var02
fi
echo

# Easy Script auto list build
filelist1='pvesm_nfs_export_list_var02'
filelist2=$(cat ${DIR}/source/pve_host_source_nfs_mounts | sed '/^#/d' | awk -F'|' '$2 == "0" { print $1 }' | awk '{ print tolower ($1) }' | sed '/^$/d')
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
  msg "A total of $(cat pvesm_nfs_export_list_var02 | wc -l)x NFS server mount points are available on '${NAS_HOSTNAME}'. Next you will be prompted to enter a numerical value (i.e 1-$(cat ${DIR}/source/pve_host_source_nfs_mounts | wc -l)) to identify a 'media type' for for each available '${NAS_HOSTNAME} NFS mount point'.

  To ignore and remove a NFS mount point choose:
    1) ${YELLOW}None${NC} - Ignore this share.
  To exit and leave the selection task choose ( after the User has selected ALL their required/wanted PVE storage mounts):
    "$(cat ${DIR}/source/pve_host_source_nfs_mounts | wc -l)") ${YELLOW}Exit/Finished${NC} - Nothing more to add."
  echo
  mapfile -t options < <( cat ${DIR}/source/pve_host_source_nfs_mounts | awk -F'|' '{ print $1 }' )
  touch pvesm_input
  while IFS=, read -r line; do
    PS3="Select the media type for NFS share ${WHITE}$line${NC} (entering numeric) : "
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
      info "NFS share ${WHITE}$line${NC} is set as : $(echo $media_type | awk '{print $1}')"
    fi
    while true; do
      read -p "Confirm your selection is correct [y/n]?: " -n 1 -r YN
      echo
      case $YN in
        [Yy]*)
          echo "$(cat pvesm_nfs_export_list_var02 | grep $line)|$(echo ${NAS_HOSTNAME,,})-$(echo ${media_type,,} | awk '{print $1}' | sed "s/\x1B\[\([0-9]\{1,2\}\(;[0-9]\{1,2\}\)\?\)\?[mGK]//g")" >> pvesm_input
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
  done < pvesm_nfs_export_list_var02
  echo

  # Removing shares identified as "none"
  sed -i "/${NAS_HOSTNAME,,}-none/d" pvesm_input
fi

# Checking for existing PVE storage mounts
pvesm status | grep -E 'nfs|cifs' | awk '{print $1}' | tr '[:upper:]' '[:lower:]' > pvesm_existing_mount_var01 || true
cat ${DIR}/source/pve_host_source_nfs_mounts | sed '/^#/d' | awk -F'|' '$2 == "0" { print $1 }' | awk '{ print tolower ($1) }' | sed '/^$/d' | sed "s/^/${NAS_HOSTNAME}-/" > pvesm_existing_mount_var02 || true
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
  while read -r NFS_EXPORT PVE_MNT_LABEL; do
    if [ "${PVE_MNT_LABEL}" == "$(echo ${NAS_HOSTNAME,,}-backup)" ]; then
      msg "Creating PVE storage mount..."
      pvesm add nfs ${PVE_MNT_LABEL} --path /mnt/pve/${PVE_MNT_LABEL} --server ${NAS_IP} --export ${NFS_EXPORT} --content backup --maxfiles 3 --options vers=${NFS_VER}
      info "PVE storage mount created: ${YELLOW}${PVE_MNT_LABEL}${NC}\n       (${NAS_IP}:${NFS_EXPORT})"
      echo
    else
      msg "Creating PVE storage mount..."
      pvesm add nfs ${PVE_MNT_LABEL} --path /mnt/pve/${PVE_MNT_LABEL} --server ${NAS_IP} --export ${NFS_EXPORT} --content images --options vers=${NFS_VER}
      info "PVE storage mount created: ${YELLOW}${PVE_MNT_LABEL}${NC}\n       (${NAS_IP}:${NFS_EXPORT})"
      echo    
    fi
  done < pvesm_input
else
  msg "There are no PVE storage mounts to create."
  echo
fi

#---- Finish Line ------------------------------------------------------------------