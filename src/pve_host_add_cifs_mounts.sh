#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_add_cifs_mounts.sh
# Description:  Source script for creating PVE Host CIFS Mounts
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------
#---- Source -----------------------------------------------------------------------
#---- Dependencies -----------------------------------------------------------------

# nbtscan
if [ ! $(dpkg -s nbtscan >/dev/null 2>&1; echo $?) == 0 ]; then
  apt-get install nbtscan -yqq
fi

#---- Static Variables -------------------------------------------------------------

# Easy Script Section Header Body Text
SECTION_HEAD='PVESM CIFS Storage Mounts'

# Check for PVE Hostname mod
if [ -z "${HOSTNAME_FIX+x}" ]; then
  PVE_HOSTNAME=$HOSTNAME
fi

#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------

#---- Introduction
section "Introduction"

msg_box "#### PLEASE READ CAREFULLY - NAS CIFS SERVER EXPORTS ####\n
Your NAS server SMB/CIFS properties must be configured so your PVE CIFS backend (client) can mount the SMB/CIFS shares automatically. Your SMB/CIFS server should support SMB3 protocol (PVE default). SMB1 is NOT supported. Your NAS server should support:

  SMB VERSION
    --  SMB v2.02 minimum ( PVE default is v3.00 and above )
  
    --  NAS SMB shares to all PVE nodes (i.e default PVE nodes are 'nas-01' to 'nas-05' or '192.168.1.101' to '192.168.1.105')

The User is required to input a valid NAS user SMB credentials (username and password). The login user must have suitable permissions (i.e privatelab:rwx) to acccess, read, write and execute to the SMB server shares you wish to mount. If you have more than one SMB/CIFS Server and/or SMB login username account then run this script again for each SMB/CIFS Server IP and SMB login username.

The next steps requires user input. You can accept our default values by pressing ENTER on your keyboard. Or overwrite our default value by typing in your own value and then pressing ENTER to accept and to continue to the next step."
echo
while true; do
  read -p "Create PVE CIFS storage mounts [y/n]?: " -n 1 -r YN
  echo
  case $YN in
    [Yy]*)
      info "The User has chosen to proceed."
      echo
      break
      ;;
    [Nn]*)
      info "The User has chosen to skip this step."
      return
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
section "Select CIFS server"

while true; do
  read -p "Enter your NAS Server IPv4/6 address OR hostname: " -e -i nas-01 NAS_ID
  msg "Checking for a working CIFS NAS server..."
  if [ $(valid_ip ${NAS_ID} > /dev/null 2>&1; echo $?) == '0' ]; then
    # Perform ping check
    if [ $(ping -s 1 -c 2 "$(echo "${NAS_ID}")" > /dev/null; echo $?) = 0 ]; then
      NAS_IP=${NAS_ID}
      info "Ping '${NAS_ID}' status: ${YELLOW}pass${NC}"
      info "NAS IP status: ${YELLOW}pass${NC} ( ${NAS_IP} )"
    else
      NAS_IP=""
      info "Ping '${NAS_ID}' status: ${RED}fail${NC}"
      info "NAS IP status: ${RED}fail${NC}"
    fi
    # Perform hostname check
    if [[ $(nbtscan -q ${NAS_ID} | awk '{print $2}') ]]; then
      NAS_HOSTNAME=$(nbtscan -q ${NAS_ID} | awk '{print $2}') 
      info "NAS hostname status: ${YELLOW}pass${NC} ( ${NAS_HOSTNAME} )"
    else
      NAS_HOSTNAME=""
      info "NAS hostname status: ${RED}fail${NC} ( cannot map hostname )"
    fi
  elif [[ ${NAS_ID} =~ ${hostname_regex} ]]; then
    # Perform ping check
    if [ $(ping -s 1 -c 2 "$(echo "${NAS_ID}")" > /dev/null; echo $?) = 0 ]; then
      NAS_HOSTNAME=${NAS_ID}
      info "Ping '${NAS_ID}' status: ${YELLOW}pass${NC}"
      info "NAS hostname status: ${YELLOW}pass${NC} ( ${NAS_HOSTNAME} )"
    else
      NAS_HOSTNAME=""
      info "Ping '${NAS_ID}' status: ${RED}fail${NC}"
      info "NAS hostname status: ${RED}fail${NC}"
    fi
    # Perform IP check
    if [[ $(nslookup "${NAS_ID}" | awk '/^Address: / { print $2 }') ]]; then
      NAS_IP=$(nslookup "${NAS_ID}" | awk '/^Address: / { print $2 }') 
      info "NAS IP status: ${YELLOW}pass${NC} ( ${NAS_IP} )"
    else
      NAS_IP=""
      info "NAS IP status: ${RED}fail${NC} ( cannot map IP address )"
    fi
  fi

  # CIFS IP server status
  if [[ $(nc -z ${NAS_IP} 139 && echo up) ]] && [ -n ${NAS_IP} ]; then
    # '0' enabled, '1' disabled
    CIFS_EXPORT_IP='0'
  else
    CIFS_EXPORT_IP='1'
  fi
  # CIFS DHCP server status
  if [[ $(nc -z ${NAS_HOSTNAME} 139 && echo up) ]] && [ -n ${NAS_HOSTNAME} ]; then
    # '0' enabled, '1' disabled
    CIFS_EXPORT_DHCP='0'
  else
    CIFS_EXPORT_DHCP='1'
  fi
  # Check
  if [ ${CIFS_EXPORT_DHCP} == '0' ] || [ ${CIFS_EXPORT_IP} == '0' ]; then
    break
  else
    warn "There are problems with your input:
      1. The IP address meets the IPv4 standard, BUT
      2. The IP address $(echo "${NAS_IP}") is not reachable by ping.
      Try again..."
  fi
  echo
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
  OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE02" "TYPE03" "TYPE04" "TYPE05" "TYPE00")
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
  elif [ $(echo "${RESULTS[@]}") == TYPE00 ]; then
    msg "Fix, upgrade or find your NAS SMB protocol dialect and try again. Exiting this script..."
    echo
    return
  fi
fi

# Set NAS Hostname or Static IP
if [ ${CIFS_EXPORT_DHCP} == '0' ] && [ ${CIFS_EXPORT_IP} == '0' ]; then
  msg_box "#### PLEASE READ CAREFULLY - NAS CIFS SERVER EXPORTS BY PROTOCOL ####\n\nNAS CIFS exports can be mounted using either the NAS IP address or NAS hostname protocol.\n\nSelect your preferred NAS CIFS export protocol. Hostname protocol is recommended."
  echo
  OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE02" "TYPE00")
  OPTIONS_LABELS_INPUT=( "Hostname - CIFS by hostname '${NAS_HOSTNAME}' (Recommended)" "IP address - CIFS by static IP '${NAS_IP}'" "None. Return to the Toolbox" )
  makeselect_input2
  singleselect SELECTED "$OPTIONS_STRING"
  # Set the NFS protocol
  if [ ${RESULTS} == 'TYPE01' ]; then
    # Set NFS by hostname
    NAS_ID=${NAS_HOSTNAME}
    info "NAS CIFS export mount protocol set: ${YELLOW}${NAS_ID}${NC} (by hostname)"
  elif [ ${RESULTS} == 'TYPE02' ]; then
    # Set NFS by IP
    NAS_ID=${NAS_IP}
    info "NAS CIFS export mount protocol set: ${YELLOW}${NAS_ID}${NC} (by IP)"
  elif [ ${RESULTS} == 'TYPE00' ]; then
    return
  fi
elif [ ${CIFS_EXPORT_DHCP} == '0' ] && [ ${CIFS_EXPORT_IP} == '1' ]; then
  # Set NFS by hostname
  NAS_ID=${NAS_HOSTNAME}
  info "NAS CIFS export mount protocol set: ${YELLOW}${NAS_ID}${NC} (by hostname)"
elif [ ${CIFS_EXPORT_DHCP} == '1' ] && [ ${CIFS_EXPORT_IP} == '0' ]; then
  # Set NFS by hostname
  NAS_ID=${NAS_IP}
  info "NAS CIFS export mount protocol set: ${YELLOW}${NAS_ID}${NC} (by IP)"
fi
echo

# SMB/CIFS Server Credentials
msg_box "#### PLEASE READ CAREFULLY - SMB/CIFS SERVER CREDENTIALS ####\n
Your NAS SMB/CIFS Server shares are likely to be password protected. To create PVE SMB/CIFS backend storage pools we require your NAS SMB login credentials. The login user must have suitable permissions (i.e privatelab:rwx) to access, read, write and execute to the SMB server shares you wish to mount.

If you have more than one SMB/CIFS Server and/or SMB login user account then run this script again for each SMB/CIFS Server IP or SMB username.

If your SMB/CIFS Server is password protected then you will need to input your NAS SMB login username and password in the next steps."
echo
while true; do
  read -p "Do you require SMB login credentials for '${NAS_HOSTNAME^^}' [y/n]?: " -n 1 -r YN
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
        # Test SMB connection
        if [ "${SMB_PASSWORD}" != "${SMB_PASSWORD2}" ]; then
          warn "Passwords do not match. Please try again."
          echo
        elif [ $(pvesm scan cifs ${NAS_ID} --username ${SMB_USERNAME} --password ${SMB_PASSWORD} &> /dev/null; echo $?) != '0' ]; then
          # Fail msg
          FAIL_MSG="The user name credentials are not valid.\nTry again..."
          warn "$FAIL_MSG"
          echo
        elif [ $(pvesm scan cifs ${NAS_ID} --username ${SMB_USERNAME} --password ${SMB_PASSWORD} &> /dev/null; echo $?) == '0' ]; then
          info "SMB server login credentials are set: ${YELLOW}${SMB_USERNAME}${NC} ( username )"
          echo
          break 2
        fi
      done
      ;;
    [Nn]*)
      SMB_CREDENTIALS=1
      SMB_USERNAME=""
      SMB_PASSWORD=""
      if [ $(pvesm scan cifs ${NAS_ID} --username ${SMB_USERNAME} --password ${SMB_PASSWORD} &> /dev/null; echo $?) != '0' ]; then
        # Fail msg
        FAIL_MSG="User name credentials appear to be required for the NAS SMB/CIFS Server.\nTry again..."
        warn "$FAIL_MSG"
        echo
      else
        info "SMB server login credentials are set: ${YELLOW}Not Required${NC}"
        echo
        break 2
      fi
      ;;
    *)
      warn "Error! Entry must be 'y' or 'n'. Try again..."
      echo
      ;;
  esac
done


# Manually set NAS hostname (required because nbtscan failed to get the NAS hostname using the NAS IP )
if [ -z ${NAS_HOSTNAME} ]; then
  msg "For unknown reasons we could not determine the hostname the NAS server '${NAS_IP}'. The user must manually enter the NAS hostname at the prompt."
  while true; do
    read -p "Enter your NAS CIFS Server '${NAS_IP}' hostname: " -e -i $(nslookup ${NAS_IP} | awk 'sub(/.*name =/,""){print $1}' | sed 's/\..*//') NAS_HOSTNAME_VAR
    if [[ ${NAS_HOSTNAME_VAR} =~ ${hostname_regex} ]]; then
      NAS_HOSTNAME=${NAS_HOSTNAME_VAR}
      info "NAS hostname set: ${YELLOW}${NAS_HOSTNAME}${NC}"
      echo
      break
    else
      # Fail msg
      FAIL_MSG="The hostname is not valid. A valid hostname is when all of the following constraints are satisfied:\n
        --  it contains only lowercase characters.
        --  it may include numerics, hyphens (-) and periods (.) but not start or end with them.
        --  it doesn't contain any other special characters [!#$&%*+_].
        --  it doesn't contain any white space.\n
        Try again..."
      warn "${FAIL_MSG}"
      echo
    fi
  done
fi


#---- Create PVE Storage Mounts
section "Create PVE Storage Mounts"

# Create CIFS Server export list
mapfile -t cifs_server_LIST <<< $(pvesm scan cifs ${NAS_ID} --username ${SMB_USERNAME} --password ${SMB_PASSWORD} | awk '{ print $1 }' | sort | uniq | sed "/.*\/backup$/d" | sed '/^backup/d' | sed 's/proxmox$/proxmox\/backup/g' | sed 's/[[:blank:]]*$//' | sed '/^$/d') # Removing backup dir, editing /src/proxmox/'backup'
# Create required pvesm list
mapfile -t pvesm_req_LIST <<< $(cat ${SHARED_DIR}/src/pve_host_mount_list | sed '/^#/d' | awk -F':' '$3 == "0" { print $1 }' | awk '{ print tolower ($1) }' | sed '/^$/d' | sed 's/[[:blank:]]*$//' | sed '/^$/d')


# Create cifs exports vs required match list
# 1=src:2=pvesm name:3=media type:4=status (0 existing, 1 required,):5=format(nfs,cifs)
msg "Creating a list of CIFS Server '${NAS_ID}' exports and performing match (be patient, might take a while)..."
unset match_LIST
while IFS= read -r line; do
  if [ "$(printf '%s\n' "${cifs_server_LIST[@]}" | grep -s "\.*${line}$" > /dev/null; echo $?)" == '0' ]; then
    match_LIST+=( "$(printf '%s\n' "${cifs_server_LIST[@]}" | grep -s "\.*${line}$"):$(echo "${NAS_HOSTNAME,,}-${line}":${line}:$(if [[ $(pvesm status | grep -E 'nfs|cifs' | tr '[:upper:]' '[:lower:]' | grep "^${NAS_HOSTNAME,,}-${line}") ]]; then pvesm status | grep -E 'nfs|cifs' | tr '[:upper:]' '[:lower:]' | grep "^${NAS_HOSTNAME,,}-${line}" | awk '{ print "0:"$2 }'; else echo "1:"; fi))" )
  fi
done < <( printf '%s\n' "${pvesm_req_LIST[@]}" )
while IFS= read -r line; do
  if [ "$(printf '%s\n' "${match_LIST[@]}" | grep -s "^${line}" > /dev/null; echo $?)" != '0' ]; then
    match_LIST+=( "${line}::::" )
  fi
done < <( printf '%s\n' "${cifs_server_LIST[@]}" )

# Auto select and label of exports
if [ $(printf '%s\n' "${match_LIST[@]}" | awk -F':' '{OFS=FS} { if (($4 == 0 || $4 == 1)) print $0 }' | wc -l) == ${#pvesm_req_LIST[@]} ]; then
  # Auto selection and labelling of exports
  msg_box "#### AUTOMATIC PVE STORAGE MOUNT MATCHING ####\n\nWe have discovered and matched all the required PVE storage mounts. Any conflicting or existing mount points are excluded. Only mounts labeled 'required' will be created. This should work 'out-of-the-box'.\n\n$(printf '%s\n' "${match_LIST[@]}" | awk -F':' '{OFS=FS} { if ($4 == 0) print $1,"<<",$2,$5} { if ($4 == 1) print $1,"<<",$2,"required"}' | column -s ":" -t -N "SOURCE INPUT, ,PVESM LABEL,MOUNT STATUS" | indent2)\n\nAccept the auto match list by typing 'y' at the next prompt. Or manually select and match each PVE mount point(s) you want by entering 'n' at the next prompt."
  echo
  while true; do
    read -p "Accept the auto matched pairing ( Recommended for our custom NAS builds ) [y/n]?: " -n 1 -r YN
    echo
    case $YN in
      [Yy]*)
        ES_LIST='0'
        input_LIST=( $(printf '%s\n' "${match_LIST[@]}" | awk -F':' '{OFS=FS} { if ($4 == 1) print $1, $3}') )
        info "The User has accepted the matched pairing."
        echo
        break 
        ;;
      [Nn]*)
        ES_LIST='1'
        info "The User has chosen to skip this option."
        break
        ;;
      *)
        warn "Error! Entry must be 'y' or 'n'. Try again..."
        echo
        ;;
    esac
  done
else
  ES_LIST='1'
fi

# Manual selection and labelling of exports
if [ ${ES_LIST} == '1' ]; then
  # Create required manual lists
  unset options_values_input_LIST
  unset options_labels_input_LIST
  while IFS=: read -r type desc; do
    if [ "$(printf '%s\n' "${match_LIST[@]}" | awk -F':' -v pvesm_id="${NAS_HOSTNAME,,}-${type}" '{OFS=FS} { if ($2=pvesm_id && $4 == 0) print $3 }' | sed '/^$/d' | grep "${type,,}" > /dev/null; echo $?)" != 0 ]; then
      options_values_input_LIST+=( "${type,,}" )
      options_labels_input_LIST+=( "${type} - ${desc}" )
    fi
  done < <( cat ${SHARED_DIR}/src/pve_host_mount_list | sed '/^#/d' | awk -F':' '{OFS=FS} $3 == "0" { print $1,$2 }' | sed 's/[[:blank:]]*$//' | sed '/^$/d' )

  # Prepare required input arrays for func matchselect
  mapfile -t OPTIONS_VALUES_INPUT <<< $(printf '%s\n' "${options_values_input_LIST[@]}")
  mapfile -t OPTIONS_LABELS_INPUT <<< $(printf '%s\n' "${options_labels_input_LIST[@]}")
  SRC_VALUES_INPUT=( $(printf '%s\n' "${match_LIST[@]}" | awk -F':' '{OFS=FS} { if (($4 == "" || $4 == 1)) print $1 }') )

  while true; do
    msg_box "#### MANUAL PVE STORAGE MOUNT MATCHING ####\n\nWe have discovered ${#SRC_VALUES_INPUT[@]}x NAS exports available for PVE storage mounts. All conflicting or existing mount points are excluded.\n\nExisting PVE '${NAS_HOSTNAME^^}' storage mounts are:\n\n$(printf '%s\n' "${match_LIST[@]}" | awk -F':' '{OFS=FS} { if ($4 == 0) print $1,"<<",$2,$5}' | column -s ":" -t -N "SOURCE INPUT, ,PVESM NAME,MOUNT STATUS" | indent2)\n\nManual matching is required for the following:\n\n$(printf '%s\n' "${match_LIST[@]}" | awk -F':' '{OFS=FS} { if ($4 == 1 ) print $1,"<<",$3} { if ($4 == "") print $1,"","-"}' | column -s ":" -t -N "SOURCE INPUT, ,SUGGESTED MATCH TYPE" | indent2)\n\nTo ignore a NAS share export select:\n\n  --  Ignore this match\n\nTo finish the task select (after matching all the required NAS exports):\n\n  --  Exit/Finished - Nothing more to match"
    echo

    # Run func matchselect
    matchselect SELECTED

    # Print results
    printf '%s\n' "${PRINT_RESULTS[@]}" | awk -F':' '{OFS=FS} { print $1,">>",$2}' | column -s ":" -t -N "SOURCE INPUT, ,SELECTED PAIR DESCRIPTION" | indent2
    echo

    # Confirm selection
    read -p "Accept the matched pairing [y/n]?: " -n 1 -r YN
    echo
    case $YN in
      [Yy]*)
        info "The User has accepted the matched pairing."
        echo
        # Create match list
        input_LIST=( $(printf '%s\n' "${RESULTS[@]}") )
        break 
        ;;
      [Nn]*)
        msg "No problem. Try again..."
        echo
        ;;
      *)
        warn "Error! Entry must be 'y' or 'n'. Try again..."
        echo
        ;;
    esac
  done
fi


# Create PVE Storage Mounts
if [ ${#input_LIST[@]} -ge 1 ]; then
  while IFS=':' read -r SHARE TYPE; do
    PVESM_LABEL="${NAS_HOSTNAME,,}-${TYPE}"
    if [ "${PVESM_LABEL}" == "$(echo ${NAS_HOSTNAME,,}-backup)" ]; then
      msg "Creating PVE storage mount..."
      pvesm add cifs ${PVESM_LABEL} --server ${NAS_ID} --path /mnt/pve/${PVESM_LABEL} --share $SHARE --content backup --maxfiles 3 --smbversion ${NAS_SMB_VER} $(if [ ${SMB_CREDENTIALS} == 0 ]; then echo "--username ${SMB_USERNAME} --password ${SMB_PASSWORD}";fi)
      info "PVE storage mount created: ${YELLOW}${PVESM_LABEL}${NC}\n       (${NAS_ID}:${SHARE})"
      echo
    else
      msg "Creating PVE storage mount..."
      pvesm add cifs ${PVESM_LABEL} --server ${NAS_ID} --path /mnt/pve/${PVESM_LABEL} --share $SHARE --content images --smbversion ${NAS_SMB_VER} $(if [ ${SMB_CREDENTIALS} == 0 ]; then echo "--username ${SMB_USERNAME} --password ${SMB_PASSWORD}";fi)
      info "PVE storage mount created: ${YELLOW}${PVESM_LABEL}${NC}\n       (${NAS_ID}:${SHARE})"
      echo    
    fi
  done < <( printf '%s\n' "${input_LIST[@]}" )
else
  msg "No PVE storage mounts to create."
  echo
fi
#---- Finish Line ------------------------------------------------------------------

section "Completion Status."
msg "Success. Task complete."
echo