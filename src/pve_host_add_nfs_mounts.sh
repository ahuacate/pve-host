#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_add_nfs_mounts.sh
# Description:  Source script for creating PVE Host NFS Mounts
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------
#---- Source -----------------------------------------------------------------------
#---- Dependencies -----------------------------------------------------------------
#---- Static Variables -------------------------------------------------------------

# Easy Script Section Header Body Text
SECTION_HEAD='PVESM NFS Storage Mounts'

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
Proxmox can add storage by creating NFS and/or CIFS backend storage pools. Your NAS server NFS properties must be configured so your PVE NFS backend (client) can mount the NAS shares automatically. Your NAS server must support:

  NFS VERSION
    --  NFS v3/v4
  
    --  NAS NFS exports to all PVE nodes (i.e default PVE nodes are 192.168.1.101-192.168.1.109)

We need to set some variables. The next steps requires your input. You can accept our default values by pressing ENTER on your keyboard. Or overwrite our default value by typing in your own value and then pressing ENTER to accept and to continue to the next step."
echo
while true
do
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
if [[ ! $(dpkg -s nbtscan) ]]; then
  msg "Installing nbtscan..."
  apt-get install -y nbtscan >/dev/null
  info "nbtscan status: ${GREEN}installed${NC}"
  echo
fi


#---- Checking NFS Server exports
section "Select NFS server"

# Look for NFS server using hostname or IP address
while true
do
  read -p "Enter your NFS Server (NAS) IPv4/6 address OR hostname: " -e -i nas-01 NAS_ID
  msg "Checking for a working NFS server..."
  if [ "$(valid_ip "$NAS_ID" > /dev/null 2>&1; echo $?)" = 0 ]; then
    # Perform IP ping check
    if [ "$(ping -s 1 -c 2 "$(echo "$NAS_ID")" > /dev/null; echo $?)" = 0 ]; then
      NAS_IP="$NAS_ID"
      info "Ping '$NAS_ID' status: ${YELLOW}pass${NC}"
      info "NAS IP status: ${YELLOW}pass${NC} ( $NAS_IP )"
    else
      NAS_IP=""
      info "Ping '$NAS_ID' status: ${RED}fail${NC}"
      info "NAS IP status: ${RED}fail${NC}"
    fi

    # Perform hostname check
    if [[ $(nbtscan -q $NAS_ID | awk '{print $2}') ]]; then
      NAS_HOSTNAME="$(nbtscan -q $NAS_ID | awk '{print $2}')" 
      info "NAS hostname status: ${YELLOW}pass${NC} ( $NAS_HOSTNAME )"
    else
      NAS_HOSTNAME=""
      info "NAS hostname status: ${RED}fail${NC} ( cannot map hostname )"
    fi
  elif [[ "$NAS_ID" =~ ${hostname_regex} ]]; then
    # Perform hostname ping check
    if [ "$(ping -s 1 -c 2 "$(echo "$NAS_ID")" > /dev/null; echo $?)" = 0 ]; then
      NAS_HOSTNAME="$NAS_ID"
      info "Ping '$NAS_ID' status: ${YELLOW}pass${NC}"
      info "NAS hostname status: ${YELLOW}pass${NC} ( $NAS_HOSTNAME )"
    else
      NAS_HOSTNAME=""
      info "Ping '$NAS_ID' status: ${RED}fail${NC}"
      info "NAS hostname status: ${RED}fail${NC}"
    fi

    # Perform IP lookup using hostname
    if [[ $(nslookup "${NAS_ID}" | awk '/^Address: / { print $2 }') ]]; then
      NAS_IP="$(nslookup "$NAS_ID" | awk '/^Address: / { print $2 }')" 
      info "NAS IP lookup status: ${YELLOW}pass${NC} ( $NAS_IP )"
    else
      NAS_IP=""
      info "NAS IP lookup status: ${RED}fail${NC} ( cannot map IP address )"
    fi
  fi
  
  # NFS IP server status ('0' enabled, '1' disabled)
  if [[ $(pvesm nfsscan "$NAS_IP" 2> /dev/null) ]] && [ -n ${NAS_IP} ]; then
    NAS_IP_STATUS=0 # '0' enabled, '1' disabled
  else
    NAS_IP_STATUS=1 # '0' enabled, '1' disabled
  fi

  # NFS hostname server status ('0' enabled, '1' disabled)
  if [[ $(pvesm nfsscan ${NAS_HOSTNAME} 2> /dev/null) ]] && [ -n ${NAS_HOSTNAME} ]; then
    NAS_HOSTNAME_STATUS=0 # '0' enabled, '1' disabled
  else
    NAS_HOSTNAME_STATUS=1 # '0' enabled, '1' disabled
  fi

  # Check status
  if [ "$NAS_HOSTNAME_STATUS" -eq 0 ] || [ "$NAS_IP_STATUS" -eq 0 ]; then
    break
  fi
  echo
done


#---- Select NFS mount protocol (IP or hostname)
if [ "$NAS_HOSTNAME_STATUS" -eq 0 ] && [ "$NAS_IP_STATUS" -eq 0 ]; then
  # Select NFS protocol - NAS Hostname or Static IP
  print_DISPLAYIP=( "$(pvesm nfsscan "$NAS_IP" | awk '{print $1}' | uniq | sed "/.*\/backup$/d" | sed 's/proxmox$/proxmox\/backup/g')" )
  print_DISPLAYHOSTNAME=( "$(pvesm nfsscan "$NAS_HOSTNAME" | awk '{print $1}' | uniq | sed "/.*\/backup$/d" | sed 's/proxmox$/proxmox\/backup/g')" )
  msg_box "#### PLEASE READ CAREFULLY - NAS NFS SERVER EXPORTS BY PROTOCOL ####\n\nNAS NFS exports can be mounted using either the NAS IP address or NAS hostname protocol. NFS export shares may vary between the two protocols (but they can also be the same).\n\n$(paste <(printf "%s\n" "${print_DISPLAYIP[@]}") <(printf "%s\n" "${print_DISPLAYHOSTNAME[@]}") | column -t -N "NFS EXPORTS by HOSTNAME,NFS EXPORTS by IP" | indent2)\n\nSelect your preferred NAS NFS export protocol. Hostname protocol is recommended if the shares meet your requirements."
  echo

  OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE02" "TYPE00")
  OPTIONS_LABELS_INPUT=( "Hostname - NFS by hostname '$NAS_HOSTNAME' (Recommended)" "IP address - NFS by static IP '$NAS_IP'" "None. Return to the Toolbox" )
  makeselect_input2
  singleselect SELECTED "$OPTIONS_STRING"

  # Set the NFS protocol from menu
  if [ "$RESULTS" = 'TYPE01' ]; then
    # Set NFS by hostname
    NAS_ID="$NAS_HOSTNAME"
    info "NAS NFS export mount protocol set: ${YELLOW}$NAS_ID${NC} (by hostname)"
  elif [ "$RESULTS" = 'TYPE02' ]; then
    # Set NFS by IP
    NAS_ID="$NAS_IP"
    info "NAS NFS export mount protocol set: ${YELLOW}$NAS_ID${NC} (by IP)"
  elif [ "$RESULTS" = 'TYPE00' ]; then
    return
  fi
elif [ "$NAS_HOSTNAME_STATUS" = 0 ] && [ "$NAS_IP_STATUS" = 1 ]; then
  # Set NFS protocol - by hostname
  NAS_ID="$NAS_HOSTNAME"
  info "NAS NFS export mount protocol set: ${YELLOW}$NAS_ID${NC} (by hostname)"
elif [ "$NAS_HOSTNAME_STATUS" = 1 ] && [ "$NAS_IP_STATUS" = 0 ]; then
  # Set NFS protocol - by IP
  NAS_ID="$NAS_IP"
  info "NAS NFS export mount protocol set: ${YELLOW}$NAS_ID${NC} (by IP)"
else
  # Fail msg
  FAIL_MSG="The entry '${NAS_ID}' not valid. A valid NAS NFS server address is when the following constraints are satisfied:\n
    Required constraints
    --  NAS IP or hostname is reachable.
    --  NAS NFS server is reachable.
    --  NAS NFS server supports NFSv3 or higher.
    --  the NAS NFS server name entry (IP or hostname) doesn't contain any white space.
    Other constraints
    --  a IP address entry is incorrectly formatted. It must be in the IPv4 or IPv6 format.
    --  a hostname entry is correctly formatted.\n
    Try again..."
  warn "$FAIL_MSG"
  break
fi
echo


# Manually set NAS hostname
# This runs when no hostname is found using nbtscan failed to get the NAS hostname using the NAS IP.
if [ -z ${NAS_HOSTNAME} ]; then
  msg "For unknown reasons, we could not determine the hostname for the NAS server with IP '${NAS_IP}'. Please manually enter the NAS hostname at the prompt."
  while true
  do
    read -p "Enter your NAS NFS Server '${NAS_IP}' hostname: " -e -i $(nslookup $NAS_IP | awk 'sub(/.*name =/,""){print $1}' | sed 's/\..*//') NAS_HOSTNAME_VAR
    if [[ "$NAS_HOSTNAME_VAR" =~ ${hostname_regex} ]]; then
      NAS_HOSTNAME="$NAS_HOSTNAME_VAR"
      info "NAS hostname set: ${YELLOW}$NAS_HOSTNAME${NC}"
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


# Check NFS version
msg " Checking PVE NFS support"
# Check PVE host NFS supported version no.
# Match to highest NFS4 when possible for 'backup' mounts
nfs_ver_pve_LIST=( "4.2" "4.1" "4" "3" "default" )
nfs_ver_pve_max=$(rpcinfo -p | awk '{print $2}' | sort -rn | head -1)

# NAS NFS supported version no.
# nfs_ver_nas_max=$(nfsstat -m "$NAS_ID" | grep -oP 'vers=\K\d+\.\d+' | sort -k2 -nr | head -1)
nfs_ver_nas_max=$(rpcinfo -p "$NAS_ID" | grep nfs | awk '{print $2}' | sort -k2 -nr | head -1)


# Set $nfs_ver_max
# Set to highest nfs version match for client and server
if (( $(echo "$nfs_ver_pve_max <= $nfs_ver_nas_max" | bc -l) )); then
  nfs_ver_max=$(printf '%s\n' "${nfs_ver_pve_LIST[@]}" | grep -E "^$nfs_ver_pve_max\.[0-9]+$" | sort -rn | head -1)
  if [ -z "$nfs_ver_max" ]; then
    nfs_ver_max=$(printf '%s\n' "${nfs_ver_pve_LIST[@]}" | grep -E "^$nfs_ver_pve_max$" | sort -rn | head -1)
  fi
else
  nfs_ver_max=$(printf '%s\n' "${nfs_ver_pve_LIST[@]}" | grep -E "^$nfs_ver_nas_max\.[0-9]+$" | sort -rn | head -1)
  if [ -z "$nfs_ver_max" ]; then
    nfs_ver_max=$(printf '%s\n' "${nfs_ver_pve_LIST[@]}" | grep -E "^$nfs_ver_nas_max$" | sort -rn | head -1)
  fi
fi

# Check if NAS NFS version meets minimum requirement
if (( $(echo "$nfs_ver_nas_max >= 4" | bc -l) )); then
  info "NFS version check: ${YELLOW}pass${NC}"
elif (( $(echo "$nfs_ver_nas_max < 4 && $nfs_ver_nas_max >= 3" | bc -l) )); then
  info "NFS version check: ${YELLOW}pass${NC} (NFSv3 limit - potential connectivity issues)"
else
  warn "Your NFS Server '${NAS_ID}' is running NFSv2 or older. You must upgrade your NFS server to support NFSv4 or higher. User intervention required. Exiting installation script."
  sleep 1
  return
fi
echo

#---- Create NFS mount pairs
section "Create PVE Storage Mounts"

# Get NFS NAS Server export list
mapfile -t nfs_server_LIST <<< $(pvesm nfsscan $NAS_ID | awk '{print $1}' | uniq | sed "/.*\/backup$/d" | sed 's/proxmox$/proxmox\/backup/g' | sed 's/[[:blank:]]*$//' | sed '/^$/d') # Removing backup dir, editing /src/proxmox/'backup'
# Create required pvesm list
mapfile -t pvesm_req_LIST <<< $(cat $SHARED_DIR/src/pve_host_mount_list | sed '/^#/d' | awk -F':' '$3 == "0" { print $1 }' | awk '{ print tolower ($1) }' | sed '/^$/d' | sed 's/[[:blank:]]*$//' | sed '/^$/d')


# Match nfs exports vs required match list 
# Here we match our default list pf PVESM mounts "${pvesm_req_LIST[@]}" against your NFS Server exports "${nfs_server_LIST[@]}", removing any existing matching PVE NFS/CIF mounts to avoid conflicts.
# 1=src:2=pvesm name:3=media type:4=status (0 existing, 1 required,):5=format(nfs,cifs)
msg "Matching NFS Server '${NAS_ID}' exports with Ahuacate default shares (be patient, might take a while)..."
unset match_LIST
while IFS= read -r line
do
  if [ "$(printf '%s\n' "${nfs_server_LIST[@]}" | grep -s "\.*${line}$" > /dev/null; echo $?)" = 0 ]; then
    match_LIST+=( "$(printf '%s\n' "${nfs_server_LIST[@]}" | grep -s "\.*${line}$"):$(echo "${NAS_HOSTNAME,,}-${line}":${line}:$(if [[ $(pvesm status | grep -E 'nfs|cifs' | tr '[:upper:]' '[:lower:]' | grep "^${NAS_HOSTNAME,,}-${line}") ]]; then pvesm status | grep -E 'nfs|cifs' | tr '[:upper:]' '[:lower:]' | grep "^${NAS_HOSTNAME,,}-${line}" | awk '{ print "0:"$2 }'; else echo "1:"; fi))" )
  fi
done < <( printf '%s\n' "${pvesm_req_LIST[@]}" )

while IFS= read -r line
do
  if [ ! "$(printf '%s\n' "${match_LIST[@]}" | grep -s "^${line}" > /dev/null; echo $?)" = 0 ]; then
    match_LIST+=( "${line}::::" )
  fi
done < <( printf '%s\n' "${nfs_server_LIST[@]}" )

# Auto select and label exports
if [ "$(printf '%s\n' "${match_LIST[@]}" | awk -F':' '{OFS=FS} { if (($4 == 0 || $4 == 1)) print $0 }' | wc -l)" = ${#pvesm_req_LIST[@]} ]; then
  # Auto selection and labelling of exports
  msg_box "#### AUTOMATIC PVE STORAGE MOUNT MATCHING ####\n\nWe have discovered and matched all the required PVE storage mounts. Any conflicting or existing mount points are excluded. Only mounts labeled 'required' will be created. This should work 'out-of-the-box'.\n\n$(printf '%s\n' "${match_LIST[@]}" | awk -F':' '{OFS=FS} { if ($4 == 0) print $1,"<<",$2,$5} { if ($4 == 1) print $1,"<<",$2,"required"}' | column -s ":" -t -N "SOURCE INPUT, ,PVESM LABEL,MOUNT STATUS" | indent2)\n\nAccept the auto match list by typing 'y' at the next prompt. Or manually select and match each PVE mount point(s) you want by entering 'n' at the next prompt."
  echo
  while true
  do
    read -p "Accept the auto matched pairing ( Recommended for our custom NAS builds ) [y/n]?: " -n 1 -r YN
    echo
    case $YN in
      [Yy]*)
        ES_LIST=0
        input_LIST=( $(printf '%s\n' "${match_LIST[@]}" | awk -F':' '{OFS=FS} { if ($4 == 1) print $1, $3}') )
        info "The User has accepted the matched pairing."
        echo
        break 
        ;;
      [Nn]*)
        ES_LIST=1
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
if [ "$ES_LIST" -eq 1 ]; then
  # Create required manual lists
  unset options_values_input_LIST
  unset options_labels_input_LIST
  while IFS=: read -r type desc; do
    if [ "$(printf '%s\n' "${match_LIST[@]}" | awk -F':' -v pvesm_id="${NAS_HOSTNAME,,}-${type}" '{OFS=FS} { if ($2=pvesm_id && $4 == 0) print $3 }' | sed '/^$/d' | grep "${type,,}" > /dev/null; echo $?)" != 0 ]; then
      options_values_input_LIST+=( "${type,,}" )
      options_labels_input_LIST+=( "${type} - ${desc}" )
    fi
  done < <( cat $SHARED_DIR/src/pve_host_mount_list | sed '/^#/d' | awk -F':' '{OFS=FS} $3 == "0" { print $1,$2 }' | sed 's/[[:blank:]]*$//' | sed '/^$/d' )

  # Prepare required input arrays for func matchselect
  mapfile -t OPTIONS_VALUES_INPUT <<< $(printf '%s\n' "${options_values_input_LIST[@]}")
  mapfile -t OPTIONS_LABELS_INPUT <<< $(printf '%s\n' "${options_labels_input_LIST[@]}")
  SRC_VALUES_INPUT=( $(printf '%s\n' "${match_LIST[@]}" | awk -F':' '{OFS=FS} { if (($4 == "" || $4 == 1)) print $1 }') )

  while true
  do
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


#---- Create PVE Storage Mounts
if [ ${#input_LIST[@]} -ge 1 ]; then
  while IFS=':' read -r SHARE TYPE
  do
    PVESM_LABEL="${NAS_HOSTNAME,,}-${TYPE}"
    if [ "${PVESM_LABEL}" == "$(echo ${NAS_HOSTNAME,,}-backup)" ]; then
      # Round down $nfs_ver_max
      nfs_ver_max_int=$(printf "%.0f" "$nfs_ver_max")
      msg "Creating PVE storage mount..."
      pvesm add nfs $PVESM_LABEL --path /mnt/pve/$PVESM_LABEL --server $NAS_ID --export $SHARE --content backup,images --maxfiles 3 --preallocation metadata --options vers=$nfs_ver_max_int
      info "PVE storage mount created: ${YELLOW}$PVESM_LABEL${NC}\n       (${NAS_ID}:${SHARE})"
      echo
    else
      msg "Creating PVE storage mount..."
      pvesm add nfs $PVESM_LABEL --path /mnt/pve/$PVESM_LABEL --server $NAS_ID --export $SHARE --content images
      info "PVE storage mount created: ${YELLOW}$PVESM_LABEL${NC}\n       (${NAS_ID}:${SHARE})"
      echo    
    fi
  done < <( printf '%s\n' "${input_LIST[@]}" )
else
  msg "It seems you already have all the required NFS PVE storage mounts. No additional PVE storage mounts will ne created."
  echo
fi

#---- Finish Line ------------------------------------------------------------------

section "Completion Status."
msg "Success. Task complete."
echo
#-----------------------------------------------------------------------------------