#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pvetool_ct_updater.sh
# Description:  Simple bash script to APT updating Linux LXC/CT CTIDs.
#               Stopped CTs will be started, updated and returned to stopped status.
#               Running CTs will be updated.
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------

#bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/common/master/pve/tool/pvetool_ct_updater.sh)"

#---- Source -----------------------------------------------------------------------
#---- Dependencies -----------------------------------------------------------------
#---- Static Variables -------------------------------------------------------------

# Easy Script Section Header Body Text
SECTION_HEAD='PVE CT Updater'

# List of CTIDs
## 1=CTID:2=STATUS (running or stopped):3=NAME (CT name):4=SIZE (CT size used in megabytes)
unset ctid_LIST
while IFS=':' read CTID STATUS NAME; do
  ctid_LIST+=( "$CTID:$STATUS:$NAME:$(pct df $CTID | awk '/^rootfs/ { s=substr($4,1,length($4)-1); u=substr($4,length($4)); if(u=="G") $4=sprintf("%.0f",(s*1024)); else if(u=="M") $4=sprintf("%.0f",s); print $4 }')" )
done < <( pct list | awk 'NR > 1 { OFS = ":"; print $1, $2, $3 }' )

# CURRENT_OS='ubuntu'
# if [[ ${CURRENT_OS} == 'ubuntu' ]]; then
# echo hello
# fi

# Update function
function update_container() {
  local CTID="$1"
  msg "Updating CT '$CTID'..."
  # to chain commands within one exec we will need to wrap them in bash
  if [[ ${CURRENT_OS} == 'ubuntu' ]]; then
    # Ubuntu OS
    pct exec $CTID -- bash -c "apt-get update -y"
    pct exec $CTID -- bash -c "apt-get upgrade -y"
    pct exec $CTID -- bash -c "apt-get autoremove -y"
    info "Ubuntu CT'$CTID' update status: ${GREEN}success${NC}"
  elif [[ ${CURRENT_OS} == 'fedora linux' ]]; then
    # Fedora OS
    pct exec $CTID -- bash -c "dnf -y upgrade --refresh"
    info "Fedora CT '$CTID' update status: ${GREEN}success${NC}"
  elif [[ ${CURRENT_OS} == 'centos stream' ]]; then
    # Centos OS
    pct exec $CTID -- bash -c "yum -y update"
  elif [[ ${CURRENT_OS} == 'alpine linux' ]]; then
    # Alpine OS
    pct exec $CTID -- ash -c "apk update"
    pct exec $CTID -- ash -c "apk upgrade --available"
    pct exec $CTID -- ash -c "sync"
    info "Alpine CT '$CTID' update status: ${GREEN}success${NC}\n       ( requires a reboot )"
  elif [[ ${CURRENT_OS} =~ (gentoo|unknown) ]]; then
    # Unknown & Gentoo OS
    msg "User must manually update the CT. Skipping CTID '$CTID'..."
  fi
}

# CT start function
function pct_start_waitloop() {
  local CTID="$1"
  if [ "$(pct status $CTID)" == "status: stopped" ]; then
    msg "Starting CT '$CTID'..."
    pct start $CTID
    msg "Waiting to hear from CT '$CTID'..."
    while ! [[ "$(pct status $CTID)" == "status: running" ]]; do
      echo -n .
    done
    sleep 2
    msg "CT '$CTID' status: running"
  fi
}

# Check OS Version
function findCurrentOSType() {
  local CTID="$1"
  # Determine OS type and shell (ash or bash)
  if [[ $(pct exec $CTID 2> /dev/null -- bash -c "echo hello") ]]; then
    SHELL='bash'
    osType=$(pct exec $CTID -- ${SHELL} -c "uname")
  elif [[ $(pct exec $CTID 2> /dev/null -- ash -c "echo hello") ]]; then
    SHELL='ash'
    osType=$(pct exec $CTID -- ${SHELL} -c "uname")
  fi
  case "$osType" in
    "Darwin")
    {
      CURRENT_OS='osx'
    } ;;    
    "Linux")
    {
      # If available, use LSB to identify distribution
      if [ "$(pct exec $CTID -- ${SHELL} -c "[ -f /etc/lsb-release -o -f /etc/os-release -o -d /etc/lsb-release.d ] && echo '0' || echo '1'")" == '0' ]; then
        DISTRO=$(pct exec $CTID -- ${SHELL} -c "awk -F'=' '/^NAME/{print \$2}' /etc/os-release")
      else
        DISTRO=$(pct exec $CTID -- ${SHELL} -c "ls -d /etc/[A-Za-z]*[_-][rv]e[lr]* | grep -v "lsb" | cut -d'/' -f3 | cut -d'-' -f1 | cut -d'_' -f1")
      fi
      CURRENT_OS=$(echo ${DISTRO,,} | tr -d '"')
    } ;;
    *) 
    {
      CURRENT_OS='unknown'
    } ;;
  esac
}


#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------

#---- Set Backup destination
section "Set backup destination"

# Create PVESM backup storage destination list
pvesmbackup_LIST=( $(pvesm status --content backup | awk 'NR > 1 { $6=sprintf("%.0f",$6/1024); OFS = ":"; print $1, $2, $3, $6 }') )

# Set PVESM backup destination
msg "Set VZDUMP backup storage destination..."
if [ $(printf '%s\n' "${pvesmbackup_LIST[@]}" | awk -F':' -v BACKUP_SIZE=$(printf '%s\n' "${ctid_LIST[@]}" | awk -F':' '{sum+=$4;} END{print sum;}') 'BEGIN{OFS=FS} {if ($3 == "active" && $4 > BACKUP_SIZE) print $0 }' | wc -l) == '1' ]; then
  # Set backup storage if only 1x option
  BACKUP_DEST=$(printf '%s\n' "${pvesmbackup_LIST[@]}" | awk -F':' -v BACKUP_SIZE=$(printf '%s\n' "${ctid_LIST[@]}" | awk -F':' '{sum+=$4;} END{print sum;}') 'BEGIN{OFS=FS} {if ($3 == "active" && $4 > BACKUP_SIZE) print $1 }')
  info "Backup storage destination: ${YELLOW}${BACKUP_DEST}${NC}\n       ( only one option available )"
  echo
elif [ $(printf '%s\n' "${pvesmbackup_LIST[@]}" | awk -F':' -v BACKUP_SIZE=$(printf '%s\n' "${ctid_LIST[@]}" | awk -F':' '{sum+=$4;} END{print sum;}') 'BEGIN{OFS=FS} {if ($3 == "active" && $4 > BACKUP_SIZE) print $0 }' | wc -l) == '0' ]; then
  # Fail msg if 1x option has no free space
  FAIL_MSG="The Toolbox CT Updater failed. Before performing any CT upgrade a full backup of every CT is made (by default). The PVE host backup storage size is less than the required minimum of $(printf '%s\n' "${ctid_LIST[@]}" | awk -F':' '{sum+=$4;} END{print sum;}')M. Try again when the following constraints are satisfied:\n
    Required constraints
    --  More than $(printf '%s\n' "${ctid_LIST[@]}" | awk -F':' '{sum+=$4;} END{print sum;}')M of backup storage space is available.\n
    Try again..."
  warn "$FAIL_MSG"
  echo
  return
elif [ $(printf '%s\n' "${pvesmbackup_LIST[@]}" | awk -F':' -v BACKUP_SIZE=$(printf '%s\n' "${ctid_LIST[@]}" | awk -F':' '{sum+=$4;} END{print sum;}') 'BEGIN{OFS=FS} {if ($3 == "active" && $4 > BACKUP_SIZE) print $0 }' | wc -l) -gt '1' ]; then
  # Select a CT backup storage destination (multiple option)
  msg_box "#### PLEASE READ CAREFULLY - SET CT BACKUP DESTINATION ####\n\nBefore performing any CT upgrade a full CT backup is made (by default).\n\nThe User must select a backup location from the following ${#pvesmbackup_LIST[@]}x available PVESM storage destinations."
  echo
  mapfile -t OPTIONS_VALUES_INPUT <<< $(printf '%s\n' "${pvesmbackup_LIST[@]}" | awk -F':' -v BACKUP_SIZE=$(printf '%s\n' "${ctid_LIST[@]}" | awk -F':' '{sum+=$4;} END{print sum;}') 'BEGIN{OFS=FS} \
  {if ($3 == "active" && ($2 == "nfs" || $2 == "cifs") && $4 > BACKUP_SIZE) print $1 } \
  {if ($3 == "active" && $2 == "dir" && $4 > BACKUP_SIZE) print $1 }')
  mapfile -t OPTIONS_LABELS_INPUT <<< $(printf '%s\n' "${pvesmbackup_LIST[@]}" | awk -F':' -v BACKUP_SIZE=$(printf '%s\n' "${ctid_LIST[@]}" | awk -F':' '{sum+=$4;} END{print sum;}') 'BEGIN{OFS=FS} \
  {if ($3 == "active" && ($2 == "nfs" || $2 == "cifs") && $4 > BACKUP_SIZE) print "Backup network storage - "$1" ( Recommended )" } \
  {if ($3 == "active" && $2 == "dir" && $4 > BACKUP_SIZE) print "Backup storage folder - "$1 }')

  makeselect_input2 "$OPTIONS_VALUES_INPUT" "$OPTIONS_LABELS_INPUT"
  singleselect SELECTED "$OPTIONS_STRING"

  # Set backup storage
  BACKUP_DEST="${RESULTS[@]}"
fi


#---- Perform updates
section "Performing CT Updates"

while IFS=':' read CTID STATUS NAME SIZE; do
  msg "Commencing to update PVE CT: ${YELLOW}$CTID${NC} (be patient, can take some time)"
  if [ ${STATUS} == 'stopped' ]; then
    # CT start
    pct_start_waitloop $CTID
    # Find CT OS
    findCurrentOSType $CTID
    # Perform backup
    msg "Performing CT '$CTID' backup..."
    vzdump ${CTID} --storage ${BACKUP_DEST} --compress zstd --quiet 1 --mode snapshot
    # CT update
    update_container $CTID
    # Return CT to former state
    msg "Returning to former state..."
    pct shutdown $CTID
  elif [ ${STATUS} == 'running' ]; then
    # Find CT OS
    findCurrentOSType $CTID
    # Perform backup
    msg "Performing CT '$CTID' backup..."
    vzdump ${CTID} --storage ${BACKUP_DEST} --compress zstd --quiet 1 --mode snapshot
    # CT update
    update_container $CTID
  fi
  echo
done < <( printf '%s\n' "${ctid_LIST[@]}" )

#---- Finish Line ------------------------------------------------------------------

section "Completion Status."

msg "Success. Task complete."
echo