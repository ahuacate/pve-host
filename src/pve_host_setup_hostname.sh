#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_setup_hostname.sh
# Description:  Set (PVE) Host machine hostname
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------
#---- Source -----------------------------------------------------------------------
#---- Dependencies -----------------------------------------------------------------

# Check Hostname availability status
function valid_pvehostname() {
  local  name=$1
  local  stat=1
  if [ ${PVE_TYPE} = 1 ]; then
    pve_hostname_regex='^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9]+\-01)$'
  elif [ ${PVE_TYPE} = 2 ]; then
    pve_hostname_regex='^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9]+\-[2-9]{2})$'
  fi
  # Run function
  if [[ $name =~ ${hostname_regex} ]] && [[ ! $(grep -h -Po 'hostname: \K[^/]*' /etc/pve/lxc/* 2> /dev/null) =~ $name ]] && [[ ! $(grep -h -Po 'name: \K[^/]*' /etc/pve/qemu-server/* 2> /dev/null) =~ $name ]] && [[ ! $name == $(echo $(hostname) | awk '{ print tolower($0) }') ]] && [ ! $(ping -s 1 -c 2 ${name} > /dev/null; echo $?) == '0' ]; then
    stat=$?
  fi
  return $stat
}

#---- Static Variables -------------------------------------------------------------

# Easy Script Section Header Body Text
SECTION_HEAD='PVE Host Hostname'

#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------

#---- Prerequisites

# Validate conditions
if [[ $(pct list) ]] || [[ $(qm list) ]] || [[ $(pvecm nodes 2>/dev/null | grep $HOSTNAME) ]]; then
  msg_box "#### PLEASE READ CAREFULLY - VALIDATE PREREQUISITES ####\n\n$(if [[ $(pct list) ]] || [[ $(qm list) ]]; then echo -e "PVE host '$HOSTNAME' is reporting to be hosting $(qm list | awk 'NR>1 { print $1 }' | wc -l)x virtual machines (VMs) and $(pct list | awk 'NR>1 { print $1 }' | wc -l)x LXC containers (CTs).\n\nIf you want to proceed to configure or make system changes to this PVE host '$HOSTNAME' you must first take the following steps:\n\n      FOR SINGLE OR PRIMARY NODES - REMOVE ALL CONTAINERS\n      --  Stop all VMs and CTs.\n      --  Create a backup archive of all VMs and CTs.\n      --  REMOVE all VMs and CTs.\n\nBackup VM archives can be restored through the Proxmox VE web GUI.\n\n"; fi)$(if [[ $(pvecm nodes 2>/dev/null | grep $HOSTNAME) ]]; then echo -e "PVE host '$HOSTNAME' is also reporting as a member of a PVE cluster. To proceed you must first remove this node ( '$HOSTNAME' ) from the PVE cluster.\n\n      REMOVE NODE FROM CLUSTER\n      --  Migrate all VMs and CTs to another active node.\n      --  Remove '$HOSTNAME' from the PVE cluster.\n\n"; fi)Complete the above tasks and try running this script again. PVE hostname remains unchanged."
  echo
  # Set for other scripts 
  PVE_HOSTNAME=$HOSTNAME
  SET_PVE_HOST_HOSTNAME=1
  sleep 3
  return
fi


#---- Introduction
section "Introduction"

msg_box "#### PLEASE READ CAREFULLY - PVE HOST CHECKER ####\n
This script changes your $(if [ ${PVE_TYPE} == '1' ]; then echo "primary"; else echo "secondary"; fi) PVE host '$HOSTNAME'. Tasks to be performed include:

      PREREQUISITES BASICS
  --  Update Proxmox.
  --  Set a new hostname.
  $(if [ ${PVE_TYPE} == '1' ]; then echo "--  Primary PVE hosts must be denoted with -01 (i.e must be hostname-01)"; else echo "--  Secondary PVE hosts must be denoted within the range 02 to 09 (i.e hostname-02)."; fi)

Changing a PVE hostname requires editing many linux system files. The required edits could change with newer Proxmox releases and our edits may no longer work. The user can always reinstall Proxmox and input a valid hostname during the installation."
echo
while true; do
  read -p "Do you want to change the current '$HOSTNAME' [y/n]?: " -n 1 -r YN
  echo
  case $YN in
    [Yy]*)
      SET_PVE_HOST_HOSTNAME=0
      info "The User has chosen to proceed."
      echo
      break
      ;;
    [Nn]*)
      PVE_HOSTNAME=$HOSTNAME
      SET_PVE_HOST_HOSTNAME=1
      info "You have chosen to skip this step.\nPVE hostname is set: ${YELLOW}${PVE_HOSTNAME}${NC} (Unchanged)."
      echo
      return
      ;;
    *)
      warn "Error! Entry must be 'y' or 'n'. Try again..."
      echo
      ;;
  esac
done

#---- Set PVE Search domain
section "Modify PVE host 'hostname'"

# Set PVE host 'hostname'
# Hostname suggestion only
if [ ${PVE_TYPE} = 1 ] && [[ $HOSTNAME =~ ^[A-Za-z]+\-"01"$ ]];then
  PVE_HOSTNAME_VAR01=$HOSTNAME
elif [ ${PVE_TYPE} = 1 ] && ! [[ $HOSTNAME =~ ^[A-Za-z]+\-"01"$ ]];then
  PVE_HOSTNAME_VAR01=pve-01
elif [ ${PVE_TYPE} = 2 ] && [[ $HOSTNAME =~ ^[A-Za-z]+\-0[2-9]{1}$ ]];then
  PVE_HOSTNAME_VAR01=$HOSTNAME
elif [ ${PVE_TYPE} = 2 ] && ! [[ $HOSTNAME =~ ^[A-Za-z]+\-0[2-9]{1}$ ]];then
  PVE_HOSTNAME_VAR01=pve-02
fi
while true; do
  read -p "Enter a new PVE host 'hostname': " -e -i ${PVE_HOSTNAME_VAR01} PVE_HOSTNAME
  PVE_HOSTNAME=${PVE_HOSTNAME,,}
  FAIL_MSG="The $(if [ ${PVE_TYPE} == '1' ]; then echo "primary"; else echo "secondary"; fi) hostname is not valid. A valid $(if [ ${PVE_TYPE} == '1' ]; then echo "primary"; else echo "secondary"; fi) hostname is when all of the following constraints are satisfied:\n
  --  it does not exist on the network.
  --  it is not in use by any CT or VM.
  --  it contains only lowercase characters.
  --  it may include numerics, hyphens (-) and periods (.) but not start or end with them.
  --  it doesn't contain any other special characters [!#$&%*+_].
  --  it doesn't contain any white space.
  --  it conforms to our PVE host naming convention:
        $(if [ ${PVE_TYPE} == '1' ]; then echo "--  Primary PVE hosts must be denoted with -01 (i.e must be hostname-01)"; else echo "--  Secondary PVE hosts must be denoted within the range -02/03/04-09 (i.e hostname-02)."; fi)\n
  Try again..."
  PASS_MSG="PVE Hostname is set: ${YELLOW}${PVE_HOSTNAME}${NC}"
  result=$(valid_pvehostname ${PVE_HOSTNAME} > /dev/null 2>&1)
  if [ $? == 0 ]; then
    HOSTNAME_FIX=0
		info "$PASS_MSG"
    echo
    break
  elif [ $? != 0 ]; then
		warn "$FAIL_MSG"
    echo
	fi
done

#---- Finish Line ------------------------------------------------------------------