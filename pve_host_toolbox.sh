#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_toolbox.sh
# Description:  Installer toolbox for Proxmox host setup and configuration
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------

#---- Source Github
# bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-setup/master/pve_host_toolbox.sh)"

#---- Source local Git
# /mnt/pve/nas-01-git/ahuacate/pve-host-setup/pve_host_toolbox.sh

#---- Source -----------------------------------------------------------------------

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
# DIR="${REPO_TEMP}/${GIT_REPO}"
COMMON_DIR="${DIR}/../common"
COMMON_PVE_SRC_DIR="${DIR}/common/pve/src"
SHARED_DIR="${DIR}/shared"

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

# Installer cleanup
function installer_cleanup () {
rm -R ${REPO_TEMP}/${GIT_REPO} &> /dev/null
rm ${REPO_TEMP}/${GIT_REPO}.tar.gz &> /dev/null
}

#---- Static Variables -------------------------------------------------------------

# Git server
GIT_SERVER='https://github.com'
# Git user
GIT_USER='ahuacate'
# Git repository
GIT_REPO='pve-host-setup'
# Git branch
GIT_BRANCH='master'
# Git common
GIT_COMMON='0'
# Installer App script
GIT_APP_SCRIPT='pve_host_setup.sh'

# Set Package Installer Temp Folder
REPO_TEMP='/tmp'
cd ${REPO_TEMP}

#---- Local Repo path (check if local)
# For local SRC a 'developer_settings.git' file must exist in repo dir (value: dev_git_mount=0)
REPO_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P | sed "s/${GIT_USER}.*/${GIT_USER}/" )"

#---- Other Variables --------------------------------------------------------------

# Easy Script Section Header Body Text
SECTION_HEAD='PVE Host Toolbox'

#---- Other Files ------------------------------------------------------------------

#---- Package loader
if [ -f ${REPO_PATH}/common/bash/src/pve_repo_loader.sh ] && [[ $(sed -n 's/^dev_git_mount=//p' ${REPO_PATH}/developer_settings.git 2> /dev/null) == '0' ]]; then
  # Download Local loader (developer)
  source ${REPO_PATH}/common/bash/src/pve_repo_loader.sh
else
  # Download Github loader
  wget -qL - https://raw.githubusercontent.com/${GIT_USER}/common/master/bash/src/pve_repo_loader.sh -O ${REPO_TEMP}/pve_repo_loader.sh
  chmod +x ${REPO_TEMP}/pve_repo_loader.sh
  source ${REPO_TEMP}/pve_repo_loader.sh
fi

#---- Body -------------------------------------------------------------------------

#---- Run Bash Header
source ${COMMON_PVE_SRC_DIR}/pvesource_bash_defaults.sh

# Check PVE SMTP status
check_smtp_status

#---- Identify PVE Host Type
section "Set PVE host type"
msg_box "#### PLEASE READ CAREFULLY - PVE BUILD TYPE ####\n
We need to determine the type of PVE host being built or updated. There are two types of PVE hosts machines:

  PRIMARY TYPE
    --  Primary PVE host is the first Proxmox machine

    --  Primary PVE hostnames are denoted by '-01'

    --  Default hostname is pve-01

    --  Default primary host IPv4 address is 192.168.1.101
  
  SECONDARY TYPE
    --  Secondary PVE hosts are cluster machines

    --  Proxmox requires a minimum of 3x PVE hosts to form a cluster

    --  Secondary PVE hostnames are denoted by '-02' onwards

    --  Default hostname naming convention begins from pve-02 (i.e 03,0x)

    --  Default secondary host IPv4 addresses begin from 192.168.1.102 and upwards."

# Set PVE Build Type
OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE02" )
OPTIONS_LABELS_INPUT=( "Primary - Primary PVE host" \
"Secondary - Secondary PVE host (cluster node)" )
makeselect_input2
singleselect SELECTED "$OPTIONS_STRING"
if [ ${RESULTS} == 'TYPE01' ]; then
  PVE_TYPE='1'
  export PVE_TYPE=1
elif [ ${RESULTS} == 'TYPE02' ]; then
  PVE_TYPE='2'
  export PVE_TYPE=2
fi

#---- Run Installer
while true; do
  section "Run a PVE Host Add-On task"

  msg_box "The User must select a task to perform. 'PVE Host Basic' is mandatory or required for all hosts. 'PVE Full Build' includes the full suite of Toolbox add-on options.\n\nSelect a Toolbox task or 'None. Exit this installer' to leave."
  echo
  warn_msg="Only primary PVE hosts can run this add-on task.\nRun another task or select 'None. Exit this installer'. Try again..."
  OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE02" "TYPE03" "TYPE04" "TYPE05" "TYPE06" "TYPE07" "TYPE00" )
  OPTIONS_LABELS_INPUT=( "PVE Basic - required by all hosts (mandatory)" \
  "PVESM NFS Storage - add NFS PVE storage mounts" \
  "PVESM SMB/CIFS Storage - add SMB/CIFS storage mounts" \
  "PVE Hostname Updater - change a hosts hostname" \
  "Fail2Ban Installer $(if [ $(dpkg -s fail2ban >/dev/null 2>&1; echo $?) = 0 ]; then echo "( installed & active )"; else echo "(not installed)"; fi)" \
  "SMTP Email Setup $(if [ "${SMTP_STATUS}" == 1 ]; then echo "( installed & active )"; else echo "(not installed)"; fi)" \
  "PVE CT updater - mass update all CT OS" \
  "None. Exit this installer" )
  makeselect_input2
  singleselect SELECTED "$OPTIONS_STRING"

  if [ ${RESULTS} == 'TYPE01' ]; then
    #---- Configure PVE host - basic
    source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_setup_basic.sh

  elif [ ${RESULTS} == 'TYPE02' ]; then
    #---- Create PVE Storage mounts (NFS)
    if [ ${PVE_TYPE} == '1' ]; then
      source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_add_nfs_mounts.sh
    else
      warn "${warn_msg}"
      echo
    fi
  elif [ ${RESULTS} == 'TYPE03' ]; then
    #---- Create PVE Storage mounts (CIFS)
    if [ ${PVE_TYPE} == '1' ]; then
      source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_add_cifs_mounts.sh
    else
      warn "${warn_msg}"
      echo
    fi
  elif [ ${RESULTS} == 'TYPE04' ]; then
    #---- PVE Hostname edit
    source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_setup_hostname.sh
    source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_setup_hostnameupdate.sh
  elif [ ${RESULTS} == 'TYPE05' ]; then
    #---- Install and Configure Fail2ban
    source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_setup_fail2ban.sh
  elif [ ${RESULTS} == 'TYPE06' ]; then
    #---- Configure Email Alerts
    source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_setup_postfix_server.sh
  elif [ ${RESULTS} == 'TYPE07' ]; then
    #---- PVE CT Updater
    if [ ${PVE_TYPE} == '1' ]; then
      source ${REPO_TEMP}/${GIT_REPO}/src/pvetool_ct_updater.sh
    else
      warn "${warn_msg}"
      echo
    fi
  elif [ ${RESULTS} == 'TYPE00' ]; then
    # Exit installation
    msg "You have chosen not to proceed. Aborting. Bye..."
    echo
    sleep 1
    break
  fi
  # Reset Section Head
  SECTION_HEAD='PVE Host Toolbox'
done


#---- Finish Line ------------------------------------------------------------------

section "Completion Status"

msg "Success. Task complete."
echo

# Cleanup
# # Clean up CT tmp files
# pct exec $CTID -- bash -c "rm -R /tmp/${GIT_REPO} &> /dev/null; rm /tmp/${GIT_REPO}.tar.gz &> /dev/null"
# Clean up pve host
installer_cleanup
trap cleanup EXIT