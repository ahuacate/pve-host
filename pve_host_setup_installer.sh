#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_setup_installer.sh
# Description:  Installer script for Proxmox host setup and configuration
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------

#---- Source Github
# bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-setup/master/pve_host_setup_installer.sh)"

#---- Source local Git
# /mnt/pve/nas-01-git/ahuacate/pve-host-setup/pve_host_setup_installer.sh

#---- Source -----------------------------------------------------------------------
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

#---- Other Variables --------------------------------------------------------------

# Easy Script Section Header Body Text
SECTION_HEAD='PVE Host Manager'

#---- Other Files ------------------------------------------------------------------

#---- Package loader
if [ -f /mnt/pve/nas-*[0-9]-git/${GIT_USER}/developer_settings.git ] && [ -f /mnt/pve/nas-*[0-9]-git/${GIT_USER}/common/bash/source/pve_repo_loader.sh ]; then
  # Developer Options loader
  source /mnt/pve/nas-*[0-9]-git/${GIT_USER}/common/bash/source/pve_repo_loader.sh
else
  # Download Github loader
  bash -c "$(wget -qLO - https://raw.githubusercontent.com/${GIT_USER}/common/master/bash/source/pve_repo_loader.sh)"
fi

#---- Package loader
if [ -f /mnt/pve/nas-*[0-9]-git/${GIT_USER}/developer_settings.git ] && [ -f /mnt/pve/nas-*[0-9]-git/${GIT_USER}/common/bash/source/pve_repo_loader.sh ]; then
  # Developer Options loader
  source /mnt/pve/nas-*[0-9]-git/${GIT_USER}/common/bash/source/pve_repo_loader.sh
else
  # Download Github loader
  wget -qL - https://raw.githubusercontent.com/${GIT_USER}/common/master/bash/source/pve_repo_loader.sh -O ${REPO_TEMP}/pve_repo_loader.sh
  chmod +x ${REPO_TEMP}/pve_repo_loader.sh
  source ${REPO_TEMP}/pve_repo_loader.sh
fi


#---- Body -------------------------------------------------------------------------

#---- Run Bash Header
source /tmp/common/pve/source/pvesource_bash_defaults.sh

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
OPTIONS_LABELS_INPUT=( "Primary - Primary PVE host" "Secondary - Secondary PVE host (cluster node)" )
makeselect_input2
singleselect SELECTED "$OPTIONS_STRING"
if [ ${RESULTS} == TYPE01 ]; then
  PVE_TYPE=1
  export PVE_TYPE=1
elif [ ${RESULTS} == TYPE02 ]; then
  PVE_TYPE=2
  export PVE_TYPE=2
fi

#---- Run Installer
while true; do
  section "Run a PVE Host Add-On task"
  msg_box "The User must select a task to perform. Before selecting options 1 - 3, make sure your NAS is available with all the required network shares. Option 1 includes all of the Add-on modules."
  echo
  OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE02" "TYPE03" "TYPE04" "TYPE05" "TYPE06" "TYPE07" "TYPE08" )
  OPTIONS_LABELS_INPUT=( "New PVE Host Builder - fully configure a new Proxmox host" "NFS Storage - add NFS PVE storage mounts" "SMB/CIFS Storage - add SMB/CIFS storage mounts" "Install Fail2Ban $(if [ $(dpkg -s fail2ban >/dev/null 2>&1; echo $?) = 0 ]; then echo "( installed & active )"; else echo "( not installed )"; fi)" "Install SSMTP Email Server $(if [ $(dpkg -s ssmtp >/dev/null 2>&1; echo $?) = 0 ] && [ $(grep -qs "^root:*" /etc/ssmtp/revaliases >/dev/null; echo $?) = 0 ]; then echo "( installed & active )"; else echo "( not installed )"; fi)" "Install a SSH Key -  add or create your own private SSH access key" "PVE CT updater - program for scheduling CT updates" "None. Exit this installer" )
  makeselect_input2
  singleselect SELECTED "$OPTIONS_STRING"

  if [ ${RESULTS} == TYPE01 ]; then
    #---- Configure PVE host
    /tmp/pve-host-setup/scripts/pve_host_setup_fullbuild.sh
    section "Completion Status."
    msg "Success. Task complete. The User will now return to the PVE Host Manager menu. Then select the last menu item 'None. Exit this installer' to end the installer program.\n"
  elif [ ${RESULTS} == TYPE02 ]; then
    #---- Create PVE Storage mounts (NFS)
    if [ ${PVE_TYPE} == 1 ]; then
      /tmp/pve-host-setup/scripts/pve_host_add_nfs_mounts.sh
      section "Completion Status."
      msg "Success. Task complete. The User will now return to the PVE Host Manager menu. Then select the last menu item 'None. Exit this installer' to end the installer program.\n"
    else
      warn "Only Primary PVE Hosts can create PVE Storage Mounts.\nRun another task or select: 'None. Exit this installer'. Try again..."
      echo
    fi
  elif [ ${RESULTS} == TYPE03 ]; then
    #---- Create PVE Storage mounts (CIFS)
    if [ ${PVE_TYPE} == 1 ]; then
      /tmp/pve-host-setup/scripts/pve_host_add_cifs_mounts.sh
      section "Completion Status."
      msg "Success. Task complete. The User will now return to the PVE Host Manager menu. Then select the last menu item 'None. Exit this installer' to end the installer program.\n"
    else
      warn "Only Primary PVE Hosts can create PVE Storage Mounts.\nRun another task or select: 'None. Exit this installer'. Try again..."
      echo
    fi
  elif [ ${RESULTS} == TYPE04 ]; then
    #---- Install and Configure Fail2ban
    /tmp/pve-host-setup/scripts/pve_host_setup_fail2ban.sh
    section "Completion Status."
    msg "Success. Task complete. The User will now return to the PVE Host Manager menu. Then select the last menu item 'None. Exit this installer' to end the installer program.\n"
  elif [ ${RESULTS} == TYPE05 ]; then
    #---- Configure Email Alerts
    /tmp/pve-host-setup/scripts/pve_host_setup_postfix.sh
    section "Completion Status."
    msg "Success. Task complete. The User will now return to the PVE Host Manager menu. Then select the last menu item 'None. Exit this installer' to end the installer program.\n"
  elif [ ${RESULTS} == TYPE06 ]; then
    #---- Configure SSH key
    /tmp/pve-host-setup/scripts/pve_host_setup_sshkey.sh
    section "Completion Status."
    msg "Success. Task complete. The User will now return to the PVE Host Manager menu. Then select the last menu item 'None. Exit this installer' to end the installer program.\n"
  elif [ ${RESULTS} == TYPE07 ]; then
    #---- PVE CT Updater
    msg "Coming soon...\n\n\n"
  elif [ ${RESULTS} == TYPE08 ]; then
    # Exit installation
    msg "You have chosen not to proceed. Aborting. Bye..."
    echo
    sleep 1
    break
  fi
done


#---- Finish Line ------------------------------------------------------------------

section "Completion Status."

msg "Success. Task complete."
echo

# Cleanup
rm -R /tmp/common &> /dev/null
rm -R /tmp/pve-host-setup &> /dev/null
rm /tmp/common.tar.gz &> /dev/null
rm /tmp/pve-host-setup.tar.gz &> /dev/null

trap cleanup EXIT