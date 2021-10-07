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

# Set Package Installer Temp Folder
cd /tmp


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

#---- Body -------------------------------------------------------------------------

#---- Run Bash Header
source /tmp/common/pve/source/pvesource_bash_defaults.sh

#---- Run Installer
section "Run a PVE Host Add-On task"
msg_box "The User must select a task to perform. Before selecting options 1 - 3, make sure your NAS is available with all the required network shares. Option 1 includes all of the Add-on modules."
echo
OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE02" "TYPE03" "TYPE04" "TYPE05" "TYPE06" "TYPE07" )
OPTIONS_LABELS_INPUT=( "Proxmox Host Builder - prepare & configure a new Proxmox host" "NFS Storage - add NFS PVE storage mounts" "CIFS Storage - add CIFS storage mounts" "Install Fail2Ban $(if [ $(dpkg -s fail2ban >/dev/null 2>&1; echo $?) = 0 ]; then echo "( installed & active )"; else echo "( not installed )"; fi)" "Install SSMTP Email Server $(if [ $(dpkg -s ssmtp >/dev/null 2>&1; echo $?) = 0 ] && [ $(grep -qs "^root:*" /etc/ssmtp/revaliases >/dev/null; echo $?) = 0 ]; then echo "( installed & active )"; else echo "( not installed )"; fi)" "Install a SSH Key -  add or create your own private SSH access key" "None. Exit this installer" )
makeselect_input2
singleselect SELECTED "$OPTIONS_STRING"

if [ ${RESULTS} == TYPE01 ]; then
  #---- Configure PVE host
  /tmp/pve-host-setup/scripts/pve_host_setup.sh
elif [ ${RESULTS} == TYPE02 ]; then
  #---- Create PVE Storage mounts (NFS)
  /tmp/pve-host-setup/scripts/pve_host_setup_nfs_mounts.sh
elif [ ${RESULTS} == TYPE03 ]; then
  #---- Create PVE Storage mounts (CIFS)
  /tmp/pve-host-setup/scripts/pve_host_setup_cifs_mounts.sh
elif [ ${RESULTS} == TYPE04 ]; then
  #---- Install and Configure Fail2ban
  /tmp/pve-host-setup/scripts/pve_host_setup_fail2ban.sh
elif [ ${RESULTS} == TYPE05 ]; then
  #---- Configure Email Alerts
  /tmp/pve-host-setup/scripts/pve_host_setup_postfix.sh
elif [ ${RESULTS} == TYPE06 ]; then
  #---- Configure SSH key
  /tmp/pve-host-setup/scripts/pve_host_setup_sshkey.sh
elif [ ${RESULTS} == TYPE07 ]; then
  # Exit installation
  msg "You have chosen not to proceed. Aborting. Bye..."
  echo
  sleep 1
fi


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