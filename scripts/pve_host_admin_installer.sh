#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_admin_installer.sh
# Description:  Installer script for Proxmox host administration & Add-Ons
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------

#---- Source Github
#bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-setup/master/pve_host_admin_installer.sh)"

#---- Source local Git
# /mnt/pve/nas-01-git/ahuacate/pve-nas/pve_nas_ct_admin_installer.sh

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

#---- Set Bash Temp Folder
if [ -z "${TEMP_DIR+x}" ]; then
    TEMP_DIR=$(mktemp -d)
    pushd $TEMP_DIR > /dev/null
else
    if [ $(pwd -P) != $TEMP_DIR ]; then
    cd $TEMP_DIR > /dev/null
    fi
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

#---- Other Variables --------------------------------------------------------------

# Easy Script Section Header Body Text
SECTION_HEAD='PVE Host Setup'

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

#---- Select NAS CTID
section "Select and Connect with your NAS"
msg "User must identify and select a Ubuntu NAS from the menu:"
unset vmid_LIST
vmid_LIST+=( $(pct list | sed 's/[ ]\+/:/g' | sed 's/:$//' | awk -F':' 'BEGIN { OFS=FS } { if(NR > 1) print $3, $1 }') )
OPTIONS_VALUES_INPUT=$(printf '%s\n' "${vmid_LIST[@]}" | awk -F':' '{ print $2}')
OPTIONS_LABELS_INPUT=$(printf '%s\n' "${vmid_LIST[@]}" | awk -F':' '{ print "NAME: "$1, "| VMID: "$2 }')
makeselect_input1 "$OPTIONS_VALUES_INPUT" "$OPTIONS_LABELS_INPUT"
singleselect SELECTED "$OPTIONS_STRING"
CTID=${RESULTS}

# Check NAS run status
pct_start_waitloop

# Pushing PVE common setup scripts to NAS CT
msg "Pushing common scripts to NAS CT..."
pct push $CTID /tmp/common.tar.gz /tmp/common.tar.gz
pct exec $CTID -- tar -zxf /tmp/common.tar.gz -C /tmp

# Pushing PVE-nas setup scripts to NAS CT
msg "Pushing NAS configuration scripts to NAS CT..."
pct push $CTID /tmp/${GIT_REPO}.tar.gz /tmp/${GIT_REPO}.tar.gz
pct exec $CTID -- tar -zxf /tmp/${GIT_REPO}.tar.gz -C /tmp
echo


#---- Run Installer
section "Run a Ubuntu NAS Add-On task"
OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE02" "TYPE03" "TYPE04" "TYPE05" "TYPE06" "TYPE07" )
OPTIONS_LABELS_INPUT=( "Power User Account - create or delete account" "Jailed User Account - create or delete account" "Upgrade NAS OS - software packages, OS and patches" "Install Fail2Ban $(if [ $(pct exec $CTID -- dpkg -s fail2ban >/dev/null 2>&1; echo $?) = 0 ]; then echo "( installed & active )"; else echo "( not installed )"; fi)" "Install SSMTP Email Server $(if [ $(pct exec $CTID -- dpkg -s ssmtp >/dev/null 2>&1; echo $?) = 0 ] && [ $(pct exec $CTID -- grep -qs "^root:*" /etc/ssmtp/revaliases >/dev/null; echo $?) = 0 ]; then echo "( installed & active )"; else echo "( not installed )"; fi)" "Install ProFTPd Server $(if [ $(pct exec $CTID -- dpkg -s proftpd-core >/dev/null 2>&1; echo $?) = 0 ]; then echo "( installed & active )"; else echo "( not installed )"; fi)" "None. Exit this installer" )
makeselect_input2
singleselect SELECTED "$OPTIONS_STRING"

if [ ${RESULTS} == TYPE01 ]; then
  #---- Create New Power User Accounts
  pct exec $CTID -- bash -c "/tmp/pve-nas/scripts/source/ubuntu/pve_nas_ct_addpoweruser.sh"
elif [ ${RESULTS} == TYPE02 ]; then
  #---- Create New Jailed User Accounts
  pct exec $CTID -- bash -c "/tmp/pve-nas/scripts/source/ubuntu/pve_nas_ct_addjailuser.sh"
elif [ ${RESULTS} == TYPE03 ]; then
  #---- Perform a NAS upgrade
  pct exec $CTID -- bash -c "/tmp/pve-nas/scripts/source/ubuntu/pve_nas_ct_versionupdater.sh"
elif [ ${RESULTS} == TYPE04 ]; then
  #---- Install and Configure Fail2ban
  pct exec $CTID -- bash -c "export SSH_PORT=\$(grep Port /etc/ssh/sshd_config | sed '/^#/d' | awk '{ print \$2 }') && /tmp/common/pve/source/pvesource_ct_ubuntu_installfail2ban.sh"
elif [ ${RESULTS} == TYPE05 ]; then
  #---- Install and Configure SSMTP Email Alerts
  pct exec $CTID -- bash -c "/tmp/common/pve/source/pvesource_ct_ubuntu_installssmtp.sh"
elif [ ${RESULTS} == TYPE06 ]; then
  #---- Install and Configure ProFTPd
  # pct exec $CTID -- bash -c "cp /tmp/pve-nas/scripts/source/ubuntu/proftpd_settings/sftp.conf /tmp/common/pve/source/ && /tmp/common/pve/source/pvesource_ct_ubuntu_installproftpd.sh"
  # Check if ProFTPd is installed
  if [ $(pct exec $CTID -- dpkg -s proftpd-core >/dev/null 2>&1; echo $?) != 0 ]; then
    pct exec $CTID -- bash -c "/tmp/common/pve/source/pvesource_ct_ubuntu_installproftpd.sh"
  else
    msg "ProFTPd is already installed..."
  fi
  pct exec $CTID -- bash -c "/tmp/pve-nas/scripts/source/ubuntu/proftpd_settings/pve_nas_ct_proftpdsettings.sh"
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
pct exec $CTID -- bash -c "rm -R /tmp/common &> /dev/null; rm -R /tmp/pve-nas &> /dev/null; rm /tmp/common.tar.gz &> /dev/null; rm /tmp/pve-nas.tar.gz &> /dev/null"
rm -R /tmp/common &> /dev/null
rm -R /tmp/pve-nas &> /dev/null
rm /tmp/common.tar.gz &> /dev/null
rm /tmp/pve-nas.tar.gz &> /dev/null

trap cleanup EXIT