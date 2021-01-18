#!/usr/bin/env bash

set -Eeuo pipefail
shopt -s expand_aliases
alias die='EXIT=$? LINE=$LINENO error_exit'
trap die ERR
trap cleanup EXIT
function error_exit() {
  trap - ERR
  local DEFAULT='Unknown failure occured.'
  local REASON="\e[97m${1:-$DEFAULT}\e[39m"
  local FLAG="\e[91m[ERROR] \e[93m$EXIT@$LINE"
  msg "$FLAG $REASON"
  [ ! -z ${CTID-} ] && cleanup_failed
  exit $EXIT
}
function warn() {
  local REASON="\e[97m$1\e[39m"
  local FLAG="\e[93m[WARNING]\e[39m"
  msg "$FLAG $REASON"
}
function info() {
  local REASON="$1"
  local FLAG="\e[36m[INFO]\e[39m"
  msg "$FLAG $REASON"
}
function msg() {
  local TEXT="$1"
  echo -e "$TEXT"
}
function section() {
  local REASON="  \e[97m$1\e[37m"
  printf -- '-%.0s' {1..100}; echo ""
  msg "$REASON"
  printf -- '-%.0s' {1..100}; echo ""
  echo
}
function pushd () {
  command pushd "$@" &> /dev/null
}
function popd () {
  command popd "$@" &> /dev/null
}
function cleanup() {
  popd
  rm -rf $TEMP_DIR
  unset TEMP_DIR
}
function load_module() {
  if ! $(lsmod | grep -Fq $1); then
    modprobe $1 &>/dev/null || \
      die "Failed to load '$1' module."
  fi
  MODULES_PATH=/etc/modules
  if ! $(grep -Fxq "$1" $MODULES_PATH); then
    echo "$1" >> $MODULES_PATH || \
      die "Failed to add '$1' module to load at boot."
  fi
}
function box_out() {
  set +u
  local s=("$@") b w
  for l in "${s[@]}"; do
	((w<${#l})) && { b="$l"; w="${#l}"; }
  done
  tput setaf 3
  echo -e " -${b//?/-}-\n| ${b//?/ } |"
  for l in "${s[@]}"; do
	printf '| %s%*s%s |\n' "$(tput setaf 7)" "-$w" "$l" "$(tput setaf 3)"
  done
  echo -e "| ${b//?/ } |\n -${b//?/-}-"
  tput sgr 0
  set -u
}

# Colour
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
GREEN=$'\033[0;32m'
WHITE=$'\033[1;37m'
NC=$'\033[0m'

# Resize Terminal
printf '\033[8;40;120t'

# Detect modules and automatically load at boot
load_module aufs
load_module overlay

# Set Temp Folder
if [ -z "${TEMP_DIR+x}" ]; then
  TEMP_DIR=$(mktemp -d)
  pushd $TEMP_DIR >/dev/null
else
  if [ $(pwd -P) != $TEMP_DIR ]; then
    cd $TEMP_DIR >/dev/null
  fi
fi

# Checking for Internet connectivity
if [ -z "${SETUP_FAIL2BAN+x}" ]; then
  msg "Checking for internet connectivity..."
  if nc -zw1 google.com 443; then
    info "Internet connectivity status: ${GREEN}Active${NC}"
    echo
  else
    warn "Internet connectivity status: ${RED}Down${NC}\n          Cannot proceed without a internet connection.\n          Fix your PVE hosts internet connection and try again..."
    echo
    cleanup
    exit 0
  fi
fi

# Check Ahuacate Check variables
if [[ $(cat /etc/postfix/main.cf | grep "### Ahuacate_Check=0.*") ]]; then
  SMTP_STATUS=0
elif [[ ! $(cat /etc/postfix/main.cf | grep "### Ahuacate_Check=0.*") ]]; then
  SMTP_STATUS=1
fi

# Check PVE Hostname variable
if [ -z "${SETUP_FAIL2BAN+x}" ]; then
  PVE_HOSTNAME=$HOSTNAME
fi


# Script Variables
SECTION_HEAD="Proxmox PVE Host Build & Configure"


# Download external scripts

#########################################################################################
# This script is for Installing and configuring Fail2Ban                                #
#                                                                                       #
# Tested on Proxmox Version : pve-manager/6.1-3/37248ce6 (running kernel: 5.3.10-1-pve) #
#########################################################################################


# Command to run script
#bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/proxmox-node/master/scripts/pve_setup_fail2ban.sh)"


### Install and Configure Fail2Ban ####

if [ -z "${SETUP_FAIL2BAN+x}" ] && [ -z "${PARENT_EXEC_PVE_SETUP_FAIL2BAN+x}" ]; then
  section "$SECTION_HEAD - Installing and configuring Fail2Ban."

  box_out '#### PLEASE READ CAREFULLY - CONFIGURING FAIL2BAN ####' '' 'Fail2Ban is an intrusion prevention software framework that protects computer' 'servers from brute-force attacks.' '' 'Most commonly this is used to block selected IP addresses that may belong to' 'hosts that are trying to breach the systems security. It can ban any host' 'IP address that makes too many login attempts or performs any other unwanted' 'action within a time frame defined by the PVE administrator.' '' 'Our default Fail2ban configuration sets the following rulesets:' '  --  PVE WEBGUI HTTP(S) ACCESS' '      Maximum HTTP retry 3 attempts.' '      PVE HTTP(S) ban time is 1 hour.' 'If your PVE Postfix SMTP server is configured and working Fail2ban will' 'configured to send email alerts.' '  --  PVE EMAIL ALERTS' '      Send email alerts of banned login attempts.' '      (requires working PVE Postfix SMTP server.)'
  echo
  read -p "Install and configure Fail2ban [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    msg "Installing and configuring Fail2ban ..."
    SETUP_FAIL2BAN=0 >/dev/null
    echo
  else
    SETUP_FAIL2BAN=1 >/dev/null
    info "You have chosen to skip this step."
    cleanup
    exit 0
  fi
fi

#### Checking PVE Host Prerequisites ####
section "$SECTION_HEAD - Checking Prerequisites"

# Installing Fail2Ban
if [ $(dpkg -s fail2ban >/dev/null 2>&1; echo $?) = 0 ]; then
  msg "Checking fail2ban status..."
  info "Fail2ban status: ${GREEN}installed.${NC}"
  echo
else
  msg "Installing fail2ban..."
  apt-get install -y fail2ban >/dev/null
  if [ $(dpkg -s fail2ban >/dev/null 2>&1; echo $?) = 0 ]; then
    info "Fail2ban status: ${GREEN}installed.${NC}"
  fi
  echo
fi

#### Configuring Fail2ban ####
section "$SECTION_HEAD - Configuring Fail2ban."

# Checking Postfix SMTP Status
msg "Checking PVE host SMTP email server status for sending Fail2ban alerts..."
EMAIL_RECIPIENT=$(pveum user list | awk -F " │ " '$1 ~ /root@pam/' | awk -F " │ " '{ print $3 }')
if [ $SMTP_STATUS = 0 ]; then
  read -p "Do you want to receive Fail2ban email alerts [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    info "You are set to receive Fail2ban alerts by email.\nAll alerts will be sent to: ${YELLOW}$EMAIL_RECIPIENT${NC}"
    F2B_EMAIL_ALERTS=0
  else
    info "You have chosen NOT to configure Fail2ban to send email alerts."
    F2B_EMAIL_ALERTS=1
  fi
  echo
elif [ $SMTP_STATUS = 1 ]; then
  msg "We cannot determine if your PVE Postfix email server works."
  read -p "Is your PVE Postfix email server configured and working [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    read -p "Do you want to receive Fail2ban email alerts [y/n]?: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      SMTP_STATUS=0
      info "You are set to receive Fail2ban alerts by email.\nAll alerts will be sent to: ${YELLOW}$EMAIL_RECIPIENT${NC}"
      F2B_EMAIL_ALERTS=0
      echo
    else
      info "You have chosen NOT to configure Fail2ban to send email alerts."
      F2B_EMAIL_ALERTS=1
      echo
    fi
  else
    info "You PVE host SMTP server is not configured or working.\nYou will not receive any Fail2ban email alerts."
    F2B_EMAIL_ALERTS=1
    echo
  fi
fi

# Configuring Fail2Ban
# Fail2Ban Default Access rulesets
if [ $F2B_EMAIL_ALERTS = 0 ]; then
  msg "Configuring Fail2Ban default rulesets..."
  F2B_DEFAULT_IPWHITELIST="127.0.0.1/8"
  info "PVE hosts Fail2ban default ruleset is set:\n         Email alerts: ${YELLOW}Active${NC}\n         Alerts sent to: ${YELLOW}$EMAIL_RECIPIENT${NC}\n         IP whitelist: ${YELLOW}$F2B_DEFAULT_IPWHITELIST${NC}"
  echo -e "[DEFAULT]\ndestemail = $EMAIL_RECIPIENT\nsender = fail2ban@localhost\nsendername = Fail2ban\nmta = mail\naction = %(action_mwl)s\nignoreip = $F2B_DEFAULT_IPWHITELIST" > /etc/fail2ban/jail.local
  echo
elif [ $F2B_EMAIL_ALERTS = 1 ]; then
  msg "Configuring Fail2Ban default rulesets..."
  info "PVE hosts Fail2ban default ruleset is set:\n         IP whitelist: ${YELLOW}127.0.0.1/8${NC}"
  echo -e "[DEFAULT]\nignoreip = 127.0.0.1/8" > /etc/fail2ban/jail.local
  echo
fi

# Fail2Ban PVE WebGui HTTP(s) Access rulesets
msg "Configuring Fail2Ban PVE WebGui HTTP(s) access rulesets..."
F2B_HTTP_MAX_RETRY=3
F2B_HTTP_BANTIME=1 # Hours (Units)
read -p "Confirm your PVE hosts WebGui HTTP(s) port number: " -e -i 8006 F2B_HTTP_PVE_PORT
info "PVE hosts Fail2ban WebGui HTTP(s) ruleset is set:\n         WebGui port number: ${YELLOW}$F2B_HTTP_PVE_PORT${NC}\n         Max retry number: ${YELLOW}$F2B_HTTP_MAX_RETRY${NC}\n         Ban time (seconds): ${YELLOW}$F2B_HTTP_BANTIME${NC}"
echo -e "[proxmox-web-gui]\nenabled = true\nport = https,http,$F2B_HTTP_PVE_PORT\nfilter = proxmox\nlogpath = /var/log/daemon.log\nmaxretry = $F2B_HTTP_MAX_RETRY\nbantime = $(echo $(( $F2B_HTTP_BANTIME * 60 * 60 )))" > /etc/fail2ban/jail.d/proxmox-web-gui.local
echo -e "[Definition]\nfailregex = pvedaemon\[.*authentication failure; rhost=<HOST> user=.* msg=.*\nignoreregex =" > /etc/fail2ban/filter.d/proxmox.conf
echo

# Fail2Ban SSHd rulesets
msg "Configuring Fail2Ban SSHD access rulesets..."
F2B_SSHD_MAX_RETRY=10
F2B_SSHD_FINDTIME=60 # Seconds (units)
F2B_SSHD_BANTIME=1 # Hours (Units)
info "PVE hosts SSHD ruleset is set:\n         Max retry number: ${YELLOW}$F2B_SSHD_MAX_RETRY${NC}\n         Findtime (seconds): ${YELLOW}$F2B_SSHD_FINDTIME${NC}\n         Ban time (seconds): ${YELLOW}$F2B_SSHD_BANTIME${NC}"
echo -e "[sshd]\nenabled = true\nport = ssh\nfilter = sshd\nlogpath = /var/log/auth.log\nmaxretry = $F2B_SSHD_MAX_RETRY\nfindtime = $F2B_SSHD_FINDTIME\nbantime = $(echo $(( $F2B_SSHD_BANTIME * 60 * 60 )))" > /etc/fail2ban/jail.d/sshd.local
echo

# Fail2ban restart
msg "Restarting Fail2ban..."
service fail2ban restart 2>/dev/null
if [ "$(systemctl is-active --quiet fail2ban; echo $?) -eq 0" ]; then
	info "Fail2ban status: ${GREEN}active (running).${NC}"
	echo
elif [ "$(systemctl is-active --quiet fail2ban; echo $?) -eq 3" ]; then
	info "Fail2ban status: ${RED}inactive (dead).${NC}. Your intervention is required."
	echo
fi

#### Finish ####
section "$SECTION_HEAD - PVE Fail2ban Completion Status"

msg "${WHITE}Success.${NC}"
sleep 3

# Cleanup
if [ -z ${PARENT_EXEC_PVE_SETUP_FAIL2BAN+x} ]; then
  cleanup
fi