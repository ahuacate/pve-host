#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_setup_sshkey.sh
# Description:  Source script for setting up PVE host SSH Keys
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------

#bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-setup/master/scripts/pve_host_setup_sshkey.sh)"

#---- Source -----------------------------------------------------------------------

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
PVE_SOURCE="$DIR/../../common/pve/source"
BASH_SOURCE="$DIR/../../common/bash/source"

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
SECTION_HEAD='PVE Host SSH Keys'
# Check Ahuacate Check variables
if [[ $(cat /etc/postfix/main.cf | grep "### Ahuacate_Check=0.*") ]]; then
  SMTP_STATUS=0
elif [[ ! $(cat /etc/postfix/main.cf | grep "### Ahuacate_Check=0.*") ]]; then
  SMTP_STATUS=1
fi
# Check PVE Hostname variable
if [ -z "${SETUP_SSHKEY+x}" ]; then
  PVE_HOSTNAME=$HOSTNAME
fi

#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------

#---- Install and Configure SSH Authorised Keys

if [ -z "${SETUP_SSHKEY+x}" ] && [ -z "${PARENT_EXEC_PVE_SETUP_SSHKEY+x}" ]; then
  section "Creating & Configuring SSH Authorized Keys"

  msg_box "#### PLEASE READ CAREFULLY - CONFIGURING SSH AUTHORIZED KEYS ####\n
  You can use a SSH key for connecting to the PVE root account over SSH. PVE requires all SSH keys to be in the OpenSSH format. Your SSH key choices are:

  1. Append or add your existing SSH Public Key to your PVE hosts authorized keys file.

  2. Generate a a new set of SSH key pairs. If you choose to append your existing SSH Public Key to your PVE host you will be prompted to paste your Public Key into this terminal console. Use your mouse right-click to paste."
  echo
  read -p "Configure your PVE host for SSH key access [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    msg "Setting up SSH Authorized Keys..."
    SETUP_SSHKEY=0 >/dev/null
    echo
  else
    SETUP_SSHKEY=1 >/dev/null
    info "You have chosen to skip this step."
    cleanup
    exit 0
  fi
fi

#---- Checking PVE Host Prerequisites
section "Checking Prerequisites"

# nohup for PVE (part of package coreutils)
if [ $(dpkg -s coreutils >/dev/null 2>&1; echo $?) = 0 ]; then
  msg "Checking coreutils (nohup) status..."
  info "coreutils (nohup) status: ${GREEN}installed.${NC}"
  echo
else
  msg "Installing coreutils (nohup)..."
  apt-get install -y coreutils >/dev/null
  if [ $(dpkg -s coreutils >/dev/null 2>&1; echo $?) = 0 ]; then
    info "coreutils (nohup) status: ${GREEN}installed.${NC}"
  fi
  echo
fi

#---- Configuring SSH keys
section "Configuring SSH Authorized Keys."

# Select SSH key access type
TYPE01="${YELLOW}Existing SSH Keys${NC} - Append or add your existing SSH Public Key."
TYPE02="${YELLOW}Create New SSH Keys${NC} - Generate a new set of SSH key pairs."
PS3="Select the SSH key access type you want to proceed with (entering numeric) : "
msg "Available options:"
options=("$TYPE01" "$TYPE02")
select menu in "${options[@]}"; do
  case $menu in
    "$TYPE01")
      info "You have chosen to use: $(echo $menu | awk -F' - ' '{print $1}')"
      SSH_TYPE=TYPE01
      echo
      break
      ;;
    "$TYPE02")
      info "SMTP server is set as: $(echo $menu | awk -F' - ' '{print $1}')"
      SSH_TYPE=TYPE02
      echo
      break
      ;;
    *) warn "Invalid entry. Try again.." >&2
  esac
done

# Copy and Paste your existing key into the terminal window
if [ $SSH_TYPE = "TYPE01" ]; then
  section "Append or Add your existing SSH Public Key."
  msg "You have chosen to use your existing SSH Public Key. First you must copy the\ncontents of your SSH Public Key file into your clipboard.\n\n  --  COPY YOUR SSH PUBLIC KEY FILE\n      1. Open your SSH Public Key file in a text editor.\n      2. Highlight the key contents ( Ctrl + A ).\n      3. Copy the highlighted contents to your clipboard ( Ctrl + C ).\n  --  PASTE YOUR SSH PUBLIC KEY FILE\n      1. Mouse Right-Click when you are prompted ( > ).\n\nOr you can use the mouse to: highlight, select copy and paste at the prompt."
  while true; do
  echo
  read -r -p "Please paste your SSH Public Key at the prompt then press ENTER: `echo $'\n> '`" INPUTLINE_PUBLIC_KEY
  if [ "$(grep -q "$(echo $INPUTLINE_PUBLIC_KEY)" /root/.ssh/authorized_keys; echo "$?")" = "0" ]; then
    warn "A matching SSH Public Key already exists on ${PVE_HOSTNAME,,}.\nNot proceeding."
    read -p "Do you want to try another SSH Public Key [y/n]?: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      msg "Try again..."
      echo
    else
      info "You have chosen to skip this step. Exiting script."
      echo
      break
    fi
  elif [ "$(grep -q "$(echo $INPUTLINE_PUBLIC_KEY)" /root/.ssh/authorized_keys; echo "$?")" = "1" ]; then
    echo $INPUTLINE_PUBLIC_KEY >> /root/.ssh/authorized_keys
    service sshd restart >/dev/null
    echo
    msg "Adding SSH Public Key to PVE host..."
    info "Success. Your new SSH Public Key has been added to PVE host ${PVE_HOSTNAME,,}\nauthorized_keys file.\n==========   SSH KEYS FOR PVE HOST : ${PVE_HOSTNAME^^}   ==========\n\nFor root access to PVE host ${PVE_HOSTNAME,,} use your SSH Private Key.\n\nYour login credentials details are:\n    Username: ${YELLOW}root${NC}\n    Password: Only you know (SSH Private Key only).\n    SSH Private Key: You should already have it.\n    PVE Server LAN IP Address: ${YELLOW}$(hostname -I)${NC}"
    echo
    break
  fi
  done
fi
  
# Generate a new set of SSH RSA Key pairs
if [ $SSH_TYPE = "TYPE02" ]; then
  section "Generate a new set of SSH Key pair files."
  msg "You have chosen to generate a new set of SSH key pair files. Your new SSH\nkey pair files will be generated using the ed25519 algorithm. In the next steps\nyou will be given the option to:\n\n  --  EMAIL YOUR NEW SSH PUBLIC KEY FILES\n      1. You may need to confirm your PVE Postfix is working.\n      2. Confirm your recipients email address is valid.\n\nYour new SSH key pair files will also be backed up to a linux tar.gz file."
  if [[ $(df -h | awk 'NR>1 { print $1, "mounted on", $NF }' | grep "/mnt/pve/.*backup") ]]; then
    msg "\n  --  BACKUP LOCATION OF SSH PUBLIC KEY FILES\n      $(df -h | awk 'NR>1 { print $1, "mounted on", $NF }' | grep "/mnt/pve/.*backup")\n      NAS File Location: ${WHITE}"$(df -h | awk 'NR>1 { print $1, $NF }' | grep "/mnt/pve/.*backup" | awk '{ print $1}')/${PVE_HOSTNAME,,}"_ssh_keys.tar.gz${NC}\n      PVE File Location: ${WHITE}$(df -h | awk 'NR>1 { print $1, $NF }' | grep "/mnt/pve/.*backup" | awk '{ print $NF}')/"${PVE_HOSTNAME,,}"_ssh_keys.tar.gz${NC}"
    # Backup Location
    SSH_BACKUP_LOCATION=$(df -h | awk 'NR>1 { print $1, $NF }' | grep "/mnt/pve/.*backup" | awk '{ print $NF}')/pve/ssh_keys
    SSH_BACKUP_FILENAME="${PVE_HOSTNAME,,}"_ssh_keys.tar.gz
  elif [[ ! $(df -h | awk 'NR>1 { print $1, "mounted on", $NF }' | grep "/mnt/pve/.*backup") ]]; then
    msg "\n  --  BACKUP LOCATION OF SSH PUBLIC KEY FILES\n      We cannot find a NAS NFS/CIFS backup folder mountpoint on your PVE host.\n      Using your PVE host /tmp folder instead. You should move the backup tar.gz\n      from /tmp to a secure storage location not on this PVE host.\n      Temporary PVE File Location: ${WHITE}/tmp/"${PVE_HOSTNAME,,}"_ssh_keys.tar.gz${NC}"
    # Backup Location
    SSH_BACKUP_LOCATION=/tmp
    SSH_BACKUP_FILENAME="${PVE_HOSTNAME,,}"_ssh_keys.tar.gz
  fi
  echo
  
  # Check SMTP server status
  msg "Checking PVE host SMTP email server status..."
  EMAIL_RECIPIENT=$(pveum user list | awk -F " │ " '$1 ~ /root@pam/' | awk -F " │ " '{ print $3 }')
  if [ $SMTP_STATUS = 0 ]; then
    info "You are set to receive your SSH key pair by email.\nYour SSH key pairs will be sent to: ${YELLOW}$EMAIL_RECIPIENT${NC}"
    echo
  elif [ $SMTP_STATUS = 1 ]; then
    read -p "Is your PVE Postfix email server configured and working [y/n]?: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      SMTP_STATUS=0
      info "You are set to receive your SSH key pair by email.\nYour SSH key pairs will be sent to: ${YELLOW}$EMAIL_RECIPIENT${NC}"
      echo
    else
      SMTP_STATUS=1
      info "You PVE host SMTP is not configured or working.\nYou will not receive your SSH key pair by email."
      echo
    fi
  fi

  # uuencode for Postfix (part of package sharutils)
  if [ $SMTP_STATUS = 0 ]; then
    msg "Checking SMTP Postfix email server prerequisites..."
    if [ $(dpkg -s sharutils >/dev/null 2>&1; echo $?) = 0 ]; then
      msg "Checking sharutils (uuencode) status..."
      info "sharutils (uuencode) status: ${GREEN}installed.${NC}"
      echo
    else
      msg "Installing sharutils (uuencode)..."
      apt-get install -y sharutils >/dev/null
      if [ $(dpkg -s sharutils >/dev/null 2>&1; echo $?) = 0 ]; then
        info "sharutils (uuencode) status: ${GREEN}installed.${NC}"
      fi
      echo
    fi
  fi

  # Generating SSH Key Pair
  msg "Generating ed25519 SSH key pair..."
  ssh-keygen -o -q -t ed25519 -a 100 -f id_ed25519 -N ""
  msg "Adding SSH Public Key to PVE host..."
  cat id_ed25519.pub >> /root/.ssh/authorized_keys
  msg "Creating backup ${WHITE}$SSH_BACKUP_FILENAME${NC} file of SSH key pairs..."
  tar czf $SSH_BACKUP_FILENAME id_ed25519 id_ed25519.pub
  mkdir -p $SSH_BACKUP_LOCATION >/dev/null
  cp $SSH_BACKUP_FILENAME $SSH_BACKUP_LOCATION

  # Email SSH key pairs
  if [ $SMTP_STATUS = 0 ]; then
    msg "Emailing SSH key pairs..."
    echo -e "\n==========   SSH KEYS FOR PVE HOST : ${PVE_HOSTNAME^^}   ==========\n\nFor root access to PVE host ${PVE_HOSTNAME,,} use the attached SSH Private Key file named id_ed25519.\n\nYour login credentials details are:\n    Username: root\n    Password: Not Required (SSH Private Key only).\n    SSH Private Key: id_ed25519\n    PVE Server LAN IP Address: $(hostname -I)\n\nA backup linux tar.gz file containing your SSH Key pairs is also attached.\n    Backup filename of SSH Key Pairs: $SSH_BACKUP_FILENAME\n\nDo you use Putty as your SSH client? If so then you need to convert the SSH private key into the right format to use with Putty:\n    1. In Puttygen, in the 'Conversions' menu choose 'Import' and load 'id_ed25519'.\n    2. Under 'Parameters' set type of key to generate to 'ED25519'.\n    3. 'Save private key' to a different filename.\nUse this new file with Putty, either on the connection properties menu or run Pageant (the Putty key agent)and 'Add key' the new file.\n" | (cat - && uuencode id_ed25519 id_ed25519 ; uuencode id_ed25519.pub id_ed25519.pub ; uuencode $SSH_BACKUP_FILENAME $SSH_BACKUP_FILENAME) | mail -s "SHH key pairs for PVE host $(echo $SSH_BACKUP_FILENAME | awk -F'_' '{ print $1}')." -- $EMAIL_RECIPIENT
    info "SSH key pairs to emailed to: ${YELLOW}$EMAIL_RECIPIENT${NC}"
    echo
  fi

  # Closing Message
  if [ $SMTP_STATUS = 0 ]; then
    info "Success. Your new SSH Public Key has been added to PVE host ${PVE_HOSTNAME,,}\nauthorized_keys file.\n\n==========   SSH KEYS FOR PVE HOST : ${PVE_HOSTNAME^^}   ==========\n\nFor root access to PVE host ${PVE_HOSTNAME,,} use SSH Private Key\nfile named id_ed25519.\n\nYour login credentials details are:\n    Username: ${YELLOW}root${NC}\n    Password: Not Required (SSH Private Key only).\n    SSH Private Key: ${YELLOW}id_ed25519${NC}\n    PVE Server LAN IP Address: ${YELLOW}$(hostname -I)${NC}\n\nA backup linux tar.gz file containing your SSH Key pairs has also been created.\n    Backup filename of SSH Key Pairs: ${YELLOW}$SSH_BACKUP_FILENAME${NC}\n    Backup of SSH Key Pairs emailed to: ${YELLOW}$EMAIL_RECIPIENT${NC}\n    Backup location for SSH Key Pairs: ${YELLOW}$SSH_BACKUP_LOCATION/$SSH_BACKUP_FILENAME${NC}\n\nDo you use Putty as your SSH client? If so, then you need to convert the\nSSH private key into the right format to use with Putty:\n    1. In Puttygen, in the ${WHITE}Conversions${NC} menu choose ${WHITE}Import${NC} and\n    load ${WHITE}id_ed25519${NC}.\n    2. Under ${WHITE}Parameters${NC} set type of key to generate to ${WHITE}ED25519${NC}.\n    3. ${WHITE}Save private key${NC} to a different filename - ${WHITE}id_ed25519_putty${NC}.\n\nUse this new file with Putty, either on the connection properties menu or\nrun Pageant (the Putty key agent) and ${WHITE}Add key${NC} selecting the new file."
    echo
  elif [ $SMTP_STATUS = 1 ]; then
    info "Success. Your new SSH Public Key has been added to PVE host ${PVE_HOSTNAME,,}\nauthorized_keys file.\n\n==========   SSH KEYS FOR PVE HOST : ${PVE_HOSTNAME^^}   ==========\n\nFor root access to PVE host ${PVE_HOSTNAME,,} use SSH Private Key\nfile named id_ed25519.\n\nYour login credentials details are:\n    Username: ${YELLOW}root${NC}\n    Password: Not Required (SSH Private Key only).\n    SSH Private Key: ${YELLOW}id_ed25519${NC}\n    PVE Server LAN IP Address: ${YELLOW}$(hostname -I)${NC}\n\nA backup linux tar.gz file containing your SSH Key pairs has also been created.\n    Backup filename of SSH Key Pairs: ${YELLOW}$SSH_BACKUP_FILENAME${NC}\n    Backup location for SSH Key Pairs: ${YELLOW}$SSH_BACKUP_LOCATION/$SSH_BACKUP_FILENAME${NC}\n\nDo you use Putty as your SSH client? If so, then you need to convert the\nSSH private key into the right format to use with Putty:\n    1. In Puttygen, in the ${WHITE}Conversions${NC} menu choose ${WHITE}Import${NC} and\n    load ${WHITE}id_ed25519${NC}.\n    2. Under ${WHITE}Parameters${NC} set type of key to generate to ${WHITE}ED25519${NC}.\n    3. ${WHITE}Save private key${NC} to a different filename - ${WHITE}id_ed25519_putty${NC}.\n\nUse this new file with Putty, either on the connection properties menu or\nrun Pageant (the Putty key agent) and ${WHITE}Add key${NC} selecting the new file."
    echo
  fi
fi


#---- Configuring SSH Security
section "Proxmox SSHD security modifications."

msg "Minimizing vulnerabilities in your Secure Shell (SSH) protocol is key to\nensuring the security of your PVE environment. We have two preset measures you\ncan take to make your PVE host more secure."

# Select SSHD Security modifications
TYPE01="${YELLOW}SSH Keys Only${NC} - Authentication by SSH key-pairs only."
TYPE02="${YELLOW}SSH Keys & Passwords${NC} - Authentication by passwords & SSH key-pairs (Recommended)."
PS3="Select the SSH key security you want for your PVE host (entering numeric) : "
msg "Available options:"
options=("$TYPE01" "$TYPE02")
select menu in "${options[@]}"; do
  case $menu in
    "$TYPE01")
      info "You have chosen preset: $(echo $menu | awk -F' - ' '{print $1}')"
      SSH_SEC=TYPE01
      echo
      break
      ;;
    "$TYPE02")
      info "You have chosen preset: $(echo $menu | awk -F' - ' '{print $1}')"
      SSH_SEC=TYPE02
      echo
      break
      ;;
    *) warn "Invalid entry. Try again.." >&2
  esac
done

if [ $SSH_SEC = TYPE01 ]; then
  # SSH key only, permitted root login & prohibit password authentication
  sed -i -r '/^#?PermitRootLogin.*/c\PermitRootLogin prohibit-password' /etc/ssh/sshd_config
  sed -i -r '/^#?PasswordAuthentication.*/c\PasswordAuthentication no' /etc/ssh/sshd_config
  sed -i -r '/^#?PubkeyAuthentication.*/c\PubkeyAuthentication yes' /etc/ssh/sshd_config
  sed -i -r '/^#?PermitEmptyPasswords.*/c\PermitEmptyPasswords no' /etc/ssh/sshd_config
  info "SSH security modifications are:\n         PermitRootLogin = ${YELLOW}prohibit-password${NC}\n         PasswordAuthentication = ${YELLOW}no${NC}\n         PubkeyAuthentication = ${YELLOW}yes${NC}\n         PermitEmptyPasswords = ${YELLOW}no${NC}"
elif [ $SSH_SEC = TYPE02 ]; then
  # SSH key, permitted root login & allow password authentication
  sed -i -r '/^#?PermitRootLogin.*/c\PermitRootLogin yes' /etc/ssh/sshd_config
  sed -i -r '/^#?PasswordAuthentication.*/c\PasswordAuthentication yes' /etc/ssh/sshd_config
  sed -i -r '/^#?PubkeyAuthentication.*/c\PubkeyAuthentication yes' /etc/ssh/sshd_config
  sed -i -r '/^#?PermitEmptyPasswords.*/c\PermitEmptyPasswords no' /etc/ssh/sshd_config
  info "SSH security modifications are:\n         PermitRootLogin = ${YELLOW}yes${NC}\n         PasswordAuthentication = ${YELLOW}yes${NC}\n         PubkeyAuthentication = ${YELLOW}yes${NC}\n         PermitEmptyPasswords = ${YELLOW}no${NC}"
fi


#---- Finish
section "PVE SSH Key Completion Status"

msg "${WHITE}Success.${NC}"
sleep 3

# Cleanup
if [ -z ${PARENT_EXEC_PVE_SETUP_SSHKEY+x} ]; then
  msg "Restarting PVE host SSH daemon..."
  nohup service sshd restart >/dev/null 2>&1
  if [ "$(systemctl is-active --quiet sshd; echo $?) -eq 0" ]; then
    info "SSHD status: ${GREEN}active (running).${NC}"
    echo
  elif [ "$(systemctl is-active --quiet sshd; echo $?) -eq 3" ]; then
    info "SSHD status: ${RED}inactive (dead).${NC}. Your intervention is required."
    echo
  fi
  cleanup
fi