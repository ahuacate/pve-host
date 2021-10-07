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
  section "Setup Proxmox for SSH Authorized Key access"

  msg_box "#### PLEASE READ CAREFULLY - CONFIGURING SSH AUTHORIZED KEYS ####\n
  PVE System Administrators should use SSH keys to access PVE root accounts over SSH. PVE requires all SSH keys to be in the OpenSSH format. Your PVE host SSH key choices are:

  1. Append or add an existing SSH Public Key to PVE hosts authorized keys file.

  2. Generate a a new set of SSH key pairs. If the User chooses to append a existing SSH Public Key to the PVE host you will be prompted to paste the SSH Public Key into this terminal console. Use your mouse right-click to paste."
  echo
  while true; do
    read -p "Configure this PVE host for SSH key access [y/n]?: " -n 1 -r YN
    echo
    case $YN in
      [Yy]*)
        msg "Setting up SSH Authorized Keys..."
        SETUP_SSHKEY=0 >/dev/null
        echo
        break
        ;;
      [Nn]*)
        SETUP_SSHKEY=1 >/dev/null
        info "The User has chosen to skip this step."
        cleanup
        exit 0
        break
        ;;
      *)
        warn "Error! Entry must be 'y' or 'n'. Try again..."
        echo
        ;;
    esac
  done
fi


#---- Checking PVE Host Prerequisites
section "Checking Prerequisites"

# nohup for PVE (part of package coreutils)
if [ $(dpkg -s coreutils >/dev/null 2>&1; echo $?) = 0 ]; then
  msg "Checking coreutils (nohup) status..."
  info "coreutils (nohup) status: ${GREEN}installed${NC}"
  echo
else
  msg "Installing coreutils (nohup)..."
  apt-get install -y coreutils >/dev/null
  if [ $(dpkg -s coreutils >/dev/null 2>&1; echo $?) = 0 ]; then
    info "coreutils (nohup) status: ${GREEN}installed${NC}"
  fi
  echo
fi

# Install Puttytools
if [ $(dpkg -s putty-tools >/dev/null 2>&1; echo $?) = 0 ]; then
  msg "Putty-Tools status..."
  info "Putty-Tools status: ${GREEN}installed${NC}"
  echo
else
  msg "Installing Putty Tools..."
  apt-get install -y putty-tools >/dev/null
  info "Putty-Tools status: ${GREEN}installed${NC}"
  echo
fi

#---- Configuring SSH keys
section "Configuring SSH Authorized Keys."

# Select SSH key access type
TYPE01="${YELLOW}Existing SSH Keys${NC} - Append or add existing SSH Public Key to the host."
TYPE02="${YELLOW}Create New SSH Keys${NC} - Generate a new set of SSH key pairs."
PS3="Select the SSH key access type to proceed with (entering numeric) : "
msg "Available options:"
options=("$TYPE01" "$TYPE02")
select menu in "${options[@]}"; do
  case $menu in
    "$TYPE01")
      info "User has chosen: $(echo $menu | awk -F' - ' '{print $1}')"
      SSH_TYPE=TYPE01
      echo
      break
      ;;
    "$TYPE02")
      info "User has chosen: $(echo $menu | awk -F' - ' '{print $1}')"
      SSH_TYPE=TYPE02
      echo
      break
      ;;
    *) warn "Invalid entry. Try again.." >&2
  esac
done

# Copy and Paste your existing key into the terminal window
if [ $SSH_TYPE = "TYPE01" ]; then
  section "Append or Add a existing SSH Public Key."
  msg "User has chosen add a existing SSH Public Key to the PVE host. The User must copy the contents the SSH Public Key file to be added into the Users computer clipboard.
    --  COPY A SSH PUBLIC KEY FILE
          1. Open the SSH Public Key file in a text editor.
          2. Highlight the key contents ( Ctrl + A ).
          3. Copy the highlighted contents to the Users computer clipboard ( Ctrl + C ).
    --  PASTE THE SSH PUBLIC KEY FILE
          1. Mouse Right-Click when you are prompted ( > ).\n"
  while true; do
  echo
  read -r -p "Paste the SSH Public Key at the prompt then press ENTER: `echo $'\n> '`" INPUTLINE_PUBLIC_KEY
  if [ "$(grep -q "$(echo $INPUTLINE_PUBLIC_KEY)" /root/.ssh/authorized_keys; echo "$?")" = "0" ]; then
    warn "A matching SSH Public Key already exists on ${PVE_HOSTNAME,,}.\nNot proceeding."
    while true; do
      read -p "Try another SSH Public Key [y/n]?: " -n 1 -r YN
      echo
      case $YN in
        [Yy]*)
          msg "Try again..."
          echo
          ;;
        [Nn]*)
          info "User has chosen to skip this step. Exiting script."
          echo
          exit 0
          ;;
        *)
          warn "Error! Entry must be 'y' or 'n'. Try again..."
          echo
          ;;
      esac
    done
  elif [ "$(grep -q "$(echo $INPUTLINE_PUBLIC_KEY)" /root/.ssh/authorized_keys; echo "$?")" = "1" ]; then
    echo $INPUTLINE_PUBLIC_KEY >> /root/.ssh/authorized_keys
    service sshd restart >/dev/null
    echo
    msg "Adding SSH Public Key to PVE host..."
    info "Success. The SSH Public Key has been added to PVE host ${PVE_HOSTNAME,,}\nauthorized_keys file."
    msg "==========   SSH KEYS FOR PVE HOST : ${PVE_HOSTNAME^^}   ==========\n\nFor root access to PVE host ${PVE_HOSTNAME,,} use the SSH Private key pair.\n\nLogin credentials are:\n    Username: ${YELLOW}root${NC}\n    Password: Only the System Administrator knows (SSH Private Key only).\n    SSH Private Key: The must already have it.\n    PVE Server LAN IP Address: ${YELLOW}$(hostname -I)${NC}"
    echo
    break
  fi
  done
fi
  
# Generate a new set of SSH RSA Key pairs
if [ $SSH_TYPE = "TYPE02" ]; then
  section "Generate SSH Key pair files."
  echo
  if [[ $(df -h | awk 'NR>1 { print $1, "mounted on", $NF }' | grep "/mnt/pve/.*backup") ]]; then
    msg "--  BACKUP LOCATION OF SSH PUBLIC KEY FILES
        NAS file location: ${WHITE}"$(df -h | awk 'NR>1 { print $1, $NF }' | grep "/mnt/pve/.*backup" | awk '{ print $1}')/${PVE_HOSTNAME,,}"_ssh_keys.tar.gz${NC}
        PVE file location: ${WHITE}$(df -h | awk 'NR>1 { print $1, $NF }' | grep "/mnt/pve/.*backup" | awk '{ print $NF}')/"${PVE_HOSTNAME,,}"_ssh_keys.tar.gz${NC}"
    echo
    # Backup Location
    SSH_BACKUP_LOCATION=$(df -h | awk 'NR>1 { print $1, $NF }' | grep "/mnt/pve/.*backup" | awk '{ print $NF}')/pve/ssh_keys
    SSH_BACKUP_FILENAME="${PVE_HOSTNAME,,}"_ssh_keys.tar.gz
  elif [[ ! $(df -h | awk 'NR>1 { print $1, "mounted on", $NF }' | grep "/mnt/pve/.*backup") ]]; then
    msg "--  BACKUP LOCATION OF SSH PUBLIC KEY FILES
        Cannot locate a NAS NFS/CIFS backup folder mount point on PVE host '${HOSTNAME}'. Using PVE host '${HOSTNAME}' /tmp folder instead. The User should immediately move the backup '${PVE_HOSTNAME,,}_ssh_keys.tar.gz' to a secure storage location off the PVE host.
        Temporary PVE File Location: ${WHITE}/tmp/"${PVE_HOSTNAME,,}"_ssh_keys.tar.gz${NC}"
    echo
    # Backup Location
    SSH_BACKUP_LOCATION=/tmp
    SSH_BACKUP_FILENAME="${PVE_HOSTNAME,,}"_ssh_keys.tar.gz
  fi
  echo
  
  # Check SMTP server status
  msg "Checking PVE host SMTP email server status..."
  EMAIL_RECIPIENT=$(pveum user list | awk -F " │ " '$1 ~ /root@pam/' | awk -F " │ " '{ print $3 }')
  if [ ${SMTP_STATUS} = 0 ]; then
    info "SMTP email status: ${YELLOW}enabled${NC}.\nThe Users SSH key pairs will be sent to: ${YELLOW}${EMAIL_RECIPIENT}${NC}"
    echo
  elif [ ${SMTP_STATUS} = 1 ]; then
    SMTP_STATUS=1
    info "The PVE host SMTP is not configured or working.\nNo SSH key pairs will be sent by email."
    echo
  fi

  # uuencode for Postfix (part of package sharutils)
  if [ ${SMTP_STATUS} = 0 ]; then
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
  ssh-keygen -o -q -t ed25519 -a 100 -f id_${PVE_HOSTNAME,,}_ed25519 -N ""
  # Create ppk key for Putty or Filezilla or ProFTPd
  msg "Creating a private PPK key (for Putty)..."
  puttygen id_${PVE_HOSTNAME,,}_ed25519 -o id_${PVE_HOSTNAME,,}_ed25519.ppk
  msg "Adding SSH Public Key to PVE host..."
  cat id_${PVE_HOSTNAME,,}_ed25519.pub >> /root/.ssh/authorized_keys
  msg "Creating backup ${WHITE}${SSH_BACKUP_FILENAME}${NC} file of SSH key pairs{..."
  tar czf ${SS}H_BACKUP_FILENAME} id_${PVE_HOSTNAME,,}_ed25519 id_${PVE_HOSTNAME,,}_ed25519.pub id_${PVE_HOSTNAME,,}_ed25519.ppk
  mkdir -p ${SSH_BACKUP_LOCATION} >/dev/null
  cp ${SSH_BACKUP_FILENAME} ${SSH_BACKUP_LOCATION}

  # Email SSH key pairs
  if [ ${SMTP_STATUS} = 0 ]; then
    msg "Emailing SSH key pairs..."
    echo -e "\n==========   SSH KEYS FOR PVE HOST : ${PVE_HOSTNAME^^}   ==========\n\nFor root access to PVE host ${PVE_HOSTNAME,,} use the attached SSH Private Key file named id_${PVE_HOSTNAME,,}_ed25519.\n\nYour login credentials details are:\n    Username: root\n    Password: Not Required (SSH Private Key only).\n    SSH Private Key: id_${PVE_HOSTNAME,,}_ed25519\n    Putty SSH Private Key: id_${PVE_HOSTNAME,,}_ed25519.ppk\n    PVE Server LAN IP Address: $(hostname -I)\n\nA backup linux tar.gz file containing your SSH Key pairs is also attached.\n    Backup filename of SSH Key Pairs: $SSH_BACKUP_FILENAME\n" | (cat - && uuencode id_${PVE_HOSTNAME,,}_ed25519 id_${PVE_HOSTNAME,,}_ed25519 ; uuencode id_${PVE_HOSTNAME,,}_ed25519.pub id_${PVE_HOSTNAME,,}_ed25519.pub ; uuencode ${SSH_BACKUP_FILENAME} $SSH_BACKUP_FILENAME) | mail -s "SHH key pairs for PVE host $(echo ${SSH_BACKUP_FILENAME} | awk -F'_' '{ print $1}')." -- $EMAIL_RECIPIENT
    info "SSH key pairs to emailed to: ${YELLOW}$EMAIL_RECIPIENT${NC}"
    echo
  fi

  # Closing Message
  if [ ${SMTP_STATUS} = 0 ]; then
    info "Success. Your new SSH Public Key has been added to PVE host ${PVE_HOSTNAME,,}\nauthorized_keys file.\n\n==========   SSH KEYS FOR PVE HOST : ${PVE_HOSTNAME^^}   ==========\n\nFor root access to PVE host ${PVE_HOSTNAME,,} use SSH Private Key\nfile named id_${PVE_HOSTNAME,,}_ed25519.\n\nYour login credentials details are:\n    Username: ${YELLOW}root${NC}\n    Password: Not Required (SSH Private Key only).\n    SSH Private Key: ${YELLOW}id_${PVE_HOSTNAME,,}_ed25519${NC}\n    Putty SSH Private Key: ${YELLOW}id_${PVE_HOSTNAME,,}_ed25519.ppk${NC}\n    PVE Server LAN IP Address: ${YELLOW}$(hostname -I)${NC}\n\nA backup linux tar.gz file containing your SSH Key {pairs has also been} created.\n    Backup filename of SSH Key Pairs: ${YELLOW}$SSH_BACKUP_FILENAME${NC}\n    Backup of SSH Key Pairs emailed to: ${YELLOW}$EMAIL_RECIPIENT${NC}\n    Backup location for SSH Key Pairs: ${YELLOW}${SSH_BACKUP_LOCATION}/$SSH_BACKUP_FILENAME${NC}"
    echo
  elif [ ${SMTP_STATUS} = 1 ]; then
    info "Success. Your new SSH Public Key has been added to PVE host ${PVE_HOSTNAME,,}\nauthorized_keys file.\n\n==========   SSH KEYS FOR PVE HOST : ${PVE_HOSTNAME^^}   ==========\n\nFor root access to PVE host ${PVE_HOSTNAME,,} use SSH Private Key\nfile named id_${PVE_HOSTNAME,,}_ed25519.\n\nYour login credentials details are:\n    Username: ${YELLOW}root${NC}\n    Password: Not Required (SSH Private Key only).\n    SSH Private Key: ${YELLOW}id_${PVE_HOSTNAME,,}_ed25519${NC}\n    Putty SSH Private Key: ${YELLOW}id_${PVE_HOSTNAME,,}_ed25519.ppk${NC}\n    PVE Server LAN IP Address: ${YELLOW}$(hostname -I)${NC}\n\nA backup linux tar.gz file containing your SSH Key pairs has also been created.\n    Backup filename of SSH Key Pairs: ${YELLOW}$SSH_BACKUP_FILENAME${NC}\n    Backup location for SSH Key Pairs: ${YELLOW}${SSH_BACKUP_LOCATION}/$SSH_BACKUP_FILENAME${NC}"
    echo
  fi
fi


#---- Configuring SSH Security
section "Proxmox SSHD security modifications"

msg "Minimizing vulnerabilities in the Secure Shell (SSH) protocol is key to ensuring the security of the PVE OS environment. The System Administrator can select from two preset measures to make PVE host '${HOSTNAME^}' more secure."

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
  trap cleanup
fi