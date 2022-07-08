#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_setup_fullbuild.sh
# Description:  Full suite of updates for new Proxmox (PVE) Host machines
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------

#bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-setup/master/scripts/pve_host_setup_fullbuild.sh)"

#---- Source -----------------------------------------------------------------------
#---- Dependencies -----------------------------------------------------------------
#---- Static Variables -------------------------------------------------------------

# Host IP
PVE_HOST_IP=$(hostname -i)

#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------

#---- Introduction
section "Introduction."

msg_box "#### PLEASE READ CAREFULLY - INTRODUCTION ####\n
This script is ideal for setting up and configuring new PVE hosts. User input is required. The script will create, edit and/or change system files on PVE host '${HOSTNAME^}'. When an optional default setting is offered the User can accept this default value (Recommended) simply by pressing ENTER on the keyboard. Or overwrite any default value by typing in your own value and then pressing ENTER to accept and to continue to the next step.

Optional tasks to be performed include:

      PREREQUISITES BASICS
  --  Set Proxmox subscription status
  --  Install Nbtscan SW
  --  Adjust sysctl parameters
  --  PVE Container Mapping ( A must if you want to use any of our PVE VM or CT builds )

      NETWORK
  --  Configure a PVE host network interface card (NIC)
  --  Set PVE IPv4 address
  --  Set PVE hostname

      PVE STORAGE MOUNTS ( Primary PVE Hosts only )
  --  Create NFS and/or CIFS backend storage pools for the PVE hosts.

      SMTP EMAIL ALERTS
  --  Configure PVE host email alerts

      SSH KEYS
  --  Create a root user ssh key
  --  Enable SSH only access ( optional )

      FAIL2BAN
  --  Install and configure Fail2Ban.

Upon completion the PVE host will require a reboot."

echo
while true; do
  read -p "Proceed to setup PVE host '${HOSTNAME^^}' [y/n]?: " -n 1 -r YN
  echo
  case $YN in
    [Yy]*)
      info "The User has chosen to proceed."
      echo
      break
      ;;
    [Nn]*)
      info "You have chosen to skip this step."
      echo
      return
      ;;
    *)
      warn "Error! Entry must be 'y' or 'n'. Try again..."
      echo
      ;;
  esac
done

#---- Run setup basics
source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_setup_basic.sh

#---- Run setup hostname
source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_setup_hostname.sh

#---- Run setup network
source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_setup_network.sh

#---- Run setup NFS storage mount
if [ ${PVE_TYPE} = 1 ]; then
  source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_add_nfs_mounts.sh
fi
#---- Run setup SMB/CIFS storage mount
if [ ${PVE_TYPE} = 1 ]; then
  source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_add_cifs_mounts.sh
fi

#---- Run setup Postfix & Email alerts
if [ ${PVE_TYPE} = 1 ]; then
  source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_setup_postfix.sh
fi
#---- Run setup Install SSH keys
if [ ${PVE_TYPE} = 1 ]; then
  source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_setup_sshkey.sh
fi
#---- Run setup Fail2ban
source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_setup_fail2ban.sh

#---- Apply Hostname change ( if required )
if [ "${PVE_HOSTNAME}" != "$HOSTNAME" ]; then
  source ${REPO_TEMP}/${GIT_REPO}/src/pve_host_setup_hostnameupdate.sh
fi


#---- Finish Status
section "Completion Status."
if [ ${PVE_NET} == 1 ] && [ "${PVE_HOSTNAME}" != "echo $HOSTNAME" ] || [ "${PVE_HOST_IP}" != "`hostname -i`/$(ip addr show |grep -w inet |grep -v 127.0.0.1|awk '{ print $2}'| cut -d "/" -f 2)" ]; then
  # New hostname, IP address
  msg "Success. Your PVE host is nearly ready. Because your PVE host is scheduled for a change in hostname and/or ethernet IP address this host requires a reboot. On reboot this SSH connection will be lost.\n\nTo reconnect a SSH connection your login credentials are:\n    Username: ${YELLOW}root${NC}\n$(if [[ $(cat /etc/ssh/sshd_config | grep "^PasswordAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PubkeyAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PermitRootLogin prohibit-password") ]]; then echo "    SSH security method: ${YELLOW}SSH private key only.${NC}\n    SSH Private Key: ${YELLOW}You must have it.${NC}\n    Password: ${YELLOW}Not Permitted${NC} (SSH Private Key only).";elif [[ $(cat /etc/ssh/sshd_config | grep "^PasswordAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PubkeyAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PermitRootLogin yes") ]]; then echo "    SSH security method: ${YELLOW}SSH private key & Password.${NC}\n    SSH Private Key: ${YELLOW}You must have it.${NC}\n    Password: ${YELLOW}You must have it.${NC}";elif [[ $(cat /etc/ssh/sshd_config | grep "^PasswordAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PubkeyAuthentication no") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PermitRootLogin yes") ]]; then echo "    SSH security method: ${YELLOW}Password only.${NC}";else echo "    Password: ${YELLOW}You must have it.${NC}";fi)\n    PVE Host LAN IP Address: ${YELLOW}$(echo "${PVE_HOST_IP}" | sed  's/\/.*//g')${NC}\n    Terminal SSH CLI command: ${YELLOW}ssh root@$(echo "${PVE_HOST_IP}" | sed  's/\/.*//g')${NC}\n\nPVE web interface URL is: ${YELLOW}https://$(echo "${PVE_HOST_IP}" | sed  's/\/.*//g'):8006${NC}\n    Default login username: ${YELLOW}root${NC}\n    Password: ${YELLOW}You must have it.${NC}\n\nThe root password is what you specified during the PVE installation process."
  echo
  msg "If after rebooting the User has connection issues check the ethernet LAN cable is connected to correct PVE hardware NIC(s). You may have re-assigned PVE default LAN vmbr0 to a different hardware NIC during this setup. A backup copy of the previous network configuration is stored here: /etc/network/interfaces.old"
  echo
  msg "It is recommended the User immediately performs a reboot. If you choose NOT to reboot now remember you ${UNDERLINE}must at a later stage${NC}."
  echo
  while true; do
    read -p "Reboot PVE host now ( RECOMMENDED ) [y/n]?: "  -n 1 -r YN
    echo
    case $YN in
      [Yy]*)
        REBOOT_NOW=0
        msg "Performing a reboot in 3 seconds...\n(your ssh connection will be lost)"
        echo
        break
        ;;
      [Nn]*)
        REBOOT_NOW=1
        info "You have chosen NOT to perform a PVE system reboot. Remember you MUST perform a system reboot at some stage to invoke the changes!"
        echo
        break
        ;;
      *)
        warn "Error! Entry must be 'y' or 'n'. Try again..."
        echo
        ;;
    esac
  done
elif [ ${PVE_NET} == 2 ]; then
  # Same hostname, IP address
  msg "Success. The PVE host is nearly ready. To make a SSH connection your login credentials are:\n    Username: ${YELLOW}root${NC}\n$(if [[ $(cat /etc/ssh/sshd_config | grep "^PasswordAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PubkeyAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PermitRootLogin prohibit-password") ]]; then echo "    SSH security method: ${YELLOW}SSH private key only.${NC}\n    SSH Private Key: ${YELLOW}You must have it.${NC}\n    Password: ${YELLOW}Not Permitted${NC} (SSH Private Key only).";elif [[ $(cat /etc/ssh/sshd_config | grep "^PasswordAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PubkeyAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PermitRootLogin yes") ]]; then echo "    SSH security method: ${YELLOW}SSH private key & Password.${NC}\n    SSH Private Key: ${YELLOW}You must have it.${NC}\n    Password: ${YELLOW}You must have it.${NC}";elif [[ $(cat /etc/ssh/sshd_config | grep "^PasswordAuthentication yes") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PubkeyAuthentication no") ]] && [[ $(cat /etc/ssh/sshd_config | grep "^PermitRootLogin yes") ]]; then echo "    SSH security method: ${YELLOW}Password only.${NC}";fi)\n    PVE Server LAN IP Address: ${YELLOW}`hostname -i`${NC}\n    Terminal SSH CLI command: ${YELLOW}ssh root@`hostname -i`${NC}\n\nPVE web interface URL is: ${YELLOW}https://`hostname -i`:8006${NC}\n    Default login username: ${YELLOW}root${NC}\n    Password: ${YELLOW}You must have it.${NC}\nThe root user password is what you specified during the PVE installation process.\n\n$(if [ $SETUP_SSHKEY=0 ]; then echo "To finish we need to restart some system services.\n    Restarting service: ${YELLOW}SSHd${NC}";service sshd restart >/dev/null 2>&1;fi)"
  echo
fi

#---- Finish Line ------------------------------------------------------------------

# Cleanup
if [ ${REBOOT_NOW} == 0 ]; then
  # Cleanup
  rm -R /tmp/common &> /dev/null
  rm -R /tmp/pve-host-setup &> /dev/null
  rm /tmp/common.tar.gz &> /dev/null
  rm /tmp/pve-host-setup.tar.gz &> /dev/null

  msg "The connection is about to terminated. This is a scheduled reboot in 2 seconds..."
  sleep 2
  nohup reboot &> /tmp/nohup.out </dev/null & trap cleanup EXIT
fi