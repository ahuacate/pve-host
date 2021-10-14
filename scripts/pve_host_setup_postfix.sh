#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_setup_postfix.sh
# Description:  Source script for PVE Host Postfix setup
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------

# bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-setup/master/scripts/pve_host_setup_postfix.sh)"

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

# Check IP
ipvalid () {
  # Set up local variables
  local ip=${1:-1.2.3.4}
  local IFS=.; local -a a=($ip)
  # Start with a regex format test
  [[ $ip =~ ^[0-9]+(\.[0-9]+){3}$ ]] || return 1
  # Test values of quads
  local quad
  for quad in {0..3}; do
    [[ "${a[$quad]}" -gt 255 ]] && return 1
  done
  return 0
}

#---- Static Variables -------------------------------------------------------------

# Easy Script Section Header Body Text
SECTION_HEAD='PVE Host Postfix Setup'

# Check for PVE Hostname mod
if [ -z "${HOSTNAME_FIX+x}" ]; then
  PVE_HOSTNAME=$HOSTNAME
fi

#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------

#---- Install and Configure SSMTP Email Alerts

section "Introduction"

msg_box "#### PLEASE READ CAREFULLY - POSTFIX & EMAIL ALERTS ####\n
Send email alerts about your PVE host to the systems designated administrator. Be alerted about unwarranted login attempts and other system critical alerts. Proxmox is preinstalled with Postfix SMTP server which we use for sending your PVE nodes critical alerts.

SMTP is a simple Mail Transfer Agent (MTA) while easy to setup it requires the following prerequisites and credentials:

  --  SMTP SERVER
      You require a SMTP server that can receive the emails from your machine and send them to the designated administrator. If you use Gmail SMTP server its best to enable 'App Passwords'. An 'App Password' is a 16-digit passcode that gives an app or device permission to access your Google Account. Or you can use a mailgun.com flex account relay server (Recommended).
      
  --  REQUIRED SMTP SERVER CREDENTIALS
      1. Designated administrator email address (i.e your working admin email address)

      2. SMTP server address (i.e smtp.gmail.com or smtp.mailgun.org)

      3. SMTP server port (i.e gmail port is 587 and mailgun port is 587)

      4. SMTP server username (i.e MyEmailAddress@gmail.com or postmaster@sandboxa6ac6.mailgun.org)
  
      5. SMTP server default password (i.e your Gmail App Password or mailgun SMTP password)

If you choose to proceed have your SMTP server credentials available. This script will configure your PVE nodes Postfix SMTP server."
echo
while true; do
  read -p "Install and configure Postfix and email alerts( Recommended ) [y/n]?: " -n 1 -r YN
  echo
  case $YN in
    [Yy]*)
      while true; do
        read -p "Do you have your GMail, MailGun or Custom SMTP Server credentials ready [y/n]?: " -n 1 -r YN
        echo
        case $YN in
          [Yy]*)
            info "The User has chosen to proceed."
            echo
            break 2
            ;;
          [Nn]*)
            warn "In the next steps you must have your 16 digit GMail App Password OR MailGun\n OR custom SMTP server credentials ready for input to continue.\nTry again..."
            echo
            break
            ;;
          *)
            warn "Error! Entry must be 'y' or 'n'. Try again..."
            echo
            ;;
        esac
      done
      ;;
    [Nn]*)
      info "You have chosen to skip this step."
      echo
      exit 0
      break
      ;;
    *)
      warn "Error! Entry must be 'y' or 'n'. Try again..."
      echo
      ;;
  esac
done


#---- Checking PVE Host Prerequisites
section "Checking Prerequisites"

# libsasl2-modules for Postfix
if [ $(dpkg -s libsasl2-modules >/dev/null 2>&1; echo $?) = 0 ]; then
  msg "Checking libsasl2-modules status..."
  info "libsasl2-modules status: ${GREEN}installed.${NC}"
  echo
else
  msg "Installing libsasl2-modules..."
  apt-get install -y libsasl2-modules >/dev/null
  if [ $(dpkg -s libsasl2-modules >/dev/null 2>&1; echo $?) = 0 ]; then
    info "libsasl2-modules status: ${GREEN}installed.${NC}"
  fi
  echo
fi

# postfix-pcre for Postfix
if [ $(dpkg -s postfix-pcre >/dev/null 2>&1; echo $?) = 0 ]; then
  msg "Checking postfix-pcre status..."
  info "postfix-pcre status: ${GREEN}installed.${NC}"
  echo
else
  msg "Installing postfix-pcre..."
  apt-get install -y postfix-pcre >/dev/null
  if [ $(dpkg -s postfix-pcre >/dev/null 2>&1; echo $?) = 0 ]; then
    info "postfix-pcre status: ${GREEN}installed.${NC}"
  fi
  echo
fi

# uuencode for Postfix (part of package sharutils)
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

#---- Setting PVE Postfix Variables
while true; do
  section "Setting Postfix Variables"

  # VAR for the script
  POSTFIX_CONFIG=/etc/postfix/main.cf
  POSTFIX_SASL_PWD=/etc/postfix/sasl_passwd
  POSTFIX_SASL_DB=/etc/postfix/sasl_passwd.db

  # Set PVE SMTP Server Type
  while true; do
    TYPE01="${YELLOW}Mailgun${NC} - Configure for a Mailgun SMTP server."
    TYPE02="${YELLOW}GMail${NC} - Configure for a GMail SMTP server."
    TYPE03="${YELLOW}Other${NC} - Custom SMTP server configuration."
    PS3="Select the SMTP server type you use (entering numeric) : "
    msg "Available options:"
    options=("$TYPE01" "$TYPE02" "$TYPE03")
    select menu in "${options[@]}"; do
      case $menu in
        "$TYPE01")
          info "SMTP server is set as: $(echo $menu | awk '{print $1}')"
          SMTP_TYPE=mailgun
          SMTP_SERVER_ADDRESS="smtp.mailgun.org"
          SMTP_SERVER_PORT=587
          echo
          break
          ;;
        "$TYPE02")
          info "SMTP server is set as: $(echo $menu | awk '{print $1}')"
          SMTP_TYPE=gmail
          SMTP_SERVER_ADDRESS="smtp.gmail.com"
          SMTP_SERVER_PORT=587
          echo
          break
          ;;
        "$TYPE03")
          SMTP_TYPE=custom
          # while true; do
          read -p "Enter SMTP Server address (i.e smtp.hello.com): " -e SMTP_SERVER_ADDRESS
          read -p "Enter SMTP Server port number: " -e -i 587 SMTP_SERVER_PORT
          read -p "Accept SMTP server address: ${WHITE}${SMTP_SERVER_ADDRESS}${NC}:${WHITE}${SMTP_SERVER_PORT}${NC} [y/n]?: " -n 1 -r
          echo
          if [[ $REPLY =~ ^[Yy]$ ]]; then
            msg "Accepted. Now validating address."
            echo
            break
          else
            echo
            msg "Try again..."
            continue
          fi
          # done
          ;;
        *) warn "Invalid entry. Try again.." >&2
      esac
    done


    # Validating SMTP Server Address
    ip=${SMTP_SERVER_ADDRESS}
    if ipvalid "$ip"; then
      msg "Validating SMTP IPv4 address..."
      if [ $(ping -s 1 -c 2 "$(echo "${SMTP_SERVER_ADDRESS}")" >/dev/null; echo $?) = 0 ] || [ $(nc -z -w 5 ${SMTP_SERVER_ADDRESS} ${SMTP_SERVER_PORT} 2>/dev/null; echo $?) = 0 ]; then
        info "SMTP server address is set as: ${YELLOW}${SMTP_SERVER_ADDRESS}${NC}:${YELLOW}${SMTP_SERVER_PORT}${NC}"
        echo
        break
      elif [ $(ping -s 1 -c 2 "$(echo "${SMTP_SERVER_ADDRESS}")" >/dev/null; echo $?) != 0 ] || [ $(nc -z -w 5 ${SMTP_SERVER_ADDRESS} ${SMTP_SERVER_PORT} 2>/dev/null; echo $?) != 0 ]; then
        warn "There are problems with your input:\n1. Your IP address meets the IPv4 standard, BUT\n2. Your IP address $(echo "${SMTP_SERVER_ADDRESS}") is not reachable.\nCheck your SMTP server IP address, port number and firewall settings.\nTry again..."
        echo
      fi
    else
      msg "Validating SMTP url address..."
      if [ $(ping -s 1 -c 2 "$(echo "${SMTP_SERVER_ADDRESS}")" >/dev/null; echo $?) = 0 ] || [ $(nc -z -w 5 ${SMTP_SERVER_ADDRESS} ${SMTP_SERVER_PORT} 2>/dev/null; echo $?) = 0 ]; then
        info "SMTP server address is set as: ${YELLOW}${SMTP_SERVER_ADDRESS}${NC}:${YELLOW}${SMTP_SERVER_PORT}${NC}"
        echo
        break
      elif [ $(ping -s 1 -c 2 "$(echo "${SMTP_SERVER_ADDRESS}")" >/dev/null; echo $?) != 0 ] || [ $(nc -z -w 5 ${SMTP_SERVER_ADDRESS} ${SMTP_SERVER_PORT} 2>/dev/null; echo $?) != 0 ]; then
        warn "There are problems with your input:\n1. The URL $(echo "${SMTP_SERVER_ADDRESS}") is not reachable.\nCheck your SMTP server URL address, port number and firewall settings.\nTry again..."
        echo
      fi
    fi
  done

  # Set SMTP Credentials
  while true; do
    read -p "Enter your ${SMTP_TYPE,,} SMTP server login username: " -e SMTP_USERNAME
    read -p "Enter your ${SMTP_TYPE,,} SMTP server password: " -e SMTP_PWD
    echo
    info "Your ${SMTP_TYPE,,} SMTP server credentials are:\nUsername: ${YELLOW}${SMTP_USERNAME}${NC}\nPassword: ${YELLOW}${SMTP_PWD}${NC}"
    read -p "Accept ${SMTP_TYPE,,} SMTP server credentials:  [y/n]? " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      info "SMTP server login credentials are set : ${GREEN}OK${NC}"
      echo
      break
    else
      msg "Try again..."
      echo
    fi
  done

  # Set PVE root administrator email address
  PVE_ROOT_EMAIL_OLD=$(pveum user list | awk -F " │ " '$1 ~ /root@pam/' | awk -F " │ " '{ print $3 }')
  msg "Validate your PVE root or system email address..."
  msg "Your PVE root user email address is ${WHITE}${PVE_ROOT_EMAIL_OLD}${NC}. This email address is set to send all PVE system notifications and alerts. In the next steps you have the option to accept or change your default PVE root email address."
  read -p "Accept PVE root email address ${WHITE}${PVE_ROOT_EMAIL_OLD}${NC} [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    PVE_ROOT_EMAIL=${PVE_ROOT_EMAIL_OLD}
    info "PVE root email address remains unchanged: ${YELLOW}${PVE_ROOT_EMAIL}${NC}."
    echo
  else
    while true; do
      read -p "Enter a valid PVE root email address: " -e -i ${PVE_ROOT_EMAIL_OLD} PVE_ROOT_EMAIL
      echo
      if [[ "${PVE_ROOT_EMAIL}" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$ ]]; then
        pveum user modify root@pam -email ${PVE_ROOT_EMAIL}
        msg "Email address ${PVE_ROOT_EMAIL} is valid."
        info "PVE root email address is set: ${YELLOW}${PVE_ROOT_EMAIL}${NC}."
        echo
        break
      else
        msg "Email address ${PVE_ROOT_EMAIL} is invalid."
        warn "There are problems with your input:\n1. Email address $(echo "${PVE_ROOT_EMAIL}") does not pass the validity check.\nTry again..."
        echo
      fi
    done
  fi


  #---- Configuring PVE Postfix
  section "Configuring PVE Postfix"

  # Creating /etc/postfix/sasl_passwd
  msg "Creating /etc/postfix/sasl_passwd..."
  echo [${SMTP_SERVER_ADDRESS,,}]:${SMTP_SERVER_PORT} ${SMTP_USERNAME}:${SMTP_PWD} > ${POSTFIX_SASL_PWD}
  # Generate a .db file
  if [ -f "${POSTFIX_SASL_DB}" ]; then
    rm ${POSTFIX_SASL_DB} >/dev/null
  fi
  postmap hash:${POSTFIX_SASL_PWD}
  chmod 600 ${POSTFIX_SASL_PWD} ${POSTFIX_SASL_DB}

  # Modify Postfix configuration file /etc/postfix/main.cf
  if [ ${SMTP_TYPE} = "gmail" ]; then
    msg "Configuring Postfix for a ${SMTP_TYPE^} server..."
    # Gmail
    # Specify SMTP relay host
    postconf -e relayhost=[${SMTP_SERVER_ADDRESS,,}]:${SMTP_SERVER_PORT}
    # Enable  STARTTLS encryption
    postconf -e smtp_use_tls=yes
    # Enable SASL authentication
    postconf -e smtp_sasl_auth_enable=yes
    # Disallow methods that allow anonymous authentication
    postconf -e smtp_sasl_security_options=noanonymous
    # Required for authentication to prevent the FROMTO error
    postconf -e smtp_sasl_security_options=
    # Location of smtp credentials
    postconf -e smtp_sasl_password_maps=hash:/etc/postfix/sasl_passwd
    # Location of CA certificates
    postconf -e smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt
    # Stop Spambots - restrict the use of the mail relay to your local network and the SASL-authorized users that you defined earlier.
    postconf -e smtpd_relay_restrictions='permit_mynetworks permit_sasl_authenticated defer_unauth_destination'
    # Customize From instead of Root
    postconf -e smtp_header_checks=pcre:/etc/postfix/smtp_header_checks
    # Other
    postconf -e smtp_tls_session_cache_database=btree:/var/lib/postfix/smtp_tls_session_cache
    postconf -e smtp_tls_session_cache_timeout=3600s
    echo
  elif [ ${SMTP_TYPE} = "mailgun" ]; then
    msg "Configuring Postfix for a ${SMTP_TYPE^} server..."
    # Mailgun
    # Specify SMTP relay host
    postconf -e relayhost=[${SMTP_SERVER_ADDRESS,,}]:${SMTP_SERVER_PORT}
    # Enable  STARTTLS encryption
    postconf -e smtp_use_tls=yes
    # Enable SASL authentication
    postconf -e smtp_sasl_auth_enable=yes
    # Disallow methods that allow anonymous authentication
    postconf -e smtp_sasl_tls_security_options=noanonymous
    # Required for authentication to prevent the FROMTO error
    postconf -e smtp_sasl_security_options=noanonymous
    # Location of smtp credentials
    postconf -e smtp_sasl_password_maps=hash:/etc/postfix/sasl_passwd
    # Location of CA certificates
    postconf -e smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt
    # Stop Spambots - restrict the use of the mail relay to your local network and the SASL-authorized users that you defined earlier.
    postconf -e smtpd_relay_restrictions='permit_mynetworks permit_sasl_authenticated defer_unauth_destination'
    # Other
    postconf -e smtp_tls_session_cache_database=btree:/var/lib/postfix/smtp_tls_session_cache
    postconf -e smtp_tls_session_cache_timeout=3600s
    echo
  elif [ ${SMTP_TYPE} = "custom" ]; then
    msg "Configuring Postfix for a ${SMTP_TYPE^} server..."
    # Custom
    # Specify SMTP relay host
    postconf -e relayhost=[${SMTP_SERVER_ADDRESS,,}]:${SMTP_SERVER_PORT}
    # Enable STARTTLS encryption
    read -p "Does your SMTP server support TLS encryption [y/n]?: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      postconf -e smtp_use_tls=yes
      info "Postfix SMTP TLS support: ${YELLOW}Enabled${NC}."
      echo
    else
      postconf -e smtp_use_tls=
      info "Postfix SMTP TLS support: ${YELLOW}Disabled${NC}."
      echo
    fi
    # Enable SASL authentication
    postconf -e smtp_sasl_auth_enable=yes
    # Disallow methods that allow anonymous authentication
    postconf -e smtp_sasl_tls_security_options=noanonymous
    # Required for authentication to prevent the FROMTO error
    postconf -e smtp_sasl_security_options=
    # Location of smtp credentials
    postconf -e smtp_sasl_password_maps=hash:/etc/postfix/sasl_passwd
    # Location of CA certificates
    postconf -e smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt
    # Stop Spambots - restrict the use of the mail relay to your local network and the SASL-authorized users that you defined earlier.
    postconf -e smtpd_relay_restrictions='permit_mynetworks permit_sasl_authenticated defer_unauth_destination'
    # Other
    postconf -e smtp_tls_session_cache_database=btree:/var/lib/postfix/smtp_tls_session_cache
    postconf -e smtp_tls_session_cache_timeout=3600s
    echo
  fi

  # Customised Email header
  echo /^From:.*/ REPLACE From: "${PVE_HOSTNAME,,}-alert" '<'$(echo ${PVE_ROOT_EMAIL} | sed 's/@.*//')@localdomain'>' > /etc/postfix/smtp_header_checks
  postmap /etc/postfix/smtp_header_checks

  # Reload Postfix configuration file /etc/postfix/main.cf
  service postfix reload

  # Testing Postfix SMTP Server
  echo
  msg_box "#### PLEASE READ CAREFULLY - SMTP & EMAIL TESTING ####\n
  In the next step you have the option to test your SMTP settings by sending a test email to your PVE root or system email address. If you choose to send a test email then:

    --  Check your mailbox to validate your SMTP settings work.

    --  Check the mailbox spam folder and whitelist any test email found there.

    --  If you do not receive a test email then something is wrong with your configuration inputs. You have the option to re-enter your credentials and try again.
    
  If you choose NOT to send a test email then:

    --  SMTP settings are configured but not tested.

    --  All changes must be made manually by the PVE system administrator. (i.e edit  /etc/postfix/main.cf )"
  echo
  read -p "Do you want to send a test email to ${PVE_ROOT_EMAIL} [y/n]?: " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo
    msg "Sending test email to ${PVE_ROOT_EMAIL}..."
    echo -e "\n  To: ${PVE_ROOT_EMAIL}\n  From: "${PVE_HOSTNAME,,}-alert"\n  Subject: Test Postfix\n\n  Hello World.\n\n  Your PVE host Postfix SMTP mail server works.\n  Congratulations.\n"
    echo -e "Hello World.\n\nYour PVE host Postfix SMTP mail server works.\nCongratulations." | mail -s "Test Postfix" ${PVE_ROOT_EMAIL}
    echo
    info "Test email sent to: ${WHITE}${PVE_ROOT_EMAIL}${NC}"
    echo
    msg "Next check for the test email in your mailbox ( ${WHITE}${PVE_ROOT_EMAIL}${NC} ).\nIt will be recieved ${WHITE}From: ${PVE_HOSTNAME,,}-alert${NC}. If you cannot find it\ncheck your Spam, All Mail and whitelist the test email."
    echo
    read -p "Did you receive a PVE test email message in your mailbox [y/n]?: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      info "Success. Your PVE Postfix SMTP server is working."
      # Remove old Ahuacate Check line
      if [[ $(cat /etc/postfix/main.cf | grep "### Ahuacate_Check=.*") ]]; then
        sed -i '/### Ahuacate_Check=.*/d' /etc/postfix/main.cf
      fi
      # Add Ahuacate Check line=0
      echo -e "\n### Ahuacate_Check=0 #### This is a Github Ahuacate script check line only.\n" >> /etc/postfix/main.cf
      break
    else
      read -p "Do you want to re-input your Postfix SMTP credentials (again) [y/n]?: " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        info "You have chosen to re-input your credentials. Try again."
        sleep 2
        echo
        continue
      else
        info "You have chosen to accept your inputs despite them not working.\nSkipping the validation step."
        # Remove old Ahuacate Check line
        if [[ $(cat /etc/postfix/main.cf | grep "### Ahuacate_Check=.*") ]]; then
          sed -i '/### Ahuacate_Check=.*/d' /etc/postfix/main.cf
        fi
        # Add Ahuacate Check line=1
        echo -e "\n### Ahuacate_Check=1 #### This is a Github Ahuacate script check line only.\n" >> /etc/postfix/main.cf
        break
      fi
    fi
  else
    info "You have chosen not to test your Postfix SMTP email server. Skipping the\nvalidation step. SMTP settings are configured but not tested. All changes must\nbe made manually by the PVE system administrator."
    break
  fi
done
echo

# Activate E-Mail Notification & Email Alerts
# zfs-zed SW
if [ $(dpkg -s zfs-zed >/dev/null 2>&1; echo $?) = 0 ]; then
  msg "Checking zfs-zed status..."
  info "zfs-zed status: ${GREEN}active (running).${NC}"
  echo
else
  msg "Installing zfs-zed..."
  apt-get install -y zfs-zed >/dev/null
  if [ $(dpkg -s zfs-zed >/dev/null 2>&1; echo $?) = 0 ]; then
    info "zfs-zed status: ${GREEN}active (running).${NC}"
  fi
  echo
fi
sed -i 's|#ZED_EMAIL_ADDR.*|ZED_EMAIL_ADDR="root"|g' /etc/zfs/zed.d/zed.rc

#---- Finish Line ------------------------------------------------------------------