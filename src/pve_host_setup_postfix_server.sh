#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_setup_postfix_server.sh
# Description:  Source script for PVE Host Postfix setup
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------

# bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host/main/scripts/pve_host_setup_postfix_server.sh)"

#---- Source -----------------------------------------------------------------------
#---- Dependencies -----------------------------------------------------------------

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
SECTION_HEAD='Postfix Server'

# # Check for PVE Hostname mod
# if [ -z "${HOSTNAME_FIX+x}" ]; then
#   PVE_HOSTNAME=$HOSTNAME
# fi

# Local network
LOCAL_NET=$(hostname -I | awk -F'.' -v OFS="." '{ print $1,$2,"0.0/16" }')

# Postfix vars
POSTFIX_CONFIG=/etc/postfix/main.cf
POSTFIX_SASL_PWD=/etc/postfix/sasl_passwd
POSTFIX_SASL_DB=/etc/postfix/sasl_passwd.db

#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------

#---- Install and Configure SSMTP Email

section "Introduction"

# Set display msg
display_conditions_msg1=( "--  SMTP SERVER
    You require a SMTP server that can receive the emails from your machine and send them to the designated administrator. If you use Gmail SMTP server its best to enable 'App Passwords'. An 'App Password' is a 16-digit passcode that gives an app or device permission to access your Google Account. Or you can use a mailgun.com flex account relay server (Recommended).
    
--  REQUIRED SMTP SERVER CREDENTIALS
    1. Designated administrator email address (i.e your working admin email address)

    2. SMTP server address (i.e smtp.gmail.com or smtp.mailgun.org)

    3. SMTP server port (i.e gmail port is 587 and mailgun port is 587)

    4. SMTP server username (i.e MyEmailAddress@gmail.com or postmaster@sandboxa6ac6.mailgun.org)

    5. SMTP server default password (i.e your Gmail App Password or MailGun SMTP password)
    
    6. Only SMTP SSL/TLS ports numbers are accepted" )

msg_box "#### PLEASE READ CAREFULLY - POSTFIX & EMAIL CREDENTIALS ####\n
Send email alerts about your PVE host and VM/CTs to the systems designated administrator. Be alerted about unwarranted login attempts and other system critical alerts.

Use email to send important VM/CT install details such as new user login credentials and SSH keys.

Proxmox is preinstalled with Postfix SMTP server. SMTP is a simple Mail Transfer Agent (MTA) while easy to setup it requires the following prerequisites and credentials:

$(printf '%s\n' "${display_conditions_msg1[@]}" | indent2)

If you choose to proceed have your SMTP server credentials available."
echo
while true; do
  read -p "Install and configure Postfix and email ( Recommended ) [y/n]?: " -n 1 -r YN
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
      info "You have chosen to skip this step. Bye..."
      echo
      return
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



#--- Set PVE root administrator email address
section "PVE root email address"

# Set current root email address
PVE_ROOT_EMAIL_OLD=$(pveum user list | awk -F " │ " '$1 ~ /root@pam/' | awk -F " │ " '{ print $3 }')

msg_box "#### PLEASE READ CAREFULLY - ROOT EMAIL ADDRESS ####\n
Your PVE root email address is '${PVE_ROOT_EMAIL_OLD}'. This email address is set to send all system notifications and alerts. In the next steps you have the option to accept or update your default PVE host root email address."
while true; do
  msg "Validate your PVE root email address..."
  OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE02" "TYPE00" )
  OPTIONS_LABELS_INPUT=( "Accept - '${PVE_ROOT_EMAIL_OLD}' is valid and current" \
  "Update/Edit - I want to update my PVE root email address" \
  "None. Exit this installer")
  makeselect_input2
  singleselect SELECTED "$OPTIONS_STRING"

  if [ ${RESULTS} == 'TYPE01' ]; then
    PVE_ROOT_EMAIL=${PVE_ROOT_EMAIL_OLD}
    break
  elif [ ${RESULTS} == 'TYPE02' ]; then
    # Update PVE root email address
    while true; do
      read -p "Enter a new email address: " -e -i ${PVE_ROOT_EMAIL_OLD} PVE_ROOT_EMAIL
      echo
      read -p "Accept email address '${PVE_ROOT_EMAIL}' [y/n]?: " -n 1 -r
      case $YN in
        [Yy]*)
          # Validate email address
          if [[ ! "${PVE_ROOT_EMAIL}" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$ ]]; then
            FAIL_MSG="There are problems with your input:\n-- '${PVE_ROOT_EMAIL}' does not pass our email validity check\n-- whitespace and/or special characters are not allowed\nTry again..."
            warn "$FAIL_MSG"
            echo
          else
            echo
            break
          fi
          ;;
        [Nn]*)
          msg "No problem. Try again..."
          echo
          ;;
        *)
          warn "Error! Entry must be 'y' or 'n'. Try again..."
          echo
          ;;
      esac
    done
  elif [ ${RESULTS} == 'TYPE00' ]; then
    # Exit installation
    msg "You have chosen not to proceed. Aborting. Bye..."
    echo
    return
  fi
done


#---- Set Postfix SMTP server address
while true; do
  section "Set Postfix SMTP server address"
  
  msg "Select your email SMTP provider..."
  OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE02" "TYPE03" "TYPE00" )
  OPTIONS_LABELS_INPUT=( "MailGun - Configure for a MailGun SMTP server (Recommended)" \
  "GMail - Configure for a GMail SMTP server" \
  "Custom - Custom SMTP server configuration" \
  "None. Exit this installer")
  makeselect_input2
  singleselect SELECTED "$OPTIONS_STRING"

  if [ ${RESULTS} == 'TYPE01' ]; then
    SMTP_HOST_ID=MailGun
    SMTP_SERVER_ADDRESS="smtp.mailgun.org"
    SMTP_SERVER_PORT=587
    SMTP_USE_TLS='yes'
    TLS='enabled'
  elif [ ${RESULTS} == 'TYPE02' ]; then
    SMTP_HOST_ID=GMail
    SMTP_SERVER_ADDRESS="smtp.gmail.com"
    SMTP_SERVER_PORT=587
    SMTP_USE_TLS='yes'
    TLS='enabled'
  elif [ ${RESULTS} == 'TYPE03' ]; then
    SMTP_HOST_ID=custom
    # Input custom smtp server credentials
    while true; do
      # Input address
      read -p "Enter SMTP server address (i.e smtp.hello.com): " -e SMTP_SERVER_ADDRESS
      # Input port
      read -p "Enter SMTP server port number (i.e 465, 587): " -e -i 587 SMTP_SERVER_PORT
      # Input TLS
      read -p "Does your SMTP server support TLS encryption (Recommended) [y/n]?: "  -n 1 -r YN
      echo
      case $YN in
        [Yy]*)
          SMTP_USE_TLS='yes'
          TLS='enabled'
          ;;
        [Nn]*)
          SMTP_USE_TLS=''
          TLS='disabled'
          ;;
        *)
          warn "Error! Entry must be 'y' or 'n'. Try again..."
          echo
          ;;
      esac
      # Confirm settings
      read -p "Confirm your SMTP server settings: ${WHITE}${SMTP_SERVER_ADDRESS}${NC}:${WHITE}${SMTP_SERVER_PORT}${NC} (TLS ${WHITE}${TLS}${NC}) [y/n]?: "  -n 1 -r YN
      echo
      case $YN in
        [Yy]*)
          echo
          break
          ;;
        [Nn]*)
          msg "No problem. Try again..."
          echo
          ;;
        *)
          warn "Error! Entry must be 'y' or 'n'. Try again..."
          echo
          ;;
      esac
    done
  elif [ ${RESULTS} == 'TYPE00' ]; then
    # Exit installation
    msg "You have chosen not to proceed. Aborting. Bye..."
    echo
    return
  fi

  # Check SMTP server address
  FAIL_MSG="The SMTP address is not valid. A SMTP server check failed. A valid SMTP server address is when all of the following constraints are satisfied:\n
  --  passes openssl s_client diagnostics for SSL/TLS
  --  the server responds\n
  Check your SMTP server address and port number. Try again..."
  if [ $(timeout 10 openssl s_client -crlf -verify_quiet -starttls smtp -connect ${SMTP_SERVER_ADDRESS}:${SMTP_SERVER_PORT} &>/dev/null <<< QUIT; echo $?) != 0 ]; then
    warn "$FAIL_MSG"
  else
    break
  fi
done


#---- Set SMTP server account credentials
while true; do
  read -p "Enter your ${SMTP_HOST_ID} SMTP server account username: " -e SMTP_ACC_USERNAME
  read -p "Enter your ${SMTP_HOST_ID} SMTP server account password: " -e SMTP_ACC_PWD
  echo
  info "Your SMTP server credentials are:\nUsername: ${YELLOW}${SMTP_ACC_USERNAME}${NC}\nPassword: ${YELLOW}${SMTP_ACC_PWD}${NC}"
  read -p "Accept SMTP server credentials: [y/n]? " -n 1 -r
  case $YN in
    [Yy]*)
      info "SMTP server account credentials status: ${YELLOW}set${NC}"
      echo
      break
      ;;
    [Nn]*)
      msg "No problem. Try again..."
      echo
      ;;
    *)
      warn "Error! Entry must be 'y' or 'n'. Try again..."
      echo
      ;;
  esac
done


#---- Test email credentials
section "Sending Test email"

msg "Sending test email to '${PVE_ROOT_EMAIL}'..."
# DL Swaks
curl http://www.jetmore.org/john/code/swaks/files/swaks-20130209.0/swaks -o swaks
# Set script permissions
chmod +x swaks
# Install perl
apt-get install perl -y
# Run test email
./swaks --auth --silent 3 \
	--server ${SMTP_SERVER_ADDRESS}:${SMTP_SERVER_PORT} \
	--au ${SMTP_ACC_USERNAME} \
	--ap ${SMTP_ACC_PWD} \
	--to ${PVE_ROOT_EMAIL} \
  --from $(hostname)@$(hostname).$(hostname -d) \
	--h-Subject: "SMTP credential test." \
	--body 'Success! Proxmox awesomness.'

# Send status
SWAKS_EXIT_CODE=$?
if [ "${SWAKS_EXIT_CODE}" != 0 ]; then
  # Swaks fail
  info "Email send status: ${RED}fail${NC} (Swaks error code ${SWAKS_EXIT_CODE})"
  echo
  display_msg1=()
  display_msg1=( "The test email could not be sent for various reasons (Swaks error code ${SWAKS_EXIT_CODE}).\n\nAnyway, check your '${PVE_ROOT_EMAIL}' mailbox for our test email in case it was delivered. If the test email doesn't appear in your inbox:\n\n  --  check your mailbox spam folder\n  --  check your junk folder\n  --  whitelist any test email\n  --  check your input credentials" )
else
  # Swaks pass
  info "Email send status: ${GREEN}pass${NC}"
  echo
  display_msg1=()
  display_msg1=( "The test email has been successfully sent. Delivery speed is determined by your email service provider so be patient (normal delivery is within 1-2 minutes or less).\n\nCheck your '${PVE_ROOT_EMAIL}' mailbox for our test email. If the test email doesn't appear in your inbox:\n\n  --  check your mailbox spam folder\n  --  check your junk folder\n  --  whitelist any test email" )
fi
display_msg2=()
display_msg2=( "From:$(hostname)@$(hostname).$(hostname -d)" \
"Subject:SMTP credential test." )

msg_box "#### PLEASE READ CAREFULLY - TEST EMAIL ####

$(printf '%s\n' "${display_msg1[@]}")

The test email details are:

$(printf '%s\n' "${display_msg2[@]}" | column -s ":" -t | indent2)"

# Confirm test email delivery
msg "Confirm test email delivery..."
OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE00" )
OPTIONS_LABELS_INPUT=( "Yes - I received the test email" \
"No, Nothing, Zilch - No test email was delivered")
makeselect_input2
singleselect SELECTED "$OPTIONS_STRING"

if [ ${RESULTS} == 'TYPE01' ]; then
  info "SMTP server status: ${GREEN}ok${NC}"
elif [ ${RESULTS} == 'TYPE00' ]; then
  # Exit installation
  msg "Oops. Something must be wrong with your SMTP account and/or user credentials. Check the following prerequisites and credentials:\n\n$(printf '%s\n' "${display_conditions_msg1[@]}" | indent2)\n\nFix the problem and run our PVE Toolbox SSMTP option. Aborting. Bye..."
  echo
  return
fi

#-----------------------------------------------------------------------------------
# Do not edit below this point.

#---- Configure Postfix SMTP service

# Create /etc/postfix/sasl_passwd
echo "[${SMTP_SERVER_ADDRESS,,}]:${SMTP_SERVER_PORT} ${SMTP_ACC_USERNAME}:${SMTP_ACC_PWD}" > ${POSTFIX_SASL_PWD}
# Create HASH
postmap hash:${POSTFIX_SASL_PWD}
# Set file permissions
chmod 600 ${POSTFIX_SASL_PWD} ${POSTFIX_SASL_DB}


# Server specific configure Postfix configuration file /etc/postfix/main.cf
if [ ${SMTP_HOST_ID,,} == gmail ]; then
  # Gmail
  # Specify SMTP relay host
  postconf -e relayhost=[${SMTP_SERVER_ADDRESS,,}]:${SMTP_SERVER_PORT}
  # Enable  STARTTLS encryption
  postconf -e smtp_use_tls=${SMTP_USE_TLS}
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
  # Customize From instead of Root
  postconf -e smtp_header_checks=pcre:/etc/postfix/smtp_header_checks
  # Other
  postconf -e smtp_tls_session_cache_database=btree:/var/lib/postfix/smtp_tls_session_cache
  postconf -e smtp_tls_session_cache_timeout=3600s
  echo
elif [ ${SMTP_HOST_ID,,} == mailgun ]; then
  # Mailgun
  # Specify SMTP relay host
  postconf -e relayhost=[${SMTP_SERVER_ADDRESS,,}]:${SMTP_SERVER_PORT}
  # Enable  STARTTLS encryption
  postconf -e smtp_use_tls=${SMTP_USE_TLS}
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
  # Other
  postconf -e smtp_tls_session_cache_database=btree:/var/lib/postfix/smtp_tls_session_cache
  postconf -e smtp_tls_session_cache_timeout=3600s
  echo
elif [ ${SMTP_HOST_ID,,} == custom ]; then
  # Custom
  # Specify SMTP relay host
  postconf -e relayhost=[${SMTP_SERVER_ADDRESS,,}]:${SMTP_SERVER_PORT}
  # Enable STARTTLS encryption
  postconf -e smtp_use_tls=${SMTP_USE_TLS}
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
  # Other
  postconf -e smtp_tls_session_cache_database=btree:/var/lib/postfix/smtp_tls_session_cache
  postconf -e smtp_tls_session_cache_timeout=3600s
  echo
fi

# Global (Main) configure Postfix configuration file /etc/postfix/main.cf
postconf -e mynetworks="127.0.0.0/8, ${LOCAL_NET}"
postconf -e inet_interfaces=all
postconf -e smtpd_recipient_restrictions='permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'
postconf -e smtpd_client_restrictions='permit_mynetworks, reject'
# Stop Spambots - restrict the use of the mail relay to your local network and the SASL-authorized users.
postconf -e smtpd_relay_restrictions='permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'

# Enable Postfix Virtual Domain Aliases for PVE CT programs to send email to root/postmaster
# Alias 'vmclient.alias@virtual-alias.domain' is used to send a CC copy of App mail
# to the system administrator. 
touch /etc/postfix/virtual || exit
# Check if the line exists in the file
if ! grep -q 'vmclient.alias@virtual-alias.domain postmaster' /etc/postfix/virtual; then
  # If the line does not exist, add it to the file
  echo 'vmclient.alias@virtual-alias.domain postmaster' >> /etc/postfix/virtual
fi
# Enable 'Virtual Domain Aliases' in Postfix /etc/postfix/main.cf
postconf -e 'virtual_alias_domains = virtual-alias.domain'
postconf -e 'virtual_alias_maps = hash:/etc/postfix/virtual'
# Update Postfix Aliases
postmap /etc/postfix/virtual

# Customized Email header
echo /^From:.*/ REPLACE From: "$(hostname)-alert" '<'$(echo ${PVE_ROOT_EMAIL} | sed 's/@.*//')@$(hostname).$(hostname -d)'>' > /etc/postfix/smtp_header_checks
postmap /etc/postfix/smtp_header_checks

# Create check line in /etc/postfix/main.cf
sed -i \
    -e '/^#\?\(\s*ahuacate_smtp\s*=\s*\).*/{s//\11/;:a;n;ba;q}' \
    -e '1i ahuacate_smtp=1' /etc/postfix/main.cf

# Reload Postfix configuration file /etc/postfix/main.cf
systemctl restart postfix.service

#---- Finish Line ------------------------------------------------------------------

section "Completion Status"
msg "Success. Task complete."
echo
#-----------------------------------------------------------------------------------