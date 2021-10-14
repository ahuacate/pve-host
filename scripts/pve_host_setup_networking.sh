#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_setup_networking.sh
# Description:  Setup PVE Host networking
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------

# bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host-setup/master/scripts/pve_host_setup_networking.sh)"

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

# Check IP Validity of Octet
function valid_ip() {
  local  ip=$1
  local  stat=1
  if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      OIFS=$IFS
      IFS='.'
      ip=($ip)
      IFS=$OIFS
      [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
          && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
      stat=$?
  fi
  return $stat
}

# CIDR to netmask conversion
cdr2mask () {
   # Number of args to shift, 255..255, first non-255 byte, zeroes
   set -- $(( 5 - ($1 / 8) )) 255 255 255 255 $(( (255 < (8 - ($1 % 8))) & 255 )) 0 0 0
   [ $1 -gt 1 ] && shift $1 || shift
   echo ${1-0}.${2-0}.${3-0}.${4-0}
}

# Install lshw
if [ $(dpkg -s lshw >/dev/null 2>&1; echo $?) != 0 ]; then
  apt-get install -y lshw > /dev/null
fi


#---- Static Variables -------------------------------------------------------------

# Easy Script Section Header Body Text
SECTION_HEAD='PVE Host Networking'

#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------


#---- Configure PVE Host Networking
section "Introduction"

msg_box "PVE host '${HOSTNAME^^}' is installed with the following network NICs:
$(# Show Available NICs
if [[ $(ip -o link show | awk -F': ' '$0 ~ "eno[0-9]"{print $2}') ]]; then
  echo
  echo "      ONBOARD ETHERNET NIC"
  while IFS='|' read -r VAR1 VAR2; do
    msg "  --  ${VAR1}x Onboard (Mainboard) Ethernet NIC"
    echo "${VAR1}x $VAR2 - ${VAR1} Port Onboard Ethernet NIC"
  done < <(ip -o link show | awk -F': ' '$0 ~ "eno[0-9]"{print $2}' | cut -c-6 | uniq -c | sed 's/^ *//' | sed 's/ /|/' 2> /dev/null)
else
  echo "      ONBOARD ETHERNET NIC"
  echo "  --  None. No onboard ethernet NICs available."
fi
echo
if [[ $(ip -o link show | awk -F': ' '$0 ~ "enp[0-9]"{print $2}') ]]; then
  echo "      PCI ETHERNET NIC"
  while IFS='|' read -r VAR1 VAR2; do
    if [ ${VAR1} == 1 ]; then echo "  --  ${VAR1}x Port PCI Ethernet NIC (maybe a onboard NIC)"; echo "      ${VAR1}x $VAR2 - ${VAR1} Port PCI Ethernet NIC"; fi
    if [ ${VAR1} -gt 1 ]; then echo "  --  ${VAR1}x Port PCI Ethernet NIC Card"; echo "      ${VAR1}x $VAR2 - ${VAR1} Port PCI Ethernet NIC"; fi
  done < <(ip -o link show | awk -F': ' '$0 ~ "enp[0-9]"{print $2}' | cut -c-6 | uniq -c | sed 's/^ *//' | sed 's/ /|/' 2> /dev/null)
else
  echo "      PCI ETHERNET NIC"
  echo "  --  None." 
fi
)"

while true; do
  read -p "Setup or modify the PVE host networking [y/n]?: "  -n 1 -r YN
  echo
  case $YN in
    [Yy]*)
      echo
      break
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

#---- Select Ethernet NICs
section "Select Ethernet NICs"

# Create NIC input array list
# Logical name (1) | Port Group Count (2) | NIC capacity (3) | NIC vendor (4) | NIC Model (5)
unset NIC_SRC_LIST
declare -a NIC_SRC_LIST
while IFS='|' read -r VAR01; do
  NIC_VENDOR_ID=$(lshw -class network | grep 'logical\|product\|vendor\|\*-' | grep -B 2 "${VAR01}" | awk -F':' '/vendor/ {print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')
  NIC_PRODUCT_ID=$(lshw -class network | grep 'logical\|product\|vendor\|\*-' | grep -B 2 "${VAR01}" | awk -F':' '/product/ {print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')
  NIC_CAPACITY=$(if [[ $(lshw -class network | grep 'logical\|capacity\|\*-' | grep -A 1 "${VAR01}" | awk -F':' '/capacity/ {print $2}'| sed 's/[^0-9]*//g' | sed 's/^[ \t]*//;s/[ \t]*$//') ]]; then lshw -class network | grep 'logical\|capacity\|\*-' | grep -A 1 "${VAR01}" | awk -F':' '/capacity/ {print $2}'| sed 's/[^0-9]*//g' | sed 's/^[ \t]*//;s/[ \t]*$//'; else echo "1"; fi)
  NIC_PORT_CNT=$(ip -o link show | awk -F': ' '$0 ~ "enp[0-9]s[0-9]|eno[0-9]"{print $2}' | uniq -w 5 -c | sed 's/^[ \t]*//;s/[ \t]*$//' | awk '{ print substr($2,1,5), $1 }' | awk -v var="$(echo ${VAR01} | awk '{ print substr($1,1,5) }')" '$1 == var { print $2 }')
  NIC_SRC_LIST+=( "$(echo "${VAR01}|${NIC_PORT_CNT}|${NIC_CAPACITY}|${NIC_VENDOR_ID}|${NIC_PRODUCT_ID}")" )
  # echo "${VAR01}|${NIC_PORT_CNT}|${NIC_CAPACITY}|${NIC_VENDOR_ID}|${NIC_PRODUCT_ID}"
done < <(ip -o link show | awk -F': ' '$0 ~ "enp[0-9]s[0-9]|eno[0-9]"{print $2}')
# printf '%s\n' "${NIC_SRC_LIST[@]}"


# Select available PVE host Ethernet NICs to configure
ENO_CNT=$(if [ -z "$(ip -o link show | awk -F': ' '$0 ~ "eno[0-9]"{print $2}')" ]; then echo "0"; else ip -o link show | awk -F': ' '$0 ~ "eno[0-9]"{print $2}' | wc -l; fi)
ENP_CNT=$(if [ -z "$(ip -o link show | awk -F': ' '$0 ~ "enp[0-9]"{print $2}')" ]; then echo "0"; else ip -o link show | awk -F': ' '$0 ~ "enp[0-9]"{print $2}' | wc -l; fi)
msg "Select PVE Host ethernet NICs to enable or modify..."
msg "The PVE host has ${WHITE}$((${ENO_CNT}+$ENP_CNT))x NICs${NC} ($(echo "${ENO_CNT}")x onboard, $(echo "$ENP_CNT")x PCI) available for configuration. $(
if [ $((${ENO_CNT}+$ENP_CNT)) = 3 ]; then
  echo "With 3x NICs the User has the option to create a single pfSense OpenVPN VLAN gateway. This option is only available if Layer 2/3 network switches are installed."
elif [ $((${ENO_CNT}+$ENP_CNT)) -ge 4 ]; then
  echo "With 4x or more NICs the User has the option to create twin VLAN pfSense OpenVPN gateways. This option is only available if Layer 2/3 network switches are installed."
fi
) Select which ethernet NICs and/or PCI Cards to enable. Note: Proxmox supports Intel brand NICs. Other brands may be less reliable."
OPTIONS_VALUES_INPUT=$(printf '%s\n' "${NIC_SRC_LIST[@]}")
OPTIONS_LABELS_INPUT=$(printf '%s\n' "${NIC_SRC_LIST[@]}" | awk -F'|' '{ print $1, "---", $4",", $5, "("$3"GbE)" }')
makeselect_input1 "$OPTIONS_VALUES_INPUT" "$OPTIONS_LABELS_INPUT"
multiselect_confirm SELECTED "$OPTIONS_STRING"

# Create NIC input array list
unset NIC_SELECTION_LIST
declare -a NIC_SELECTION_LIST
NIC_SELECTION_LIST+=("${RESULTS[@]}")

#---- Option to prepare for pfSense OpenVPN Gateway(s)
if [ $(printf '%s\n' "${NIC_SELECTION_LIST[@]}" | wc -l) -ge 3 ]; then
  section "Option to prepare pfSense OpenVPN Gateways"
  msg "The PVE has enough ethernet NICs to support a pfSense OpenVPN Gateway server LXC VM. Again, this option is ${UNDERLINE}only available if Layer 2/3 network switches${NC} are installed." 
  if [ $((${ENO_CNT}+$ENP_CNT)) = 3 ] && [ ! -z "$(sort -u /proc/crypto | grep module | grep -i 'aesni_intel\|aes_x86_64')" ]; then
    msg "The suggested PVE host networking configuration would be:\n      PVE Management & Guest Bridge\n      --  vmbr0\n      pfSense OpenVPN Gateway\n      --  vmbr2 (WAN vlan2 for OpenVPN)\n      --  vmbr30 (VPN Gateway vlan30/40)"
  elif [ $((${ENO_CNT}+$ENP_CNT)) = 3 ] && [ -z "$(sort -u /proc/crypto | grep module | grep -i 'aesni_intel\|aes_x86_64')" ]; then
    msg "The suggested PVE host networking configuration would be:\n      PVE Management & Guest Bridge\n      --  vmbr0\n      pfSense OpenVPN Gateway\n      --  vmbr2 (WAN vlan2 for OpenVPN)\n      --  vmbr30 (VPN Gateway vlan30/40)"
    warn "This hosts CPU does NOT support Intel Advanced Encryption Standard\nNew Instructions (AES-NI). Without AES-NI all OpenVPN connection will be slow.\nIt is NOT recommended to install a pfSense OpenVPN Gateway server on this host."
  elif [ $((${ENO_CNT}+$ENP_CNT)) -ge 4 ] && [ ! -z "$(sort -u /proc/crypto | grep module | grep -i 'aesni_intel\|aes_x86_64')" ]; then
    msg "The suggested PVE host networking configuration would be:\n      PVE Management & Guest Bridge\n      --  vmbr0\n      pfSense OpenVPN Gateway\n      --  vmbr2 (WAN vlan2 for OpenVPN)\n      --  vmbr30 (VPN Gateway vlan30 - vpnworld)\n      --  vmbr40 (VPN Gateway vlan40 - vpnlocal)\nThe hosts networking can support two secure internet VPN Gateway exit points."
  elif [ $((${ENO_CNT}+$ENP_CNT)) -ge 4 ] && [ -z "$(sort -u /proc/crypto | grep module | grep -i 'aesni_intel\|aes_x86_64')" ]; then
    msg "The suggested PVE host networking configuration would be:\n      PVE Management & Guest Bridge\n      --  vmbr0\n      pfSense OpenVPN Gateway\n      --  vmbr2 (WAN vlan2 for OpenVPN)\n      --  vmbr30 (VPN Gateway vlan30 - vpnworld)\n      --  vmbr40 (VPN Gateway vlan40 - vpnlocal)\nThe hosts networking can support two secure internet VPN Gateway exit points."
    warn "This hosts CPU does NOT support Intel Advanced Encryption Standard\nNew Instructions (AES-NI). Without AES-NI all OpenVPN connection will be slow.\nIt is NOT recommended to install a pfSense OpenVPN Gateway server on this host."
  fi
  echo
  while true; do
    read -p "Prepare the PVE host networking to support a pfSense OpenVPN Gateway VM [y/n]?: " -n 1 -r YN
    echo
    case $YN in
      [Yy]*)
        PVE_PFSENSE=0
        info "The User has chosen to enable PVE host support for a pfSense OpenVPN VM."
        echo
        break
        ;;
      [Nn]*)
        PVE_PFSENSE=1
        info "You have chosen to skip this step."
        echo
        break
        ;;
      *)
        warn "Error! Entry must be 'y' or 'n'. Try again..."
        echo
        ;;
    esac
  done
else
  PVE_PFSENSE=1
fi


#---- Set PVE Host IP Address
section "Modify PVE host IP settings"

while true; do
  read -p "Change the PVE host IP address ( currently '$(hostname -i)' ) [y/n]?: " -n 1 -r YN
  echo
  case $YN in
    [Yy]*)
      SET_PVE_HOST_IP=0
      echo
      break
      ;;
    [Nn]*)
      SET_PVE_HOST_IP=1
      info "PVE host IP address is set: ${WHITE}$(hostname -i)${NC} ( unchanged )"
      echo
      break
      ;;
    *)
      warn "Error! Entry must be 'y' or 'n'. Try again..."
      echo
      ;;
  esac
done


# Set PVE host IP address
if [ ${SET_PVE_HOST_IP} == 0 ]; then
  msg_box "#### PLEASE READ CAREFULLY - CHANGING IP ADDRESS ####\n
  It's recommended the User follows are IP address system. For $(if [ ${PVE_TYPE} = 1 ]; then echo "Primary PVE hosts"; elif [ ${PVE_TYPE} = 2 ]; then echo "Secondary PVE hosts"; fi):

    IP ADDRESS LABEL ( $(if [ ${PVE_TYPE} = 1 ]; then echo "Primary PVE host"; elif [ ${PVE_TYPE} = 2 ]; then echo "Secondary PVE hosts"; fi) )
      --  $(if [ ${PVE_TYPE} = 1 ]; then echo "XXX.XXX.XXX.101"; elif [ ${PVE_TYPE} = 2 ]; then echo "XXX.XXX.XXX.102/109"; fi)
      --  $(if [ ${PVE_TYPE} = 1 ]; then echo "Default PVE primary host: '192.168.1.101'"; elif [ ${PVE_TYPE} = 2 ]; then echo "Default PVE secondary hosts: '192.168.1.102' --> '192.168.1.109'"; fi)

  The next steps requires your input. You can accept our default values by pressing ENTER on your keyboard. Or overwrite our default value by typing in your own value and then pressing ENTER to accept and to continue to the next step."
  echo
  while true; do
    while true; do
      read -p "Enter a new PVE host IPv4 address: " -e -i $(hostname -i) PVE_HOST_IP
        if [ $(valid_ip ${PVE_HOST_IP} >/dev/null; echo $?) = 0 ]; then
          break
        else
          warn "There are problems with your input:\n1. Your IP address '${PVE_HOST_IP}' does NOT meets the IPv4 standard.\nTry again..."
          echo
        fi
    done
    if [ ${PVE_HOST_IP} != $(hostname -i) ] && [ $(ping -s 1 -c 2 "$(echo "$PVE_HOST_IP")" > /dev/null; echo $?) = 0 ]; then
      warn "There are problems with your input:\n1. Your IP address '${PVE_HOST_IP}' is in use by another network device."
      echo
    elif [ ${PVE_TYPE} = 1 ] && [ $(echo "${PVE_HOST_IP}" | cut -d . -f 4) -eq 101 ] && [ ${PVE_HOST_IP} != $(hostname -i) ] && [ $(ping -s 1 -c 2 ${PVE_HOST_IP} > /dev/null; echo $?) != 0 ]; then
      info "Primary PVE host IP address is set: ${YELLOW}${PVE_HOST_IP}${NC}"
      echo
      break
    elif [ ${PVE_TYPE} = 1 ] && [ $(echo "${PVE_HOST_IP}" | cut -d . -f 4) -eq 101 ] && [ ${PVE_HOST_IP} = $(hostname -i) ]; then
      info "Primary PVE host IP address is set: ${YELLOW}${PVE_HOST_IP}${NC}\n       ( Note: Your host IP address is unchanged. )"
      echo
      break
    elif [ ${PVE_TYPE} = 1 ] && [ $(echo "${PVE_HOST_IP}" | cut -d . -f 4) -ne 101 ] && [ ${PVE_HOST_IP} != $(hostname -i) ] && [ $(ping -s 1 -c 2 ${PVE_HOST_IP} > /dev/null; echo $?) != 0 ]; then
      msg "Primary PVE host IP address ${WHITE}${PVE_HOST_IP}${NC} is non-standard. Standard formatting is 'XXX.XXX.XXX.101'."
      while true; do
        read -p "Accept a non-standard primary PVE host IP ${WHITE}${PVE_HOST_IP}${NC} [y/n]?: " -n 1 -r YN
        echo
        case $YN in
          [Yy]*)
            info "Primary PVE host IP address is set: ${YELLOW}${PVE_HOST_IP}${NC}"
            echo
            break 2
            ;;
          [Nn]*)
            msg "Try again..."
            echo
            break
            ;;
          *)
            warn "Error! Entry must be 'y' or 'n'. Try again..."
            echo
            ;;
        esac
      done
    elif [ ${PVE_TYPE} = 1 ] && [ $(echo "${PVE_HOST_IP}" | cut -d . -f 4) -ne 101 ] && [ ${PVE_HOST_IP} = $(hostname -i) ]; then
      msg "Primary PVE host IP address ${WHITE}${PVE_HOST_IP}${NC} is non-standard.\nStandard formatting is XXX.XXX.XXX.101."
      while true; do
        read -p "Accept a non-standard primary PVE host IP ${WHITE}${PVE_HOST_IP}${NC} [y/n]?: " -n 1 -r YN
        echo
        case $YN in
          [Yy]*)
            info "Primary PVE host IP address is set: ${YELLOW}${PVE_HOST_IP}${NC}\n       (Note: Your host IP is unchanged.)"
            echo
            break 2
            ;;
          [Nn]*)
            msg "Try again..."
            echo
            break
            ;;
          *)
            warn "Error! Entry must be 'y' or 'n'. Try again..."
            echo
            ;;
        esac
      done
    elif [ ${PVE_TYPE} = 2 ] && [ $(echo "${PVE_HOST_IP}" | cut -d . -f 4) -ge 102 ] && [ $(echo "${PVE_HOST_IP}" | cut -d . -f 4) -le 109 ] && [ ${PVE_HOST_IP} != $(hostname -i) ] && [ $(ping -s 1 -c 2 ${PVE_HOST_IP} > /dev/null; echo $?) != 0 ]; then
      info "Secondary PVE host IP address is set: ${PVE_HOST_IP}${NC}"
      echo
      break
    elif [ ${PVE_TYPE} = 2 ] && [ $(echo "${PVE_HOST_IP}" | cut -d . -f 4) -ge 102 ] && [ $(echo "${PVE_HOST_IP}" | cut -d . -f 4) -le 109 ] && [ ${PVE_HOST_IP} = $(hostname -i) ]; then
      info "Secondary PVE host IP address is set: ${YELLOW}${PVE_HOST_IP}${NC}\n       (Note: Your host IP is unchanged.)"
      echo
      break
    elif [ ${PVE_TYPE} = 2 ] && [ $(echo "${PVE_HOST_IP}" | cut -d . -f 4) -le 101 ] || [ $(echo "${PVE_HOST_IP}" | cut -d . -f 4) -ge 110 ] && [ ${PVE_HOST_IP} != $(hostname -i) ] && [ $(ping -s 1 -c 2 ${PVE_HOST_IP} > /dev/null; echo $?) != 0 ]; then
      msg "Secondary PVE host IP address ${WHITE}${PVE_HOST_IP}${NC} is non-standard.\nStandard formatting is in the range 'XXX.XXX.XXX.102' --> 'XXX.XXX.XXX.109'."
      while true; do
        read -p "Accept a non-standard secondary PVE host IP ${WHITE}${PVE_HOST_IP}${NC} [y/n]?: " -n 1 -r YN
        echo
        case $YN in
          [Yy]*)
            info "Secondary PVE host IP address is set: ${YELLOW}${PVE_HOST_IP}${NC}"
            echo
            break 2
            ;;
          [Nn]*)
            msg "Try again..."
            echo
            break
            ;;
          *)
            warn "Error! Entry must be 'y' or 'n'. Try again..."
            echo
            ;;
        esac
      done
    elif [ ${PVE_TYPE} = 2 ] && [ $(echo "${PVE_HOST_IP}" | cut -d . -f 4) -le 101 ] || [ $(echo "${PVE_HOST_IP}" | cut -d . -f 4) -ge 110 ] && [ ${PVE_HOST_IP} = $(hostname -i) ]; then
      msg "Secondary PVE host IP address ${WHITE}${PVE_HOST_IP}${NC} is non-standard.\nStandard formatting is in the range 'XXX.XXX.XXX.102' --> 'XXX.XXX.XXX.109'."
      while true; do
        read -p "Accept a non-standard secondary PVE host IP ${WHITE}${PVE_HOST_IP}${NC} [y/n]?: " -n 1 -r YN
        echo
        case $YN in
          [Yy]*)
            info "Secondary PVE host IP address is set: ${YELLOW}${PVE_HOST_IP}${NC}\n       (Note: Your host IP is unchanged.)"
            echo
            break 2
            ;;
          [Nn]*)
            msg "Try again..."
            echo
            break
            ;;
          *)
            warn "Error! Entry must be 'y' or 'n'. Try again..."
            echo
            ;;
        esac
      done
    fi
  done
fi


# Set PVE host Gateway
if [ ${SET_PVE_HOST_IP} = 0 ]; then
  while true; do
    while true; do
      read -p "Enter a new or accept the current gateway IPv4 address: " -e -i $(ip route show | grep default | awk '{print $3}') PVE_GW
        if [ $(valid_ip ${PVE_GW} >/dev/null; echo $?) = 0 ]; then
          break
        else
          warn "There are problems with your input:\n1. Your IP address '${PVE_GW}' does NOT meets the IPv4 standard.\nTry again..."
          echo
        fi
    done
    if [ $(ping -s 1 -c 2 ${PVE_GW} > /dev/null; echo $?) = 0 ]; then
      info "The PVE host gateway is set: ${YELLOW}${PVE_GW}${NC}"
      echo
      break
    elif [ $(ping -s 1 -c 2 ${PVE_GW} > /dev/null; echo $?) = 1 ]; then
      warn "There are problems with your input:\n1. The IP address meets the IPv4 standard, BUT\n2. The IP address ${PVE_GW} is NOT reachable (cannot ping)."
      while true; do
        read -p "Accept gateway IP ${WHITE}${PVE_GW}${NC} anyway (not recommended ) [y/n]?: " -n 1 -r YN
        echo
        case $YN in
          [Yy]*)
            info "The PVE host gateway is set: ${YELLOW}${PVE_GW}${NC}"
            echo
            break 2
            ;;
          [Nn]*)
            msg "Try again..."
            echo
            break
            ;;
          *)
            warn "Error! Entry must be 'y' or 'n'. Try again..."
            echo
            ;;
        esac
      done
    fi
  done
fi


#---- Set PVE Hostname
section "Modify PVE host 'hostname'"

# Edit hostname check
if [[ $(pct list) ]] || [[ $(qm list) ]] && [[ $(pvecm nodes 2>/dev/null | grep $HOSTNAME) ]]; then
  warn "PVE host '$HOSTNAME' is reporting to be hosting $(qm list | awk 'NR>1 { print $1 }' | wc -l)x virtual machines (VMs)\nand $(pct list | awk 'NR>1 { print $1 }' | wc -l)x LXC containers (CTs).\n\nIf you want to proceed to configure or make system changes to this PVE host\n'$HOSTNAME' you must first take the following steps:\n      FOR SINGLE OR PRIMARY NODES - REMOVE ALL CONTAINERS\n      --  Stop all VMs and CTs.\n      --  Create a backup archive of all VMs and CTs.\n      --  REMOVE all VMs and CTs.\nA backup archive can be restored through the Proxmox VE web GUI or through\nthe PVE CLI tools.\n\nPVE host '$HOSTNAME' is also reporting as a member of a PVE cluster.\nTo proceed you must first remove this node ( '$HOSTNAME' ) from the PVE cluster.\n      REMOVE NODE FROM CLUSTER\n      --  Migrate all VMs and CTs to another active node.\n      --  Remove '$HOSTNAME' from the PVE cluster."
  echo
  msg "Complete the above tasks and try running this script again."
  info "PVE host IP 'hostname' is set: ${WHITE}$(hostname)${NC} ( unchanged )"
  echo
  SET_PVE_HOST_HOSTNAME_CHECK=1
elif [[ $(pct list) ]] || [[ $(qm list) ]] && [[ ! $(pvecm nodes 2>/dev/null | grep $HOSTNAME) ]]; then
  warn "PVE host '$HOSTNAME' is reporting to be hosting $(qm list | awk 'NR>1 { print $1 }' | wc -l)x virtual machines (VMs)\nand $(pct list | awk 'NR>1 { print $1 }' | wc -l)x LXC containers (CTs).\n\nIf you want to proceed to configure or make system changes to this PVE host\n'$HOSTNAME' you must first take the following steps:\n      FOR SINGLE OR PRIMARY NODES - REMOVE ALL CONTAINERS\n      --  Stop all VMs and CTs.\n      --  Create a backup archive of all VMs and CTs.\n      --  REMOVE all VMs and CTs.\nA backup archive can be restored through the Proxmox VE web GUI or through\nthe PVE CLI tools."
  echo
  msg "Complete the above tasks and try running this script again."
  info "PVE host IP 'hostname' is set: ${WHITE}$(hostname)${NC} ( unchanged )"
  echo
  SET_PVE_HOST_HOSTNAME_CHECK=1
elif [[ ! $(pct list) ]] || [[ ! $(qm list) ]] && [[ $(pvecm nodes 2>/dev/null | grep $HOSTNAME) ]]; then
  warn "PVE host '$HOSTNAME' is reporting as a member of a PVE cluster.\nTo proceed you must first remove this node ( '$HOSTNAME' ) from the PVE cluster.\n      REMOVE NODE FROM CLUSTER\n      --  Migrate all VMs and CTs to another active node.\n      --  Remove '$HOSTNAME' from the PVE cluster."
  echo
  msg "Complete the above tasks and try running this script again."
  info "PVE host IP 'hostname' is set: ${WHITE}$(hostname)${NC} ( unchanged )"
  echo
  SET_PVE_HOST_HOSTNAME_CHECK=1
else
  SET_PVE_HOST_HOSTNAME_CHECK=0
fi

if [ ${SET_PVE_HOST_HOSTNAME_CHECK} == 0 ]; then
  msg "The PVE host current 'hostname' is set: ${WHITE}$HOSTNAME${NC}."
  read -p "Do you want to change the PVE host hostname [y/n]?: " -n 1 -r
  echo
  while true; do
    read -p "Do you want to change the PVE host hostname [y/n]?: " -n 1 -r YN
    echo
    case $YN in
      [Yy]*)
        SET_PVE_HOST_HOSTNAME=0
        echo
        break
        ;;
      [Nn]*)
        SET_PVE_HOST_HOSTNAME=1
        info "PVE host IP 'hostname' is set: ${WHITE}$(hostname)${NC} ( unchanged )"
        echo
        break
        ;;
      *)
        warn "Error! Entry must be 'y' or 'n'. Try again..."
        echo
        ;;
    esac
  done
fi


# Set PVE host 'hostname'
if [ ${SET_PVE_HOST_HOSTNAME} = 0 ]; then
  # Hostname suggestion only
  if [ ${PVE_TYPE} = 1 ] && [[ $HOSTNAME =~ ^[A-Za-z]+\-"01"$ ]];then
    PVE_HOSTNAME_VAR01=$HOSTNAME
  elif [ ${PVE_TYPE} = 1 ] && ! [[ $HOSTNAME =~ ^[A-Za-z]+\-"01"$ ]];then
    PVE_HOSTNAME_VAR01=pve-01
  elif [ ${PVE_TYPE} = 2 ] && [[ $HOSTNAME =~ ^[A-Za-z]+\-0[2-9]{1}$ ]];then
    PVE_HOSTNAME_VAR01=$HOSTNAME
  elif [ ${PVE_TYPE} = 2 ] && ! [[ $HOSTNAME =~ ^[A-Za-z]+\-0[2-9]{1}$ ]];then
    PVE_HOSTNAME_VAR01=pve-02
  fi
  while true; do
    read -p "Enter a new PVE host 'hostname': " -e -i ${PVE_HOSTNAME_VAR01} PVE_HOSTNAME
    PVE_HOSTNAME=${PVE_HOSTNAME,,}
    if [ ${PVE_TYPE} = 1 ] && ! [[ "${PVE_HOSTNAME}" =~ ^[A-Za-z]+\-[0-9]{2}$ ]]; then
      warn "There are problems with your input:\n1. The hostname denotation is missing (i.e must be hostname-01).\n   Try again..."
      echo
    elif [ ${PVE_TYPE} = 1 ] && [ ${PVE_HOSTNAME} == "pve-01" ]; then
      info "PVE hostname is set: ${YELLOW}${PVE_HOSTNAME}${NC}"
      HOSTNAME_FIX=0
      echo
      break
    elif [ ${PVE_TYPE} = 1 ] && [ $(echo "${PVE_HOSTNAME}" | cut -d'-' -f 1 ) != 'pve' ] && [ $(echo "${PVE_HOSTNAME}" | rev | cut -d'-' -f 1 | rev) -eq 01 ]; then
      msg "PVE hostname ${WHITE}${PVE_HOSTNAME}${NC} is:\n1. Correctly denoted for primary PVE hosts (i.e -01).\n2. The name ${WHITE}${PVE_HOSTNAME}${NC} is non-standard but acceptable (i.e pve-01)."
      while true; do
        read -p "Accept your non-standard primary PVE hostname ${WHITE}"${PVE_HOSTNAME}"${NC} [y/n]?: " -n 1 -r YN
        echo
        case $YN in
          [Yy]*)
            info "PVE hostname is set: ${YELLOW}${PVE_HOSTNAME}${NC}"
            HOSTNAME_FIX=0
            echo
            break 2
            ;;
          [Nn]*)
            msg "Try again..."
            echo
            break
            ;;
          *)
            warn "Error! Entry must be 'y' or 'n'. Try again..."
            echo
            ;;
        esac
      done
    elif [ ${PVE_TYPE} = 1 ] && [ $(echo "${PVE_HOSTNAME}" | rev | cut -d'-' -f 1 | rev) -ne 01 ]; then
      warn "There are problems with your input:\n1. Primary PVE hosts must be denoted with 01.\n   Try again..."
      echo
    elif [ ${PVE_TYPE} = 2 ] && ! [[ "${PVE_HOSTNAME}" =~ ^[A-Za-z]+\-0[2-9]{1}$ ]]; then
      warn "There are problems with your input:\n1. The hostname denotation is missing (i.e must be hostname-02/03/04 etc).\n   Try again..."
      echo
    elif [ ${PVE_TYPE} = 2 ] && [[ ${PVE_HOSTNAME} =~ "-01" ]]; then
      warn "There are problems with your input:\n1. Secondary PVE hosts cannot be denoted with 01 (i.e ${PVE_HOSTNAME}).\n2. Secondary PVE hosts must be denoted from 02 to 09.\n   Try again..."
      echo
    elif [ ${PVE_TYPE} = 2 ] && [ $(echo "${PVE_HOSTNAME}" | cut -d'-' -f 1 ) == pve ] && [ $(echo "${PVE_HOSTNAME}" | rev | cut -d'-' -f 1 | rev) -ge 02 ] && [ $(echo "${PVE_HOSTNAME}" | rev | cut -d'-' -f 1 | rev) -le 09 ]; then
      info "PVE hostname is set: ${YELLOW}${PVE_HOSTNAME}${NC}."
      HOSTNAME_FIX=0
      echo
      break
    elif [ ${PVE_TYPE} = 2 ] && [ $(echo "${PVE_HOSTNAME}" | cut -d'-' -f 1 ) != 'pve' ] && [ $(echo "${PVE_HOSTNAME}" | rev | cut -d'-' -f 1 | rev) -ge 02 ] && [ $(echo "${PVE_HOSTNAME}" | rev | cut -d'-' -f 1 | rev) -le 09 ]; then
      msg "PVE hostname ${WHITE}${PVE_HOSTNAME}${NC} is:\n1. Correctly denoted for secondary PVE hosts (i.e -02,-03).\n2. The name ${WHITE}${PVE_HOSTNAME}${NC} is non-standard but acceptable (i.e pve-$(echo "${PVE_HOSTNAME}" | rev | cut -d'-' -f 1 | rev))."
      while true; do
        read -p "Accept your non-standard secondary PVE hostname ${WHITE}"${PVE_HOSTNAME}"${NC} [y/n]?: " -n 1 -r YN
        echo
        case $YN in
          [Yy]*)
            info "PVE hostname is set: ${YELLOW}${PVE_HOSTNAME}${NC}"
            HOSTNAME_FIX=0
            echo
            break 2
            ;;
          [Nn]*)
            msg "Try again..."
            echo
            break
            ;;
          *)
            warn "Error! Entry must be 'y' or 'n'. Try again..."
            echo
            ;;
        esac
      done
    elif [ ${PVE_TYPE} = 2 ] && [ $(echo "${PVE_HOSTNAME}" | rev | cut -d'-' -f 1 | rev) -le 01 ] && [ $(echo "${PVE_HOSTNAME}" | rev | cut -d'-' -f 1 | rev) -ge 10 ]; then
      warn "There are problems with your input:\n1. Secondary PVE hosts must be denoted from 02 to 09.\n   Try again..."
      echo
    fi
  done
else
  PVE_HOSTNAME=$HOSTNAME
  info "PVE hostname is set: ${YELLOW}${PVE_HOSTNAME}${NC} (Unchanged)."
fi


#---- Configuring PVE Host Ethernet
section "Creating new PVE Host Ethernet configuration"

# Setting Ethernet variables
ETH_10GBE_CNT=$(printf '%s\n' "${NIC_SELECTION_LIST[@]}" | awk -F'|' '{ if($3 == "10") {print} }' | wc -l)
ETH_1GBE_CNT=$(printf '%s\n' "${NIC_SELECTION_LIST[@]}" | awk -F'|' '{ if($3 == "1") {print} }' | wc -l)
ETH_10GBE_LIST=$(printf '%s\n' "${NIC_SELECTION_LIST[@]}" | awk -F'|' '{ if($3 == "10") {print $0} }' | sort | awk -F'|' '{ print $3, $1 }')
ETH_1GBE_LIST=$(printf '%s\n' "${NIC_SELECTION_LIST[@]}" | awk -F'|' '{ if($3 == "1") {print $0} }' | sort | awk -F'|' '{ print $3, $1 }')
# Create array file
unset NIC_INPUT_LIST
declare -a NIC_INPUT_LIST

# PVE Node VMBR bridges (No pfSense)
if [ ${PVE_PFSENSE} = 1 ]; then
  msg "Creating PVE Ethernet NIC bridges (VMBR)..."
  if [ ${ETH_10GBE_CNT} -eq 0 ] && [ ${ETH_1GBE_CNT} -eq 1 ]; then
    # Now read from 1Gbe list file
    while read -r line1; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 1 1 $line1")" )
      info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}"${ETH_1GBE_CNT}"x vmbr0${NC}"
    done < <(echo "${ETH_1GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -eq 0 ] && [ ${ETH_1GBE_CNT} -eq 2 ]; then
    # Now read from 1Gbe list file
    while read -r line1; read -r line2; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 bond0 802.3ad $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr0 bond0 802.3ad $line2")" )
      info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}"${ETH_1GBE_CNT}"x bond0 (802.3ad) vmbr0${NC}"
    done < <(echo "${ETH_1GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -eq 0 ] && [ ${ETH_1GBE_CNT} -eq 3 ]; then
    # Now read from 1Gbe list file
    while read -r line1; read -r line2; read -r line3; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 bond0 802.3ad $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr0 bond0 802.3ad $line2")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr0 bond0 802.3ad $line3")" )
      info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}"${ETH_1GBE_CNT}"x bond0 (802.3ad) vmbr0${NC}"
    done < <(echo "${ETH_1GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -eq 0 ] && [ ${ETH_1GBE_CNT} -ge 4 ]; then
    # Now read from 1Gbe list file
    while read -r line1; read -r line2; read -r line3; read -r line4; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 bond0 802.3ad $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr0 bond0 802.3ad $line2")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr0 bond0 802.3ad $line3")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr0 bond0 802.3ad $line4")" )
      if [ ${ETH_1GBE_CNT} -eq 4 ]; then
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}"${ETH_1GBE_CNT}"x bond0 (802.3ad) vmbr0${NC}"
      elif [ ${ETH_1GBE_CNT} -ge 4 ]; then
        info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}4x bond0 (802.3ad) vmbr0${NC}"
        warn "$((${ETH_1GBE_CNT}-4))x 1GbE NICs have been excluded. You can always modify your PVE host network using the PVE management webGUI."
      fi
    done < <(echo "${ETH_1GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -eq 1 ] && [ ${ETH_1GBE_CNT} -ge 0 ]; then
    # Now read from 10Gbe list file
    while read -r line1; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 1 1 $line1")" )
      info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}"${ETH_10GBE_CNT}"x vmbr0${NC}"
      if [ ${ETH_1GBE_CNT} -ge 1 ]; then
        warn ""${ETH_1GBE_CNT}"x 1GbE NICs have been excluded because they are not required when 10GbE ethernet is available. You can always modify your PVE host network using the PVE management webGUI."
      fi
    done < <(echo "${ETH_10GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -ge 2 ] && [ ${ETH_1GBE_CNT} -ge 0 ]; then
    # Now read from 10Gbe list file
    while read -r line1; read -r line2; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 bond0 802.3ad $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr0 bond0 802.3ad $line2")" )
      info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}2x bond0 (802.3ad) vmbr0${NC}"
      if [ ${ETH_10GBE_CNT} -ge 3 ] && [ ${ETH_1GBE_CNT} -ge 1 ]; then
      warn "$((${ETH_10GBE_CNT}-2))x 10GbE NICs have been excluded because they are not required. "${ETH_1GBE_CNT}"x 1GbE NICs have been excluded because they are not required when 10GbE ethernet is available. You can always modify your PVE host network using the PVE management webGUI."
      fi
    done < <(echo "${ETH_10GBE_LIST}")
  fi
echo
fi

# PVE Node VMBR assignment (With pfSense)
if [ ${PVE_PFSENSE} = 0 ]; then
  echo
  msg "Creating PVE Ethernet NIC bridges (VMBR)..."
  if [ ${ETH_10GBE_CNT} -eq 0 ] && [ ${ETH_1GBE_CNT} -eq 3 ]; then
    # Now read from 1Gbe list file
    while read -r line1; read -r line2; read -r line3; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 1 1 $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr2 1 1 $line2")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr30 1 1 $line3")" )
      info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}\n"
    done < <(echo "${ETH_1GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -eq 0 ] && [ ${ETH_1GBE_CNT} -eq 4 ]; then
    # Now read from 1Gbe list file
    while read -r line1; read -r line2; read -r line3; read -r line4; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 1 1 $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr2 1 1 $line2")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr30 1 1 $line3")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr40 1 1 $line4")" )
      info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}\n      --  ${YELLOW}1x vmbr40${NC}"
    done < <(echo "${ETH_1GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -eq 0 ] && [ ${ETH_1GBE_CNT} -eq 5 ]; then
    # Now read from 1Gbe list file
    while read -r line1; read -r line2; read -r line3; read -r line4; read -r line5; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 bond0 802.3ad $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr0 bond0 802.3ad $line2")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr2 1 1 $line3")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr30 1 1 $line4")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr40 1 1 $line5")" )
      info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}2x bond0 (802.3ad) vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}\n      --  ${YELLOW}1x vmbr40${NC}"
    done < <(echo "${ETH_1GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -eq 0 ] && [ ${ETH_1GBE_CNT} -ge 6 ]; then
    # Now read from 1Gbe list file
    while read -r line1; read -r line2; read -r line3; read -r line4; read -r line5; read -r line6; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 bond0 802.3ad $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr0 bond0 802.3ad $line2")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr2 bond2 802.3ad $line3")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr2 bond2 802.3ad $line4")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr30 1 1 $line5")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr40 1 1 $line6")" )
      info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}2x bond0 (802.3ad) vmbr0${NC}\n      --  ${YELLOW}2x bond2 (802.3ad) vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}\n      --  ${YELLOW}1x vmbr40${NC}"
      if [ ${ETH_10GBE_CNT} -eq 0 ] && [ ${ETH_1GBE_CNT} -ge 7 ]; then
        warn "$((${ETH_1GBE_CNT}-6))x 1GbE NICs have been excluded because they are not required.\nYou can always modify your PVE host network using the PVE management webGUI."
      fi
    done < <(echo "${ETH_1GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -eq 1 ] && [ ${ETH_1GBE_CNT} -eq 2 ]; then
    # Now read from 10Gbe list file
    while read -r line1; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 1 1 $line1")" )
      info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}"
    done < <(echo "${ETH_10GBE_LIST}")
    # Now read from 1Gbe list file
    while read -r line1; read -r line2; do
      NIC_INPUT_LIST+=( "$(echo "vmbr2 1 1 $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr30 1 1 $line2")" )
      info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}"
    done < <(echo "${ETH_1GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -eq 1 ] && [ ${ETH_1GBE_CNT} -eq 3 ]; then
    # Now read from 10Gbe list file
    while read -r line1; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 1 1 $line1")" )
      info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}"
    done < <(echo "${ETH_10GBE_LIST}")
    # Now read from 1Gbe list file
    while read -r line1; read -r line2; read -r line3; do
      NIC_INPUT_LIST+=( "$(echo "vmbr2 1 1 $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr30 1 1 $line2")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr40 1 1 $line3")" )
      info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}\n      --  ${YELLOW}1x vmbr40${NC}"
    done < <(echo "${ETH_1GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -eq 1 ] && [ ${ETH_1GBE_CNT} -ge 4 ]; then
    # Now read from 10Gbe list file
    while read -r line1; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 1 1 $line1")" )
      info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}"
    done < <(echo "${ETH_10GBE_LIST}")
    # Now read from 1Gbe list file
    while read -r line1; read -r line2; read -r line3; read -r line4; do
      NIC_INPUT_LIST+=( "$(echo "vmbr2 bond2 802.3ad $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr2 bond2 802.3ad $line2")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr30 1 1 $line3")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr40 1 1 $line4")" )
      info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}2x bond2 (802.3ad) vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}\n      --  ${YELLOW}1x vmbr40${NC}"
      if [ ${ETH_10GBE_CNT} -eq 1 ] && [ ${ETH_1GBE_CNT} -ge 5 ]; then
        warn "$((${ETH_1GBE_CNT}-4))x 1GbE NICs have been excluded because they are not required.\nYou can always modify your PVE host network using the PVE management webGUI."
      fi
    done < <(echo "${ETH_1GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -eq 2 ] && [ ${ETH_1GBE_CNT} -eq 1 ]; then
    # Now read from 10Gbe list file
    while read -r line1; read -r line2; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 1 1 $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr2 1 1 $line2")" )
      info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}"
    done < <(echo "${ETH_10GBE_LIST}")
    # Now read from 1Gbe list file
    while read -r line1; do
      NIC_INPUT_LIST+=( "$(echo "vmbr30 1 1 $line1")" )
      info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}1x vmbr30${NC}"
    done < <(echo "${ETH_1GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -eq 2 ] && [ ${ETH_1GBE_CNT} -ge 2 ]; then
    # Now read from 10Gbe list file
    while read -r line1; read -r line2; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 1 1 $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr2 1 1 $line2")" )
      info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}"
    done < <(echo "${ETH_10GBE_LIST}")
    # Now read from 1Gbe list file
    while read -r line1; read -r line2; do
      NIC_INPUT_LIST+=( "$(echo "vmbr30 1 1 $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr40 1 1 $line2")" )
      info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}1x vmbr30${NC}\n      --  ${YELLOW}1x vmbr40${NC}"
      if [ ${ETH_10GBE_CNT} -eq 2 ] && [ ${ETH_1GBE_CNT} -ge 3 ]; then
        warn "$((${ETH_1GBE_CNT}-2))x 1GbE NICs have been excluded because they are not required.\nYou can always modify your PVE host network using the PVE management webGUI."
      fi
    done < <(echo "${ETH_1GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -eq 3 ] && [ ${ETH_1GBE_CNT} -eq 0 ]; then
    # Now read from 10Gbe list file
    while read -r line1; read -r line2; read -r line3; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 1 1 $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr2 1 1 $line2")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr30 1 1 $line3")" )
      info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}"
    done < <(echo "${ETH_10GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -eq 3 ] && [ ${ETH_1GBE_CNT} -eq 1 ]; then
    # Now read from 10Gbe list file
    while read -r line1; read -r line2; read -r line3; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 1 1 $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr2 1 1 $line2")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr30 1 1 $line3")" )
      info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}"
    done < <(echo "${ETH_10GBE_LIST}")
    # Now read from 1Gbe list file
    while read -r line1; do
      NIC_INPUT_LIST+=( "$(echo "vmbr40 1 1 $line1")" )
      info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}1x vmbr40${NC}"
    done < <(echo "${ETH_1GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -eq 3 ] && [ ${ETH_1GBE_CNT} -ge 2 ]; then
    # Now read from 10Gbe list file
    while read -r line1; read -r line2; read -r line3; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 1 1 $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr2 1 1 $line2")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr30 1 1 $line3")" )
      info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}"
    done < <(echo "${ETH_10GBE_LIST}")
    # Now read from 1Gbe list file
    while read -r line1; read -r line2; do
      NIC_INPUT_LIST+=( "$(echo "vmbr40 bond40 802.3ad $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr40 bond40 802.3ad $line2")" )
      info "Number of bridged 1GbE NICs:\n      --  ${YELLOW}2x bond4 (802.3ad) vmbr40${NC}"
      if [ ${ETH_10GBE_CNT} -eq 3 ] && [ ${ETH_1GBE_CNT} -ge 3 ]; then
        warn "$((${ETH_1GBE_CNT}-2))x 1GbE NICs have been excluded because they are not required.\nYou can always modify your PVE host network using the PVE management webGUI."
      fi
    done < <(echo "${ETH_1GBE_LIST}")
  elif [ ${ETH_10GBE_CNT} -ge 4 ] && [ ${ETH_1GBE_CNT} -ge 0 ]; then
    # Now read from 10Gbe list file
    while read -r line1; read -r line2; read -r line3; read -r line4; do
      NIC_INPUT_LIST+=( "$(echo "vmbr0 1 1 $line1")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr2 1 1 $line2")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr30 1 1 $line3")" )
      NIC_INPUT_LIST+=( "$(echo "vmbr40 1 1 $line4")" )
      info "Number of bridged 10GbE NICs:\n      --  ${YELLOW}1x vmbr0${NC}\n      --  ${YELLOW}1x vmbr2${NC}\n      --  ${YELLOW}1x vmbr30${NC}\n      --  ${YELLOW}1x vmbr40${NC}"
      if [ ${ETH_10GBE_CNT} -ge 5 ] && [ ${ETH_1GBE_CNT} -eq 0 ]; then
        warn "$((${ETH_10GBE_CNT}-4))x 10GbE NICs have been excluded because they are not required. You can always modify your PVE host network using the PVE management webGUI."
      elif [ ${ETH_10GBE_CNT} -ge 5 ] && [ ${ETH_1GBE_CNT} -ge 1 ]; then
        warn "$((${ETH_10GBE_CNT}-4))x 10GbE NICs have been excluded because they are not required. "${ETH_1GBE_CNT}"x 1GbE NICs have been excluded because they are not required when 10GbE ethernet is available. You can always modify your PVE host network using the PVE management webGUI."
      fi
    done < <(echo "${ETH_10GBE_LIST}")
  fi
echo
fi


# Building /etc/network/interfaces.new
msg "Creating PVE host networking '/etc/network/interfaces.new'..."
# NEW_INTERFACES=/etc/network/interfaces.new
NEW_INTERFACES=/tmp/interfaces.new
# Create a backup of the old
cp /etc/network/interfaces /etc/network/interfaces.old
# Checking for older /etc/network/interfaces.new
if [ -f ${NEW_INTERFACES} ]; then
  rm ${NEW_INTERFACES} >/dev/null
fi

# Create /etc/network/interfaces.new file
eval cat << EOF > ${NEW_INTERFACES}
# Please do NOT modify this file directly, unless you know what
# you're doing.
#
# If you want to manage parts of the network configuration manually,
# please utilize the 'source' or 'source-directory' directives to do
# so.
# PVE will preserve these directives, but will NOT read its network
# configuration from sourced files, so do not attempt to move any of
# the PVE managed interfaces into external files!

auto lo
iface lo inet loopback

#### Settings for $(if [ $(printf '%s\n' "${NIC_INPUT_LIST[@]}" | awk -F' ' '{if($4 == "10"){print}}' | wc -l) -gt 0 ]; then echo "$(printf '%s\n' "${NIC_INPUT_LIST[@]}" | awk -F' ' '{if($4 == "1"){print}}' | wc -l)x10GbE:"; fi)$(if [ $(printf '%s\n' "${NIC_INPUT_LIST[@]}" | awk -F' ' '{if($4 == "1"){print}}' | wc -l) -gt 0 ]; then echo "$(printf '%s\n' "${NIC_INPUT_LIST[@]}"| awk -F' ' '{if($4 == "1"){print}}' | wc -l)x1GbE"; fi) ####
  
EOF


# Build iface list
while IFS=" " read -r VAR1 VAR2 VAR3 VAR4 VAR5; do
  echo "iface $VAR5 inet manual" >> ${NEW_INTERFACES}
  echo >> ${NEW_INTERFACES}
done < <(printf '%s\n' "${NIC_INPUT_LIST[@]}")

# Build ethernet bond list
if [[ $(printf '%s\n' "${NIC_INPUT_LIST[@]}" | awk -F' ' '{if($2 ~ "bond"){print}}') ]]; then
while IFS=" " read -r VAR1 VAR2 VAR3 VAR4 VAR5; do
(( i= $(echo $VAR4 | sed 's/GbE//') * $(echo $VAR5 | wc -w) ))
eval cat << EOF >> ${NEW_INTERFACES}
# Linux Bond $VAR2 - ${i}GbE
auto $VAR2
iface $VAR2 inet manual
        bond-slaves $VAR5
        bond-miimon 100
        bond-mode $VAR3
        bond-xmit-hash-policy layer2+3

EOF
done < <(printf '%s\n' "${NIC_INPUT_LIST[@]}" | awk -F' ' '{if($2 ~ "bond"){print}}' | awk '{if (a!=$2) {a=$2; printf "\n%s",$0,FS} else {a=$2; printf " %s",$5 }} END {printf "\n" }' | sed '/^$/d')
fi

# Build bonded bridges
if [[ $(printf '%s\n' "${NIC_INPUT_LIST[@]}" | awk -F' ' '{if($2 ~ "bond"){print}}') ]]; then
while IFS=" " read -r VAR1 VAR2 VAR3 VAR4 VAR5; do
(( i= $(echo $VAR4 | sed 's/GbE//') * $(echo $VAR5 | wc -w) ))
if [ ${VAR1} = "vmbr0" ]; then
eval cat << EOF >> ${NEW_INTERFACES}
# Linux Bridge ${VAR1} - ${i}GbE Linux Bond
auto ${VAR1}
iface ${VAR1} inet static
        address ${PVE_HOST_IP}
        gateway ${PVE_GW}
        bridge-ports $VAR2
        bridge-stp off
        bridge-fd 0
        bridge-vlan-aware yes
        bridge-vids 2-4094

EOF
elif [ ${VAR1} != "vmbr0" ]; then
eval cat << EOF >> ${NEW_INTERFACES}
# Linux Bridge ${VAR1} - ${i}GbE Linux Bond
auto ${VAR1}
iface ${VAR1} inet manual
        bridge-ports $VAR2
        bridge-stp off
        bridge-fd 0
        bridge-vlan-aware yes
        bridge-vids 2-4094

EOF
fi
done < <(printf '%s\n' "${NIC_INPUT_LIST[@]}" | awk -F' ' '{if($2 ~ "bond"){print}}' | awk '{if (a!=$2) {a=$2; printf "\n%s",$0,FS} else {a=$2; printf " %s",$5 }} END {printf "\n" }' | sed '/^$/d')
fi

# Build standard bridges
if [[ $(printf '%s\n' "${NIC_INPUT_LIST[@]}" | awk -F' ' '{if($2 == "1"){print}}') ]]; then
while IFS=" " read -r VAR1 VAR2 VAR3 VAR4 VAR5; do
if [ ${VAR1} = "vmbr0" ]; then
eval cat << EOF >> ${NEW_INTERFACES}
# Linux Bridge ${VAR1} - $VAR4
auto ${VAR1}
iface ${VAR1} inet static
        address ${PVE_HOST_IP}
        gateway ${PVE_GW}
        bridge-ports $VAR5
        bridge-stp off
        bridge-fd 0
        bridge-vlan-aware yes
        bridge-vids 2-4094

EOF
elif [ ${VAR1} != "vmbr0" ]; then
eval cat << EOF >> ${NEW_INTERFACES}
# Linux Bridge ${VAR1} - $VAR4
auto ${VAR1}
iface ${VAR1} inet manual
        bridge-ports $VAR5
        bridge-stp off
        bridge-fd 0
        bridge-vlan-aware yes
        bridge-vids 2-4094

EOF
fi
done < <(printf '%s\n' "${NIC_INPUT_LIST[@]}" | awk -F' ' '{if($2 == "1"){print}}' | sed '/^$/d')
fi

#---- Finish Line ------------------------------------------------------------------
echo
if [ -f /etc/network/interfaces.old ]; then
msg_box "A backup copy of the previous network configuration is stored here: /etc/network/interfaces.old
In case after reboot the User has connection issues the User can restore the previous settings with the following CLI command:

    cat /etc/network/interfaces.old > /etc/network/interfaces.new
    systemctl restart networking"
fi