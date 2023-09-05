#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_setup_boot_delay.sh
# Description:  Basic mods for Proxmox (PVE) Host machines
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------
#---- Source -----------------------------------------------------------------------
#---- Dependencies -----------------------------------------------------------------
#---- Static Variables -------------------------------------------------------------

# Easy Script Section Header Body Text
SECTION_HEAD='PVE Host Boot Delay'

# Grub parameters (seconds)
grub_timeout=300
grub_timeout_default=5

#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------

#---- Prerequisites
#---- Introduction

section "Introduction"

msg_box "#### PLEASE READ CAREFULLY - PVE BOOT DELAY ####\n
This setup script is for adding a boot delay so your NAS and network devices (i.e switches, DNS servers) are up before PVE boots. Our solution is to the edit the 'grub timeout' parameter:

      TASK DESCRIPTION
  --  Edit the Grub parameter 'grub timeout' in file '/etc/default/grub'
  --  Set the boot delay to 5 minutes ( NAS can be slow to go online )

Your Proxmox server now waits 5 minutes before starting the OS, by which time your NAS and network devices (i.e switches, DNS servers) should be operational. There will be no more manual restarting of virtual machines following a power outage."
echo

msg "Select you option..."
OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE02" "TYPE00")
OPTIONS_LABELS_INPUT=( "Apply a ${grub_timeout} second Grub boot delay (recommended)" "Restore Proxmox default Grub boot delay (${grub_timeout_default} seconds)" "None. Return to the Toolbox" )
makeselect_input2
singleselect SELECTED "$OPTIONS_STRING"

if [ "$RESULTS" = 'TYPE01' ]
then
  # Set grub boot delay (300)
  msg "Setting PVE host boot delay..."
  sed -i "s/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=${grub_timeout}/" /etc/default/grub
  # Update grub
  update-grub
  info "PVE host boot delay: ${YELLOW}${grub_timeout}${NC}"
elif [ "$RESULTS" = 'TYPE02' ]
then
  # Set grub boot back to default
  msg "Setting PVE host boot delay..."
  sed -i "s/GRUB_TIMEOUT=.*/GRUB_TIMEOUT=${grub_timeout_default}/" /etc/default/grub
  # Update grub
  update-grub
  info "PVE host boot delay: ${YELLOW}${grub_timeout_default}${NC} (default)"
elif [ "$RESULTS" = 'TYPE00' ]
then
  return
fi

#---- Finish Line ------------------------------------------------------------------

section "Completion Status"
msg "Success. Task complete."
echo
#-----------------------------------------------------------------------------------