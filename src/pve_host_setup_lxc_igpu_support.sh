#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_setup_lxc_igpu_support.sh
# Description:  Source script for setting up host Intel/Amd iGPU support (qsv, VA-API etc)
# ----------------------------------------------------------------------------------

#---- Bash command to run script ---------------------------------------------------

#bash -c "$(wget -qLO - https://raw.githubusercontent.com/ahuacate/pve-host/main/pve_host_toolbox.sh)"

#---- Source -----------------------------------------------------------------------
#---- Dependencies -----------------------------------------------------------------
#---- Static Variables -------------------------------------------------------------

# Easy Script Section Header Body Text
SECTION_HEAD='PVE Host Intel or Amd iGPU support'

# Check for PVE Hostname mod
if [ -z "${HOSTNAME_FIX+x}" ]; then
    PVE_HOSTNAME=$HOSTNAME
fi

# Grub file
grub_file=/etc/default/grub

#---- Other Variables --------------------------------------------------------------
#---- Other Files ------------------------------------------------------------------
#---- Body -------------------------------------------------------------------------

#---- Checking PVE Host Prerequisites

# Check for grub file
if [ ! -e "$grub_file" ]; then
    section "Checking grub support"
    warn "No grub file detected. Exiting script..."
    sleep 1
    return 0
fi

# Check for Intel AMD integrated graphics
if ! lscpu | grep -q -E "Vendor ID:\s*(GenuineIntel|AuthenticAMD)"; then
    section "Checking CPU support"
    warn "Your CPU vendor is not supported.. Exiting script..."
    sleep 1
    return 0
fi


#---- Introduction
section "Introduction"

msg_box "#### PLEASE READ CAREFULLY - INTEL/AMD iGPU SUPPORT ####

To enable your LXCs to utilize your CPUs processors integrated iGPU, such as Intel QuickSync or VA-API, resulting in significantly improved rendering speeds, you must modify the Proxmox host's Grub bootloader file /etc/default/grub.

Before proceeding, take note of the following considerations:

1. Ensure that your hardware supports IOMMU (I/O Memory Management Unit) interrupt remapping, including the CPU and the mainboard.
2. Check if your Intel or AMD CPU includes a built-in GPU (iGPU).
2. Familiarize yourself with the functionality of this script by visiting the following resource: https://pve.proxmox.com/wiki/PCI(e)_Passthrough"
echo
while true
do
  read -p "Proceed to setup iGPU support with '/etc/default/grub' file edits [y/n]?: " -n 1 -r YN
  echo
  case $YN in
    [Yy]*)
      msg "Proceeding..."
      echo
      break
      ;;
    [Nn]*)
      info "The User has chosen to not to proceed..."
      echo
      sleep 1
      return 0
      ;;
    *)
      warn "Error! Entry must be 'y' or 'n'. Try again..."
      echo
      ;;
  esac
done


#---- Intel CPU iGPU 

# Edits for Intel CPUs only
if lscpu | grep -q "Vendor ID:\s*GenuineIntel"; then
    # Configuring Intel Low Power Encoders
    section "Enable Intel Low-Power Encoders"

    msg "If you have an Intel CPU with a low-power wattage model and QuickSync support, consider enabling low-power encoders. Low-power encoding is a feature available on certain Intel processors, optimizing QuickSync for ultra-efficient video encoding with minimal power consumption."
    OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE02" )
    OPTIONS_LABELS_INPUT=( "Disable" "Enable - setup for low-power encoding support" )
    makeselect_input2
    singleselect SELECTED "$OPTIONS_STRING"
    if [ "$RESULTS" = TYPE01 ]; then
        enable_low_power='0'  # Disable low power encoders
    elif [ "$RESULTS" = TYPE02 ]; then
        enable_low_power='1'  # Enable low power encoders
    fi

    # Update '/etc/default/grub' 
    eval "$(grep ^GRUB_CMDLINE_LINUX_DEFAULT $grub_file)"
    declare -i updated=0
    if [[ "${GRUB_CMDLINE_LINUX_DEFAULT}" != *intel_iommu=on* ]]; then
        echo "Adding 'intel_iommu=on'"
        GRUB_CMDLINE_LINUX_DEFAULT+=" intel_iommu=on"
        updated=1
    fi

    # if [[ "${GRUB_CMDLINE_LINUX_DEFAULT}" != *i915.enable_guc=2* ]] && [ "$enable_low_power" = 1 ]; then
    #     echo "Adding 'i915.enable_guc=2'"
    #     GRUB_CMDLINE_LINUX_DEFAULT+=" i915.enable_guc=2"
    #     updated=1
    # fi

    if (( updated )); then
        cp $grub_file ${grub_file}.bk
        sed -i -e "s/^GRUB_CMDLINE_LINUX_DEFAULT=.*\$/GRUB_CMDLINE_LINUX_DEFAULT=\"${GRUB_CMDLINE_LINUX_DEFAULT}\"/" $grub_file
        update-grub
        echo "GRUB configuration updated setting: ${GRUB_CMDLINE_LINUX_DEFAULT}"
        echo
    fi

    # Enable GUC in Proxmox host
    declare -i updated_modprobe=0
    modprobe_entries=("options i915 enable_guc=2" "options i915 enable_fbc=1")  # Lines to add to /etc/modules
    modprobe_file="/etc/modprobe.d/i915.conf"  # Path to the /etc/modules file
    if [ ! -e "$modprobe_file" ]; then
        touch "$modprobe_file"  # create mod file if missing
    fi
    # Check if the modules exist in the file
    for entry in "${modprobe_entries[@]}"; do
        if ! grep -q "^$entry$" "$modprobe_file"; then
            if [ "$enable_low_power" = 0 ] && [[ "$entry" =~ enable_guc ]]; then
                continue  # Skip if $enable_low_power is disabled
            fi
            echo "Adding '$entry' to $modprobe_file"
            echo "$entry" >> $modprobe_file
            updated_modprobe=1
        fi
    done

    # Check for 'ehl_gux_70.1.1.bin' in /lib/firmware/i915
    if [ ! -e '/lib/firmware/i915/ehl_gux_70.1.1.bin' ]; then
        wget -q --show-progress -O /lib/firmware/i915/ehl_gux_70.1.1.bin https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/i915/ehl_guc_70.1.1.bin
    fi
fi


#---- AMD CPU iGPU 

# Edits for AMD CPUs only
if lscpu | grep -q "Vendor ID:\s*AuthenticAMD"; then
    # Update '/etc/default/grub' 
    eval "$(grep ^GRUB_CMDLINE_LINUX_DEFAULT $grub_file)"
    declare -i updated=0
    if [[ "${GRUB_CMDLINE_LINUX_DEFAULT}" != *amd_iommu=on* ]]; then
        echo "Adding 'amd_iommu=on'"
        GRUB_CMDLINE_LINUX_DEFAULT+=" amd_iommu=on"
        updated=1
    fi

    if (( updated )); then
        cp $grub_file ${grub_file}.bk
        sed -i -e "s/^GRUB_CMDLINE_LINUX_DEFAULT=.*\$/GRUB_CMDLINE_LINUX_DEFAULT=\"${GRUB_CMDLINE_LINUX_DEFAULT}\"/" $grub_file
        update-grub
        echo "GRUB configuration updated setting: ${GRUB_CMDLINE_LINUX_DEFAULT}"
        echo
    fi
fi

#---- Update Kernel modules
msg "Checking kernel modules..."
declare -i updated_kernel=0
modules_to_add=("vfio" "vfio_iommu_type1" "vfio_pci" "vfio_virqfd")  # Lines to add to /etc/modules
modules_file="/etc/modules"  # Path to the /etc/modules file
# Check if the modules exist in the file
for module in "${modules_to_add[@]}"; do
    if ! grep -q "^$module$" "$modules_file"; then
        msg "Adding '$module' to $modules_file"
        echo "$module" | tee -a "$modules_file"
        updated_kernel=1
    fi
done

#---- Perform initramfs refresh
if (( updated_kernel )) || (( updated_modprobe )); then
    msg "Refresh your initramfs (only latest kernel)..."
    update-initramfs -u -k "$(uname -r)"
fi


#---- Reboot
section "Reboot Proxmox host"

msg "For Grub edits to take effect you must reboot your Proxmox host."
OPTIONS_VALUES_INPUT=( "TYPE01" "TYPE02" )
OPTIONS_LABELS_INPUT=( "Reboot now - Recommended (must be done)" "Skip - You must reboot at a later stage" )
makeselect_input2
singleselect SELECTED "$OPTIONS_STRING"
if [ "$RESULTS" = TYPE01 ]; then
    msg "Rebooting Proxmox host. Bye..."
    sleep 1
    reboot
elif [ "$RESULTS" = TYPE02 ]; then
    msg "The Grub bootloader changes will take effect after the next reboot."
fi
#-----------------------------------------------------------------------------------