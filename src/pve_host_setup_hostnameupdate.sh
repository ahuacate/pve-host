#!/usr/bin/env bash
# ----------------------------------------------------------------------------------
# Filename:     pve_host_setup_hostnameupdate.sh
# Description:  Script to change PVE host hostname
# ----------------------------------------------------------------------------------

#---- Applying changes to PVE Host
if [ $SET_PVE_HOST_HOSTNAME = 0 ]
then
    section "Applying changes to PVE Host"
    msg "Applying new hostname to PVE host system..."
    hostnamectl set-hostname $PVE_HOSTNAME
    msg "Updating new hostname in /etc/hosts file..."
    sed -i "s/$HOSTNAME/${PVE_HOSTNAME}/g" /etc/hosts >/dev/null
    msg "Updating new hostname in /etc/postfix/main.cf..."
    sed -i "s/$HOSTNAME/${PVE_HOSTNAME}/g" /etc/postfix/main.cf >/dev/null
    msg "Updating new hostname in /etc/pve/storage.cfg file..."
    sed -i "s/$HOSTNAME/${PVE_HOSTNAME}/g" /etc/pve/storage.cfg 2>/dev/null
    msg "Waiting for PVE to create a new ${PVE_HOSTNAME} node...\n  (be patient, this might take a while!)"
    while [ ! -d /etc/pve/nodes/${PVE_HOSTNAME} ]; do sleep 1; done
    msg "Creating backup of '$HOSTNAME' configuration files..."
    cp -r /etc/pve/nodes/$HOSTNAME . 2>/dev/null
    msg "Copying $HOSTNAME configuration files to new $PVE_HOSTNAME node..."
    cp $(pwd)/$HOSTNAME/qemu-server/* /etc/pve/nodes/$PVE_HOSTNAME/qemu-server 2>/dev/null
    # msg "Copying $HOSTNAME lxc configuration files to new ${PVE_HOSTNAME} node..."
    # cp $(pwd)/$HOSTNAME/lxc/* /etc/pve/nodes/${PVE_HOSTNAME}/lxc 2>/dev/null
    msg "Removing old $HOSTNAME configuration files from /etc/pve/nodes..."
    rm -R /etc/pve/nodes/$HOSTNAME >/dev/null
    info "PVE hostname has been updated and set: ${YELLOW}$PVE_HOSTNAME${NC}"
    echo
fi
#-----------------------------------------------------------------------------------