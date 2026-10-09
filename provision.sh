#!/bin/bash

# Normalize variables and files for clean comparison
normalize() {
    grep -vE '^\s*(#|$)' | sed 's/[[:blank:]]\+/ /g' | sort
}

configure_ssh() {

    # Create sshd config template and path variables
    local current=""
    local desired
    local backup=""
    local sshd_path="/etc/ssh/sshd_config.d/99-provision.conf"
    local sshd_config=$(cat <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
PermitEmptyPasswords no
LoginGraceTime 30
MaxAuthTries 3
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
PermitUserEnvironment no
HostbasedAuthentication no
IgnoreRhosts yes
EOF
)

    # Normalize current config if file exists
    if [[ -f "$sshd_path" ]]; then
        current=$(normalize < "$sshd_path")
    fi

    # Normalize desired config variable
    desired=$(printf '%s\n' "$sshd_config" | normalize)

    # If file doesn't exist or is not correct, then update
    if [[ ! -f "$sshd_path" || "$current" != "$desired" ]]; then

        # Create backup of config file if exists
        if [[ -f "$sshd_path" ]]; then
            backup="/etc/ssh/sshd_config.d/99-provision.backup.$(date +%F-%H%M%S)"
            if sudo cp -p -- "$sshd_path" "$backup"; then
            else
                echo "ERROR: backup failed, aborting before modifying sshd config" >&2
                exit 1
            fi
        fi

        # Copy desired config to sshd config
        printf '%s\n' "$sshd_config" | sudo tee "$sshd_path" >/dev/null

        # Validate sshd config & restart sshd if valid
        if sudo sshd -t; then
            if ! sudo systemctl restart sshd; then
                echo "ERROR: sshd restart failed"
                return 1
            fi
        else
            echo "ERROR: sshd configuration validation failed"

            # Rollback sshd config file if exists, otherwise remove sshd_path
            if [[ -n "$backup" && -f "$backup" ]]; then
                sudo cp "$backup" "$sshd_path"
                if ! sudo sshd -t; then
                    echo "ERROR: restored sshd configuration is also invalid"
                fi
            else
                sudo rm -f "$sshd_path"
            fi

            return 1
        fi
    fi
}

configure_fail2ban() {

    # Create jail config template and path variables
    local config_changed=0
    local jail_path="/etc/fail2ban/jail.d/sshd.local"
    local jail_config=$(cat <<EOF
[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 3
bantime = 3600
findtime = 600
EOF
)

    # Install fail2ban if not already installed
    if ! dpkg -s fail2ban 2> /dev/null | grep -q '^Status: install ok installed'; then
        sudo apt install -y fail2ban
    fi

    # Check if jail file is present and correct, if not update
    if [[ ! -f "$jail_path" ]] || [[ "$(<"$jail_path")" != "$jail_config" ]]; then
        printf '%s\n' "$jail_config" | sudo tee "$jail_path" >/dev/null
        config_changed=1
    fi

    # Check if fail2ban is enabled, if not enable
    if ! systemctl is-enabled --quiet fail2ban; then
        sudo systemctl enable fail2ban
    fi

    # Check if fail2ban is running, if not start
    if ! systemctl is-active --quiet fail2ban; then
        sudo systemctl start fail2ban
    elif [[ config_changed == 1 ]]; then
        sudo systemctl restart fail2ban
    fi

}

configure_firewall() {

    local ufw_status
    local ufw_log

    # If firewall inactive, enable
    ufw_status=$(sudo ufw status verbose | awk '$1 == "Status:" {print $2}')
    if [[ "$ufw_status" == 'inactive' ]]; then
        sudo ufw --force enable
    fi

    # If logging disabled or not low, enable logging low
    ufw_log=$(sudo ufw status verbose | awk '$1 == "Logging:" {print $2 $3}')
    if [[ ! "$ufw_log" == "on(low)" ]]; then
        sudo ufw logging low
    fi


    #Update Firewall to allow only trusted IP addresses on port 22
    sudo ufw allow from 192.168.40.0/24 to any port 22 proto tcp



    # Verify firewall configurations
    ufw_status=$(sudo ufw status verbose)
    grep -q 'Status: active' <<< "$ufw_status" &&
    grep -q 'Logging: on (low)' <<< "$ufw_status" &&
    grep -qE '22/tcp[[:space:]]+ALLOW IN[[:space:]]+192\.168\.40\.0/24' <<< "$ufw_status" ||
    {
        echo "ERROR: firewall validation failed"
        return 1
    }

}

configure_fail2ban
configure_ssh
configure_firewall