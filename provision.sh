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

    # Install ufw if not installed
    if ! dpkg -s ufw 2> /dev/null | grep -q '^Status: install ok installed'; then
        sudo apt-get update
        sudo apt-get install -y ufw
    fi

    # Get ufw status
    local ufw
    ufw=$(sudo ufw status verbose)

    # If logging disabled or not low, enable logging low
    local ufw_log
    ufw_log=$( printf '%s' "$ufw" | awk '$1 == "Logging:" {print $2 $3}')
    if [[ ! "$ufw_log" =~ ^(on|On|ON)\((low|Low|LOW)\)$ ]]; then
        sudo ufw logging low
    fi

    #Update Firewall to allow only trusted IP addresses on port 22
    local counter=1
    local good_rule=0
    declare -a bad_rules
    local ufw_rules
    ufw_rules=$(printf '%s' "$ufw" | sed '1,/^--/d')
    if [[ ! "$ufw_rules" =~ ^22/tcp[[:space:]]+ALLOW[[:space:]]IN[[:space:]]192\.168\.40\.0/24$ ]]; then

        # Check each rule
        while read -r line; do
            
            # Note if desired rule present, record all undesired rules
            if [[ "$line" =~ ^22/tcp[[:space:]]+ALLOW[[:space:]]IN[[:space:]]192\.168\.40\.0/24$ ]]; then
                good_rule=1
            else
                bad_rules+=("$counter")
            fi
            ((counter++))
        done <<< "$ufw_rules"

        # Remove undesired rules
        local i
        for (( i=${#bad_rules[@]}-1 ; i>=0 ; i-- )); do
            sudo ufw --force delete "${bad_rules[i]}"
        done

        # Add desired rule if not present
        if (( ! good_rule )); then
            sudo ufw allow from 192.168.40.0/24 to any port 22 proto tcp
        fi
    fi

    # If firewall inactive, enable
    local ufw_status
    ufw_status=$(printf '%s' "$ufw" | awk '$1 == "Status:" {print $2}')
    if [[ "$ufw_status" != 'active' ]]; then
        sudo ufw --force enable
    fi

    # Verify firewall configurations
    ufw=$(sudo ufw status verbose)
    grep -q 'Status: active' <<< "$ufw" &&
    grep -q 'Logging: on (low)' <<< "$ufw" &&
    grep -qE '22/tcp[[:space:]]+ALLOW IN[[:space:]]+192\.168\.40\.0/24' <<< "$ufw" ||
    {
        echo "ERROR: firewall validation failed"
        return 1
    }

}

configure_fail2ban
configure_ssh
configure_firewall