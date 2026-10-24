#!/usr/bin/env bash

set -euo pipefail

# Normalize variables and files for clean comparison
normalize() {
    { grep -vE '^[[:space:]]*(#|$)' || [[ $? -eq 1 ]]; } | sed 's/[[:blank:]]\+/ /g' | sort
}

# Returns true if file exists, is non-empty, and has valid ssh key(s)
has_valid_key() {
    local file=$1
    [[ -s "$file" ]] && ssh-keygen -l -f "$file" &>/dev/null
}

# Get effective PasswordAuthentication setting
eff_pass_auth() {
    sudo sshd -T | awk '$1 == "passwordauthentication" {print $2}'
}

# Checks for effective PasswordAuthentication setting with expected value
check_effective() {
    local expect_no=$1 user=$2 effective
    effective=$(eff_pass_auth) || {
        echo "ERROR: could not read effective sshd config" >&2
        return 1
    }
    if (( expect_no )) && [[ "$effective" != 'no' ]]; then
        echo "ERROR: effective PasswordAuthentication is '$effective', expected 'no'" >&2
        return 1
    fi
    if (( ! expect_no )) && [[ "$effective" == 'no' ]]; then
        echo "WARN: no valid key for $user but effective PasswordAuthentication is 'no', you may be locked out" >&2
        return 1
    fi
}

# Rollback sshd config if any errors
rollback_sshd() {
    local backup=$1 target=$2
    # Rollback sshd config file if exists, otherwise remove sshd_path
    if [[ -n "$backup" && -f "$backup" ]]; then
        if ! sudo cp -p -- "$backup" "$target"; then
            echo "ERROR: rollback copy failed, sshd config may be inconsistent" >&2
            return 1
        fi
        if ! sudo sshd -t; then
            echo "ERROR: restored sshd configuration is also invalid" >&2
            return 1
        fi
    else
        sudo rm -f -- "$target"
    fi
}

configure_ssh() {

    # Create sshd config template and path variables
    local user
    user=$(id -un $EUID)
    local user_home=""
    local ssh_dir=""
    local auth_keys=""
    local current=""
    local desired=""
    local backup=""
    local expect_no=1
    local effective
    local sshd_path="/etc/ssh/sshd_config.d/00-provision.conf"
    local sshd_config
    sshd_config=$(cat <<'EOF'
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

    # VALIDATE AUTH_KEYS
    # Check if script was ran by root
    if (( EUID == 0 )); then
        echo "ERROR: run as normal user, not root" >&2
        return 1
    fi

    # Get User Home Dir and authorized_keys path
    user_home=$(getent passwd "$user" | cut -d: -f6)
    ssh_dir="$user_home/.ssh"
    auth_keys="$user_home/.ssh/authorized_keys"

    # Verify Owner of .ssh and authorized_keys
    local path
    for path in "$ssh_dir" "$auth_keys"; do
        [[ -e $path ]] || continue
        if [[ $(stat -c '%U' "$path") != "$user" ]]; then
            echo "ERROR: $path is not owned by $user" >&2
            return 1
        fi
    done    
    
    # Verify permissions on .ssh
    if [[ -d "$ssh_dir" && $(stat -c '%a' "$ssh_dir") != 700 ]]; then
        chmod 700 "$ssh_dir"
    fi

    # Verify permission on authorized_keys
    if [[ -f "$auth_keys" && $(stat -c '%a' "$auth_keys") != 600 ]]; then
        chmod 600 "$auth_keys"
    fi



    # If file doesn't exist, is empty, or has invalid ssh key, remove PassAuth no from template var
    if ! has_valid_key "$auth_keys"; then
        echo "warn: no valid ssh key, leaving PasswordAuthentication unmanaged" >&2
        sshd_config=$(grep -v '^PasswordAuthentication' <<< "$sshd_config")
        expect_no=0
    fi

    # VALIDATE OR UPDATE SSHD_CONFIG
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
            backup="/etc/ssh/sshd_config.d/00-provision.backup.$(date +%F-%H%M%S)"
            if ! sudo cp -p -- "$sshd_path" "$backup"; then
                echo "ERROR: backup failed, aborting before modifying sshd config" >&2
                return 1
            fi
        fi

        # Copy desired config to sshd config
        printf '%s\n' "$sshd_config" | sudo tee "$sshd_path" >/dev/null

        # Validate sshd config & restart sshd if valid
        if ! sudo sshd -t; then
            echo "ERROR: sshd configuration validation failed, rolling back version" >&2
            rollback_sshd "$backup" "$sshd_path" || true   #already reported its own error
            return 1
        fi
        if ! check_effective "$expect_no" "$user"; then
            rollback_sshd "$backup" "$sshd_path" || true
            return 1
        fi
        if ! sudo systemctl restart sshd; then
            echo "ERROR: sshd restart failed, rolling back version" >&2
            if rollback_sshd "$backup" "$sshd_path"; then
                sudo systemctl restart sshd || true
            fi
            return 1
        fi
    fi
}

configure_fail2ban() {

    # Create jail config template and path variables
    local config_changed=0
    local jail_path="/etc/fail2ban/jail.d/sshd.local"
    local jail_config
    jail_config=$(cat <<'EOF'
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
    if [[ $(dpkg-query -W -f='${Status}' fail2ban 2>/dev/null) != 'install ok installed' ]]; then
        sudo apt-get install -y fail2ban
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
    elif [[ "$config_changed" == 1 ]]; then
        sudo systemctl restart fail2ban
    fi

}

main() { configure_fail2ban; configure_ssh; }
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi