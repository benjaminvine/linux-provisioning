#!/usr/bin/env bash

set -euo pipefail

# Config Variables
TRUSTED_CIDR="${TRUSTED_CIDR:-192.168.40.0/24}"
SSH_PORT="${SSH_PORT:-22}"
MIN_PREFIX=16

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

ip_to_int() {
    local IFS=.
    local -a o
    read -ra o <<< "$1"
    echo $(( o[0] * 16777216 + o[1] * 65536 + o[2] * 256 + o[3] ))
}

valid_cidr() {

    local cidr="${1:-}"
    if [[ -z "$cidr" ]]; then
        echo "ERROR: no IP address provided" >&2
        return 2
    fi
    local octet='(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])'
    local pattern="^${octet}\\.${octet}\\.${octet}\\.${octet}/([0-9]{1,2})$"
    if ! [[ $cidr =~ $pattern ]]; then
        echo "ERROR: '$cidr' is not a valid IPv4" >&2
        return 1
    fi
    local net="${cidr%/*}" prefix="${cidr#*/}"
    if (( prefix < MIN_PREFIX || prefix > 32 )); then
        echo "ERROR: subnet mask /$prefix outside allowed range /$MIN_PREFIX-/32" >&2
        return 1
    fi
    local mask net_int
    mask=$(( (0xFFFFFFFF * 2 ** (32 - prefix)) & 0xFFFFFFFF ))
    net_int=$(ip_to_int "$net")
    if (( (net_int & mask) != net_int )); then
        echo "ERROR: '$cidr' has host bits set" >&2
        return 1
    fi
}

ip_in_cidr() {
    local ip=$1 cidr=$2
    local prefix="${cidr#*/}"
    local mask ip_int net_int
    mask=$(( (0xFFFFFFFF * 2 ** (32 - prefix)) & 0xFFFFFFFF ))
    ip_int=$(ip_to_int "$ip")
    net_int=$(ip_to_int "${cidr%/*}")
    (( (ip_int & mask) == net_int ))
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

configure_firewall() {

    # VALIDATE GIVEN IP & SSH
    valid_cidr "$TRUSTED_CIDR"
    if ! [[ $SSH_PORT =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
        echo "ERROR: SSH_PORT '$SSH_PORT' is invalid" >&2
        return 1
    fi

    # INSTALL UFW - if not installed
    if ! dpkg -s ufw 2> /dev/null | grep -q '^Status: install ok installed'; then
        sudo apt-get update
        sudo apt-get install -y ufw
    fi

    # CHECK IP: Check Session is inside trusted range on allowed port
    local client_ip server_port
    read -r client_ip _ _ server_port <<< "$SSH_CONNECTION"
    if ! [[ $client_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "ERROR: SSH client '$client_ip' is not IPv4, cannot verify against $TRUSTED_CIDR" >&2
        return 1
    fi
    if [[ "$server_port" != "$SSH_PORT" ]]; then
        echo "ERROR: this session is on port $server_port, but the firewall will allow $SSH_PORT" >&2
        return 1
    fi
    if ! ip_in_cidr "$client_ip" "$TRUSTED_CIDR"; then
        echo "ERROR: your SSH client $client_ip is outside $TRUSTED_CIDR" >&2
        return 1
    fi

    # RULES: Update Firewall to allow only trusted IP addresses on port 22
    local good_rule=0
    local desired_rule="allow from $TRUSTED_CIDR to any port $SSH_PORT proto tcp"
    local desired_line="ufw $desired_rule"
    local ufw_rules
    ufw_rules=$(sudo ufw show added | sed '1d')

    # If no rules, add desired rules, otherwise check current rules
    if [[ -z "$ufw_rules" || "$ufw_rules" == "(None)" ]]; then
        sudo ufw allow from "$TRUSTED_CIDR" to any port "$SSH_PORT" proto tcp
    elif [[ "$ufw_rules" != "$desired_line" ]]; then

        # Check each rule
        local line
        while read -r line; do
            
            # Note if desired rule present, record all undesired rules
            if [[ "$line" == "$desired_line" ]]; then
                good_rule=1
            else
                local -a rule_args
                read -ra rule_args <<< "${line#ufw }"
                sudo ufw --force delete "${rule_args[@]}"
            fi
        done <<< "$ufw_rules"

        # Add desired rule if not present
        if (( ! good_rule )); then
            local -a add_args
            read -ra add_args <<< "$desired_rule"
            sudo ufw "${add_args[@]}"
        fi
    fi

    # ENABLE FIREWALL - if firewall is inactive
    local ufw
    ufw=$(sudo ufw status verbose)
    if ! grep -q '^Status: active' <<< "$ufw"; then
        sudo ufw --force enable
        ufw=$(sudo ufw status verbose)
    fi

    # LOGGING - ensure logging low
    if ! grep -q '^Logging: on (low)' <<< "$ufw"; then
        sudo ufw logging low
    fi

    # DEFAULT POLICIES
    local ufw_policy
    ufw_policy=$(grep '^Default:' <<< "$ufw" || true)
    local policy_pat='^Default: ([a-z]+) \(incoming\), ([a-z]+) \(outgoing\), ([a-z]+) \(routed\)'
    if ! [[ $ufw_policy =~ $policy_pat ]]; then
        echo "ERROR: cannot parse default policies from: '$ufw_policy'" >&2
        return 1
    fi
    [[ ${BASH_REMATCH[1]} == deny ]] || sudo ufw default deny incoming
    [[ ${BASH_REMATCH[2]} == allow ]] || sudo ufw default allow outgoing
    if [[ ${BASH_REMATCH[3]} != deny && ${BASH_REMATCH[3]} != disabled ]]; then
        sudo ufw default deny routed
    fi

    # Verify firewall configurations
    ufw=$(sudo ufw status verbose)
    ufw_policy=$(grep '^Default:' <<< "$ufw")
    local rules
    rules=$(sudo ufw show added | grep '^ufw' || true)
    grep -q 'Status: active' <<< "$ufw" || { echo "FAIL: firewall not active" >&2; return 1; }
    grep -q 'Logging: on (low)' <<< "$ufw" || { echo "FAIL: logging is not on low" >&2; return 1; }
    [[ "$rules" == "$desired_line" ]] || { echo "FAIL: firewall rule set is not: $desired_line" >&2; return 1; }
    if [[ $ufw_policy =~ $policy_pat ]]; then
        [[ ${BASH_REMATCH[1]} == deny ]] || { echo "FAIL: incoming policy" >&2; return 1; }
        [[ ${BASH_REMATCH[2]} == allow ]] || { echo "FAIL: outgoing policy" >&2; return 1; }
        [[ ${BASH_REMATCH[3]} == deny || ${BASH_REMATCH[3]} == disabled ]] || { echo "FAIL: routed policy" >&2; return 1; }
    fi
}
main() { configure_fail2ban; configure_ssh; configure_firewall; }
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
