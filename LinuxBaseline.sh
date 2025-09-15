#!/bin/bash

# Linux System Baseline Script
# Purpose: Collect comprehensive system information for baseline documentation
# Author: lhakpa.t.sherpa005@gmail.com
# Date: 09/15/2025

BASELINE_DIR="/tmp/baseline_$(hostname)_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$BASELINE_DIR/baseline.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

print_section() {
    echo -e "\n${BLUE}=== $1 ===${NC}" | tee -a "$LOG_FILE"
}

run_command() {
    local cmd="$1"
    local output_file="$2"
    local description="$3"
    
    print_status "Collecting: $description"
    echo "# $description" >> "$output_file"
    echo "# Command: $cmd" >> "$output_file"
    echo "# Date: $(date)" >> "$output_file"
    echo "" >> "$output_file"
    
    if eval "$cmd" >> "$output_file" 2>&1; then
        echo "Status: SUCCESS" >> "$output_file"
    else
        echo "Status: FAILED (Exit code: $?)" >> "$output_file"
        print_warning "Command failed: $cmd"
    fi
    
    echo -e "\n${'='*80}\n" >> "$output_file"
}

check_privileges() {
    if [[ $EUID -eq 0 ]]; then
        print_status "Running as root - full access available"
        IS_ROOT=true
    else
        print_warning "Not running as root - some information may be limited"
        IS_ROOT=false
    fi
}

create_baseline_dir() {
    if mkdir -p "$BASELINE_DIR"; then
        print_status "Created baseline directory: $BASELINE_DIR"
    else
        print_error "Failed to create baseline directory"
        exit 1
    fi
}

collect_system_info() {
    print_section "SYSTEM INFORMATION"
    local output_file="$BASELINE_DIR/01_system_info.txt"
    
    run_command "uname -a" "$output_file" "Kernel and system information"
    run_command "hostnamectl" "$output_file" "System hostname and details"
    run_command "cat /etc/os-release" "$output_file" "Operating system release information"
    run_command "lsb_release -a" "$output_file" "LSB release information"
    run_command "uptime" "$output_file" "System uptime and load"
    run_command "date" "$output_file" "Current date and time"
    run_command "timedatectl" "$output_file" "Time and date settings"
    run_command "cat /proc/version" "$output_file" "Kernel version details"
    run_command "dmidecode -s system-product-name" "$output_file" "System product name"
    run_command "dmidecode -s system-manufacturer" "$output_file" "System manufacturer"
}

collect_hardware_info() {
    print_section "HARDWARE INFORMATION"
    local output_file="$BASELINE_DIR/02_hardware_info.txt"
    
    run_command "lscpu" "$output_file" "CPU information"
    run_command "cat /proc/cpuinfo" "$output_file" "Detailed CPU information"
    run_command "cat /proc/meminfo" "$output_file" "Memory information"
    run_command "free -h" "$output_file" "Memory usage"
    run_command "lsblk" "$output_file" "Block devices"
    run_command "fdisk -l" "$output_file" "Disk partition information"
    run_command "df -h" "$output_file" "Filesystem usage"
    run_command "lshw -short" "$output_file" "Hardware summary"
    run_command "lspci" "$output_file" "PCI devices"
    run_command "lsusb" "$output_file" "USB devices"
    run_command "cat /proc/scsi/scsi" "$output_file" "SCSI devices"
}

collect_network_info() {
    print_section "NETWORK CONFIGURATION"
    local output_file="$BASELINE_DIR/03_network_info.txt"
    
    run_command "ip addr show" "$output_file" "IP addresses and interfaces"
    run_command "ip route show" "$output_file" "Routing table"
    run_command "cat /etc/resolv.conf" "$output_file" "DNS configuration"
    run_command "cat /etc/hosts" "$output_file" "Local host entries"
    run_command "cat /etc/hostname" "$output_file" "System hostname"
    run_command "netstat -tulpn" "$output_file" "Network connections and listening ports"
    run_command "ss -tulpn" "$output_file" "Socket statistics"
    run_command "iptables -L -n -v" "$output_file" "Iptables rules"
    run_command "cat /etc/network/interfaces" "$output_file" "Network interfaces configuration (Debian/Ubuntu)"
    run_command "ls -la /etc/sysconfig/network-scripts/" "$output_file" "Network scripts (RHEL/CentOS)"
}

collect_services_info() {
    print_section "SERVICES AND PROCESSES"
    local output_file="$BASELINE_DIR/04_services_processes.txt"
    
    run_command "systemctl list-units --type=service --state=running" "$output_file" "Running services (systemd)"
    run_command "systemctl list-units --type=service --state=enabled" "$output_file" "Enabled services (systemd)"
    run_command "ps aux" "$output_file" "Running processes"
    run_command "ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem" "$output_file" "Processes sorted by memory usage"
    run_command "top -b -n 1" "$output_file" "System processes snapshot"
    run_command "chkconfig --list" "$output_file" "Service configuration (SysV)"
    run_command "crontab -l" "$output_file" "User crontab"
    
    if [[ $IS_ROOT == true ]]; then
        run_command "crontab -l -u root" "$output_file" "Root crontab"
        run_command "cat /etc/crontab" "$output_file" "System crontab"
        run_command "ls -la /etc/cron.*/" "$output_file" "Cron directories"
    fi
}

collect_user_info() {
    print_section "USER AND GROUP INFORMATION"
    local output_file="$BASELINE_DIR/05_users_groups.txt"
    
    run_command "cat /etc/passwd" "$output_file" "User accounts"
    run_command "cat /etc/group" "$output_file" "Group information"
    run_command "cat /etc/shadow" "$output_file" "Shadow password file"
    run_command "last -n 20" "$output_file" "Recent logins"
    run_command "lastlog" "$output_file" "Last login information"
    run_command "who" "$output_file" "Currently logged in users"
    run_command "w" "$output_file" "User activity"
    run_command "id" "$output_file" "Current user ID information"
    run_command "groups" "$output_file" "Current user groups"
}

collect_security_info() {
    print_section "SECURITY CONFIGURATION"
    local output_file="$BASELINE_DIR/06_security_config.txt"
    
    run_command "cat /etc/ssh/sshd_config" "$output_file" "SSH daemon configuration"
    run_command "cat /etc/sudoers" "$output_file" "Sudo configuration"
    run_command "ls -la /etc/sudoers.d/" "$output_file" "Additional sudo files"
    run_command "sestatus" "$output_file" "SELinux status"
    run_command "getenforce" "$output_file" "SELinux enforcement mode"
    run_command "apparmor_status" "$output_file" "AppArmor status"
    run_command "ufw status" "$output_file" "UFW firewall status"
    run_command "cat /etc/security/limits.conf" "$output_file" "Security limits"
    run_command "cat /etc/login.defs" "$output_file" "Login definitions"
    run_command "cat /etc/pam.d/common-auth" "$output_file" "PAM authentication config"
    run_command "find / -perm -4000 -type f 2>/dev/null" "$output_file" "SUID files"
    run_command "find / -perm -2000 -type f 2>/dev/null" "$output_file" "SGID files"
}

collect_software_info() {
    print_section "SOFTWARE AND PACKAGES"
    local output_file="$BASELINE_DIR/07_software_packages.txt"
    
    run_command "dpkg -l" "$output_file" "Installed packages (dpkg)"
    run_command "apt list --installed" "$output_file" "Installed packages (apt)"
    run_command "cat /etc/apt/sources.list" "$output_file" "APT sources"
    run_command "ls -la /etc/apt/sources.list.d/" "$output_file" "Additional APT sources"
    
    run_command "rpm -qa" "$output_file" "Installed packages (rpm)"
    run_command "yum list installed" "$output_file" "Installed packages (yum)"
    run_command "dnf list installed" "$output_file" "Installed packages (dnf)"
    run_command "cat /etc/yum.repos.d/*.repo" "$output_file" "YUM repositories"
    
    run_command "snap list" "$output_file" "Snap packages"
    
    run_command "flatpak list" "$output_file" "Flatpak packages"
    
    run_command "pip list" "$output_file" "Python packages (pip)"
    run_command "pip3 list" "$output_file" "Python3 packages (pip3)"
}

collect_log_info() {
    print_section "LOG FILES AND SYSTEM LOGS"
    local output_file="$BASELINE_DIR/08_logs_info.txt"
    
    run_command "ls -la /var/log/" "$output_file" "Log directory contents"
    run_command "journalctl --no-pager -n 50" "$output_file" "Recent systemd journal entries"
    run_command "tail -n 20 /var/log/syslog" "$output_file" "Recent syslog entries"
    run_command "tail -n 20 /var/log/messages" "$output_file" "Recent system messages"
    run_command "tail -n 20 /var/log/auth.log" "$output_file" "Recent authentication logs"
    run_command "tail -n 20 /var/log/secure" "$output_file" "Recent security logs"
    run_command "dmesg | tail -n 20" "$output_file" "Recent kernel messages"
}

collect_environment_info() {
    print_section "ENVIRONMENT AND CONFIGURATION"
    local output_file="$BASELINE_DIR/09_environment_config.txt"
    
    run_command "env" "$output_file" "Environment variables"
    run_command "cat /etc/environment" "$output_file" "System environment file"
    run_command "cat /etc/profile" "$output_file" "System profile"
    run_command "ls -la /etc/profile.d/" "$output_file" "Profile scripts"
    run_command "cat ~/.bashrc" "$output_file" "User bashrc"
    run_command "cat ~/.bash_profile" "$output_file" "User bash profile"
    run_command "mount" "$output_file" "Mounted filesystems"
    run_command "cat /etc/fstab" "$output_file" "Filesystem table"
    run_command "cat /proc/mounts" "$output_file" "Current mounts"
    run_command "lsmod" "$output_file" "Loaded kernel modules"
    run_command "cat /etc/modules" "$output_file" "Modules configuration"
}

collect_performance_info() {
    print_section "PERFORMANCE AND RESOURCE USAGE"
    local output_file="$BASELINE_DIR/10_performance_info.txt"
    
    run_command "vmstat 1 5" "$output_file" "Virtual memory statistics"
    run_command "iostat -x 1 5" "$output_file" "I/O statistics"
    run_command "sar -u 1 5" "$output_file" "CPU utilization"
    run_command "sar -r 1 5" "$output_file" "Memory utilization"
    run_command "sar -d 1 5" "$output_file" "Disk activity"
    run_command "cat /proc/loadavg" "$output_file" "Load average"
    run_command "cat /proc/stat" "$output_file" "System statistics"
    run_command "cat /proc/interrupts" "$output_file" "Interrupt information"
}

generate_summary() {
    print_section "GENERATING SUMMARY REPORT"
    local summary_file="$BASELINE_DIR/00_SUMMARY.txt"
    
    cat > "$summary_file" << EOF
LINUX SYSTEM BASELINE SUMMARY
=============================
Generated: $(date)
Hostname: $(hostname)
Script Version: 1.0

SYSTEM OVERVIEW:
- OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2 2>/dev/null || echo "Unknown")
- Kernel: $(uname -r)
- Architecture: $(uname -m)
- Uptime: $(uptime | cut -d',' -f1)
- Load Average: $(cat /proc/loadavg | cut -d' ' -f1-3)

HARDWARE SUMMARY:
- CPU: $(grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2 | sed 's/^ *//' 2>/dev/null || echo "Unknown")
- CPU Cores: $(nproc 2>/dev/null || echo "Unknown")
- Memory: $(free -h | grep "Mem:" | awk '{print $2}' 2>/dev/null || echo "Unknown")
- Disk Space: $(df -h / | tail -1 | awk '{print $2}' 2>/dev/null || echo "Unknown")

NETWORK SUMMARY:
- Primary IP: $(ip route get 8.8.8.8 2>/dev/null | head -1 | awk '{print $7}' || echo "Unknown")
- Hostname: $(hostname)
- Domain: $(dnsdomainname 2>/dev/null || echo "Not set")

SECURITY STATUS:
- SELinux: $(getenforce 2>/dev/null || echo "Not available")
- AppArmor: $(if command -v apparmor_status &> /dev/null; then apparmor_status | head -1; else echo "Not available"; fi)
- Firewall: $(if command -v ufw &> /dev/null; then ufw status | head -1; else echo "Unknown"; fi)

FILES GENERATED:
EOF
    
    for file in "$BASELINE_DIR"/*.txt; do
        echo "- $(basename "$file")" >> "$summary_file"
    done
    
    cat >> "$summary_file" << EOF

BASELINE DIRECTORY: $BASELINE_DIR

This baseline can be used for:
- System documentation
- Change management
- Security auditing
- Compliance reporting
- Troubleshooting reference
- Disaster recovery planning

EOF
}

create_archive() {
    print_section "CREATING ARCHIVE"
    local archive_name="/tmp/baseline_$(hostname)_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    if tar -czf "$archive_name" -C "$(dirname "$BASELINE_DIR")" "$(basename "$BASELINE_DIR")"; then
        print_status "Archive created: $archive_name"
        print_status "Archive size: $(ls -lh "$archive_name" | awk '{print $5}')"
    else
        print_error "Failed to create archive"
    fi
}

main() {
    echo -e "${BLUE}"
    echo "===Linux System Baseline Script==="
    echo -e "${NC}\n"
    
    check_privileges
    create_baseline_dir
    
    echo "Baseline collection started: $(date)" > "$LOG_FILE"
    
    collect_system_info
    collect_hardware_info
    collect_network_info
    collect_services_info
    collect_user_info
    collect_security_info
    collect_software_info
    collect_log_info
    collect_environment_info
    collect_performance_info
    
    generate_summary
    create_archive
    
    print_section "BASELINE COLLECTION COMPLETE"
    print_status "Baseline directory: $BASELINE_DIR"
    print_status "Log file: $LOG_FILE"
    print_status "All files have been collected and organized"
    
    echo -e "\n${GREEN}Baseline collection completed successfully!${NC}"
    echo -e "Review the files in: ${YELLOW}$BASELINE_DIR${NC}"
}

trap 'print_error "Script interrupted"; exit 1' INT TERM

main "$@"