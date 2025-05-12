#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to check command existence
check_command() {
    command -v "$1" &> /dev/null
}

# Install package with appropriate package manager
install_pkg() {
    local pkg_manager=""
    if check_command apt; then
        pkg_manager="apt"
        sudo apt update && sudo apt install -y "$@"
    elif check_command yum; then
        pkg_manager="yum"
        sudo yum install -y "$@"
    elif check_command dnf; then
        pkg_manager="dnf"
        sudo dnf install -y "$@"
    else
        echo -e "${RED}Unsupported package manager. Install $@ manually.${NC}"
        return 1
    fi
    return 0
}

# Install snap and core snap
install_snap() {
    if install_pkg snapd && sudo systemctl enable --now snapd; then
        sudo snap install core
        return 0
    fi
    echo -e "${RED}Failed to set up snapd.${NC}"
    return 1
}

# Install tool via snap
install_snap_tool() {
    local tool="$1" log_file="/tmp/${tool}_snap.log"
    # Use --classic for feroxbuster due to full system access requirement
    local snap_args=""
    if [ "$tool" = "feroxbuster" ]; then
        snap_args="--classic"
    fi
    if sudo snap install "$tool" $snap_args 2>"$log_file"; then
        if check_command "$tool"; then
            echo -e "${GREEN}$tool installed via snap.${NC}"
            return 0
        else
            echo -e "${RED}$tool snap installed but not found in PATH. See $log_file.${NC}"
        fi
    else
        echo -e "${RED}Failed to install $tool via snap. See $log_file.${NC}"
    fi
    return 1
}

# Clone and build tool via Git
install_git_tool() {
    local tool="$1" repo_url="$2" build_cmd="$3" build_dir="$4" binary="$5" log_file="/tmp/${tool}_git.log"
    if ! check_command git; then
        echo -e "${RED}Git not installed. Installing git...${NC}"
        install_pkg git || { echo -e "${RED}Failed to install git. Cannot build $tool.${NC}"; return 1; }
    fi
    if [[ "$tool" == "nuclei" || "$tool" == "hugo" ]] && ! check_command go; then
        echo -e "${RED}Go not installed. Installing go...${NC}"
        install_pkg snapd && sudo snap install go --classic && sudo ln -s /snap/bin/go /usr/bin/go || { echo -e "${RED}Failed to install go. Cannot build $tool.${NC}"; return 1; }
    fi
    if [[ "$tool" == "feroxbuster" ]] && ! check_command cargo; then
        echo -e "${RED}Cargo not installed. Installing rust...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || { echo -e "${RED}Failed to install rustup. Cannot build $tool.${NC}"; return 1; }
        source "$HOME/.cargo/env" || { echo -e "${RED}Failed to set up rust environment.${NC}"; return 1; }
        rustc --version >>"$log_file" 2>&1 || { echo -e "${RED}Rust installation failed. See $log_file.${NC}"; return 1; }
    fi
    echo -e "${BLUE}Cloning $tool repository from $repo_url...${NC}" | tee -a "$log_file"
    git clone "$repo_url" "/tmp/$tool" >>"$log_file" 2>&1
    if [ -d "/tmp/$tool" ]; then
        cd "/tmp/$tool"
        echo -e "${BLUE}Building $tool with: $build_cmd...${NC}" | tee -a "$log_file"
        eval "$build_cmd" >>"$log_file" 2>&1
        if [ -f "$binary" ]; then
            sudo mv "$binary" /usr/local/bin/
            sudo chmod +x "/usr/local/bin/$tool"
            cd - >/dev/null
            rm -rf "/tmp/$tool"
            echo -e "${GREEN}$tool installed via Git build.${NC}"
            return 0
        else
            echo -e "${RED}Failed to build $tool binary. See $log_file.${NC}"
            cd - >/dev/null
            rm -rf "/tmp/$tool"
            return 1
        fi
    else
        echo -e "${RED}Failed to clone $tool repository. See $log_file.${NC}"
        return 1
    fi
}

# Install feroxbuster binary as fallback
install_feroxbuster_binary() {
    local log_file="/tmp/feroxbuster_binary.log"
    echo -e "${BLUE}Attempting to install pre-built feroxbuster binary...${NC}" | tee -a "$log_file"
    sudo mkdir -p /usr/local/bin
    curl -sL https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip -o /tmp/feroxbuster.zip >>"$log_file" 2>&1
    if [ -f /tmp/feroxbuster.zip ]; then
        unzip /tmp/feroxbuster.zip -d /tmp/feroxbuster >>"$log_file" 2>&1
        if [ -f /tmp/feroxbuster/feroxbuster ]; then
            sudo mv /tmp/feroxbuster/feroxbuster /usr/local/bin/
            sudo chmod +x /usr/local/bin/feroxbuster
            rm -rf /tmp/feroxbuster /tmp/feroxbuster.zip
            echo -e "${GREEN}feroxbuster installed via pre-built binary.${NC}"
            return 0
        else
            echo -e "${RED}Failed to extract feroxbuster binary. See $log_file.${NC}"
            rm -rf /tmp/feroxbuster /tmp/feroxbuster.zip
            return 1
        fi
    else
        echo -e "${RED}Failed to download feroxbuster binary. Check network or URL. See $log_file.${NC}"
        return 1
    fi
}

TOOLS=("nmap" "subfinder" "nuclei" "feroxbuster" "hugo")
for tool in "${TOOLS[@]}"; do
    if ! check_command "$tool"; then
        echo -e "${BLUE}Installing $tool...${NC}"
        case $tool in
            nmap)
                install_pkg nmap
                ;;
            subfinder)
                install_pkg snapd
                sudo snap install go --classic
                sudo ln -s /snap/bin/go /usr/bin/go
                go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
                sudo cp ~/go/bin/subfinder /usr/local/bin/
                ;;
            nuclei)
                if install_snap && install_snap_tool nuclei; then
                    : # Success
                else
                    echo -e "${BLUE}Falling back to Git-based installation for nuclei.${NC}"
                    install_git_tool nuclei "https://github.com/projectdiscovery/nuclei.git" \
                        "go build -o nuclei ./cmd/nuclei" "." "nuclei" || {
                        echo -e "${RED}Failed to install nuclei. Try manually: https://github.com/projectdiscovery/nuclei${NC}"
                        continue
                    }
                fi
                ;;
            feroxbuster)
                sudo mkdir -p /usr/local/bin
                if install_snap && install_snap_tool feroxbuster; then
                    : # Success
                elif install_git_tool feroxbuster "https://github.com/epi052/feroxbuster.git" \
                    "cargo build --release" "./target/release" "feroxbuster"; then
                    : # Success
                else
                    echo -e "${BLUE}Falling back to pre-built binary for feroxbuster.${NC}"
                    install_feroxbuster_binary || {
                        echo -e "${RED}Failed to install feroxbuster. Try manually: https://github.com/epi052/feroxbuster${NC}"
                        continue
                    }
                fi
                ;;
            hugo)
                if install_snap && install_snap_tool hugo; then
                    : # Success
                else
                    echo -e "${BLUE}Falling back to Git-based installation for hugo.${NC}"
                    install_git_tool hugo "https://github.com/gohugoio/hugo.git" \
                        "go build -tags extended" "." "hugo" || {
                        echo -e "${RED}Failed to install hugo. Try manually: https://github.com/gohugoio/hugo${NC}"
                        continue
                    }
                fi
                ;;
        esac
        if check_command "$tool"; then
            echo -e "${GREEN}$tool installed successfully.${NC}"
        else
            echo -e "${RED}Failed to install $tool. Check logs for details.${NC}"
        fi
    else
        echo -e "${GREEN}$tool is already installed.${NC}"
    fi
done
