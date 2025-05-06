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

# Log file for errors
LOG_FILE="autoscan.log"

# Function to log messages
log_message() {
    local color="$1" message="$2"
    echo -e "${color}${message}${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') $message" >> "$LOG_FILE"
}

# Check for required dependencies
if ! check_command nmap; then
    log_message "$RED" "Error: nmap is required but not installed. Please install nmap and try again."
    log_message "$BLUE" "You can run setup-autoscan.sh to install dependencies."
    exit 1
fi

if ! check_command python3; then
    log_message "$RED" "Error: python3 is required but not installed. Please install python3 and try again."
    exit 1
fi

# Check if python3-venv is installed
if ! python3 -m venv --help >/dev/null 2>&1; then
    log_message "$RED" "Error: python3-venv is required but not installed. Please install python3-venv."
    log_message "$BLUE" "On Ubuntu/Debian, run: sudo apt install -y python3-venv"
    exit 1
fi

# Check for optional tools and suggest setup-autoscan.sh if missing
optional_tools=("subfinder" "nuclei" "feroxbuster" "hugo")
missing_tools=()
for tool in "${optional_tools[@]}"; do
    if ! check_command "$tool"; then
        missing_tools+=("$tool")
    fi
done

if [ ${#missing_tools[@]} -gt 0 ]; then
    log_message "$RED" "Warning: The following optional tools are not installed: ${missing_tools[*]}"
    log_message "$BLUE" "You can install them by running setup-autoscan.sh."
fi

# Set up virtual environment
VENV_DIR=".venv"
PYTHON_VENV="$VENV_DIR/bin/python3"
PIP_VENV="$VENV_DIR/bin/pip3"

# Remove existing virtual environment if corrupted
if [ -d "$VENV_DIR" ] && ! [ -f "$VENV_DIR/bin/activate" ]; then
    log_message "$RED" "Corrupted virtual environment detected. Removing $VENV_DIR..."
    rm -rf "$VENV_DIR"
fi

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    log_message "$BLUE" "Creating virtual environment in $VENV_DIR..."
    if ! python3 -m venv "$VENV_DIR" 2>/tmp/venv_create.log; then
        log_message "$RED" "Failed to create virtual environment. See /tmp/venv_create.log."
        cat /tmp/venv_create.log >> "$LOG_FILE"
        exit 1
    fi
fi

# Activate virtual environment
if [ -f "$VENV_DIR/bin/activate" ]; then
    log_message "$BLUE" "Activating virtual environment..."
    source "$VENV_DIR/bin/activate"
    if [ -z "$VIRTUAL_ENV" ]; then
        log_message "$RED" "Failed to activate virtual environment. VIRTUAL_ENV not set."
        exit 1
    fi
else
    log_message "$RED" "Virtual environment activation script not found: $VENV_DIR/bin/activate"
    exit 1
fi

# Verify pip and python are from the virtual environment
if ! check_command "$PIP_VENV"; then
    log_message "$RED" "pip3 not found in virtual environment: $PIP_VENV"
    exit 1
fi

if ! check_command "$PYTHON_VENV"; then
    log_message "$RED" "python3 not found in virtual environment: $PYTHON_VENV"
    exit 1
fi

# Install required Python packages
for package in python-nmap tqdm; do
    if ! "$PIP_VENV" show "$package" >/dev/null 2>&1; then
        log_message "$BLUE" "Installing $package..."
        if ! "$PIP_VENV" install "$package" --no-cache-dir 2>/tmp/pip_install.log; then
            log_message "$RED" "Failed to install $package. See /tmp/pip_install.log."
            cat /tmp/pip_install.log >> "$LOG_FILE"
            exit 1
        fi
        if ! "$PIP_VENV" show "$package" >/dev/null 2>&1; then
            log_message "$RED" "$package installation appeared successful but package not found."
            exit 1
        fi
    else
        log_message "$GREEN" "$package is already installed in virtual environment."
    fi
done

# Run autoscan.py with sudo and pass all arguments
log_message "$BLUE" "Running autoscan.py..."
sudo "$PYTHON_VENV" autoscan.py "$@"
exit_code=$?

# Deactivate virtual environment
deactivate

# Restore terminal echo settings
stty echo 2>/dev/null || log_message "$RED" "Failed to restore terminal echo settings."

log_message "$GREEN" "Autoscan completed with exit code $exit_code."

exit $exit_code
