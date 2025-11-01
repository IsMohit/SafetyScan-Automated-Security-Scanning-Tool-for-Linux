#!/bin/bash

#######################################################################
# SafetyScan Installation Script
# Installs SafetyScan and report generator as global commands
#######################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Installation paths
INSTALL_DIR="/usr/local/bin"
SAFETYSCAN_SCRIPT="safetyscan.sh"
REPORT_GENERATOR="report_generator.py"
SAFETYSCAN_INSTALL="$INSTALL_DIR/safetyscan"
REPORT_GEN_INSTALL="$INSTALL_DIR/safetyscan-report-generator"

print_header() {
    echo -e "${PURPLE}"
    echo "================================================================"
    echo "           SafetyScan Installation Script"
    echo "================================================================"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

check_prerequisites() {
    echo -e "\n${BLUE}Checking prerequisites...${NC}\n"
    
    # Check if running on Linux
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        print_error "This tool is exclusively for Linux systems"
        echo "Detected OS: $OSTYPE"
        exit 1
    fi
    print_success "Running on Linux"
    
    # Check for required files
    if [ ! -f "$SAFETYSCAN_SCRIPT" ]; then
        print_error "safetyscan.sh not found in current directory"
        exit 1
    fi
    print_success "safetyscan.sh found"
    
    if [ ! -f "$REPORT_GENERATOR" ]; then
        print_warning "report_generator.py not found - comprehensive reports will be limited"
        print_info "You can add it later to enable full reporting features"
    else
        print_success "report_generator.py found"
    fi
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        print_warning "Docker is not installed"
        print_info "SafetyScan requires Docker. Please install Docker first:"
        print_info "  Ubuntu/Debian: https://docs.docker.com/engine/install/ubuntu/"
        print_info "  CentOS/RHEL:   https://docs.docker.com/engine/install/centos/"
        print_info "  Fedora:        https://docs.docker.com/engine/install/fedora/"
        echo ""
        read -p "Do you want to continue installation anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        print_success "Docker is installed"
    fi
    
    # Check if Python 3 is installed
    if ! command -v python3 &> /dev/null; then
        print_warning "Python 3 is not installed"
        print_info "Comprehensive reports require Python 3. Install it with:"
        print_info "  Ubuntu/Debian: sudo apt install python3"
        print_info "  CentOS/RHEL:   sudo yum install python3"
        print_info "  Fedora:        sudo dnf install python3"
    else
        print_success "Python 3 is installed ($(python3 --version))"
    fi
}

install_safetyscan() {
    echo -e "\n${BLUE}Installing SafetyScan...${NC}\n"
    
    # Check if we have write permissions
    if [ ! -w "$INSTALL_DIR" ]; then
        print_error "No write permission to $INSTALL_DIR"
        print_info "Please run with sudo: sudo ./install.sh"
        exit 1
    fi
    
    # Install main script
    print_info "Installing safetyscan to $SAFETYSCAN_INSTALL"
    cp "$SAFETYSCAN_SCRIPT" "$SAFETYSCAN_INSTALL"
    chmod +x "$SAFETYSCAN_INSTALL"
    print_success "SafetyScan installed successfully"
    
    # Install report generator if it exists
    if [ -f "$REPORT_GENERATOR" ]; then
        print_info "Installing report generator to $REPORT_GEN_INSTALL"
        cp "$REPORT_GENERATOR" "$REPORT_GEN_INSTALL"
        chmod +x "$REPORT_GEN_INSTALL"
        print_success "Report generator installed successfully"
    fi
}

verify_installation() {
    echo -e "\n${BLUE}Verifying installation...${NC}\n"
    
    if [ -f "$SAFETYSCAN_INSTALL" ] && [ -x "$SAFETYSCAN_INSTALL" ]; then
        print_success "SafetyScan is installed and executable"
    else
        print_error "Installation verification failed"
        exit 1
    fi
    
    if [ -f "$REPORT_GEN_INSTALL" ] && [ -x "$REPORT_GEN_INSTALL" ]; then
        print_success "Report generator is installed and executable"
    fi
}

show_completion_message() {
    echo -e "\n${GREEN}"
    echo "================================================================"
    echo "           Installation Completed Successfully!"
    echo "================================================================"
    echo -e "${NC}"
    
    echo -e "${BLUE}You can now use SafetyScan from anywhere:${NC}\n"
    
    echo "  safetyscan <project_path> --mode [sast|dast|both] [OPTIONS]"
    echo ""
    echo -e "${BLUE}Examples:${NC}\n"
    echo "  # Run SAST scan"
    echo "  safetyscan ./myproject --mode sast"
    echo ""
    echo "  # Run DAST scan"
    echo "  safetyscan ./myproject --mode dast --start \"npm start\" --port 3000"
    echo ""
    echo "  # Run both scans"
    echo "  safetyscan ./myproject --mode both --start \"npm start\" --port 3000"
    echo ""
    echo -e "${BLUE}For help:${NC}\n"
    echo "  safetyscan --help"
    echo ""
    
    if [ ! -f "$REPORT_GEN_INSTALL" ]; then
        echo -e "${YELLOW}Note: Report generator was not installed.${NC}"
        echo "  To enable comprehensive HTML/Markdown reports:"
        echo "  1. Create report_generator.py in the same directory"
        echo "  2. Run this installation script again"
        echo ""
    fi
    
    if ! command -v docker &> /dev/null; then
        echo -e "${YELLOW}Important: Docker is not installed!${NC}"
        echo "  SafetyScan requires Docker to run scans."
        echo "  Install Docker from: https://docs.docker.com/engine/install/"
        echo ""
    fi
    
    if ! command -v python3 &> /dev/null; then
        echo -e "${YELLOW}Optional: Python 3 is not installed.${NC}"
        echo "  Install Python 3 to enable comprehensive security reports."
        echo ""
    fi
    
    echo -e "${GREEN}Happy Scanning! 🛡️${NC}\n"
}

main() {
    print_header
    
    check_prerequisites
    
    install_safetyscan
    
    verify_installation
    
    show_completion_message
}

main "$@"