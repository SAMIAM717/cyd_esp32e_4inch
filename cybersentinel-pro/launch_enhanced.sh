#!/bin/bash

# CyberSentinel Pro Enhanced GUI Launcher
# Advanced Cybersecurity Platform

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# ASCII Art Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                    🛡️  CyberSentinel Pro 🛡️                      ║"
    echo "║              Enhanced AI-Powered Security Platform              ║"
    echo "║                  Professional GUI Interface                     ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Load environment variables from .env if present
if [ -f ".env" ]; then
    echo -e "${YELLOW}🔐 Loading environment from .env${NC}"
    # Export all variables defined in .env
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if port is available
port_available() {
    ! nc -z localhost "$1" >/dev/null 2>&1
}

# Function to kill process on port
kill_port() {
    local port=$1
    local pid=$(lsof -t -i:$port 2>/dev/null)
    if [ ! -z "$pid" ]; then
        echo -e "${YELLOW}⚠️  Killing existing process on port $port (PID: $pid)${NC}"
        kill -9 $pid 2>/dev/null || true
        sleep 2
    fi
}

# Function to start API server
start_api_server() {
    echo -e "${BLUE}🚀 Starting CyberSentinel API Server...${NC}"

    # Check if Python is available
    if command_exists python3; then
        PYTHON_CMD="python3"
    elif command_exists python; then
        PYTHON_CMD="python"
    else
        echo -e "${RED}❌ Python not found! Please install Python 3.x${NC}"
        return 1
    fi

    # Check if virtual environment exists
    if [ -d "venv" ]; then
        echo -e "${GREEN}📦 Activating virtual environment...${NC}"
        source venv/bin/activate
    fi

    # Install required packages if needed
    if [ -f "requirements.txt" ]; then
        echo -e "${YELLOW}📋 Installing required packages...${NC}"
        pip install -r requirements.txt --quiet
    fi

    # Kill any existing process on port 8000
    kill_port 8000

    # Start API server in background
    if [ -f "api_server.py" ]; then
        echo -e "${GREEN}✅ Starting API server on port 8000...${NC}"
        nohup $PYTHON_CMD api_server.py > api_server.log 2>&1 &
        API_PID=$!
        echo $API_PID > api_server.pid

        # Wait for server to start
        echo -e "${YELLOW}⏳ Waiting for API server to initialize...${NC}"
        for i in {1..10}; do
            if curl -s http://localhost:8000/health >/dev/null 2>&1; then
                echo -e "${GREEN}✅ API Server running on http://localhost:8000${NC}"
                return 0
            fi
            sleep 1
        done

        echo -e "${YELLOW}⚠️  API server may still be starting (check logs: tail -f api_server.log)${NC}"
    else
        echo -e "${YELLOW}⚠️  API server not found - GUI will run in demo mode${NC}"
    fi
}

# Function to start GUI server
start_gui_server() {
    echo -e "${PURPLE}🎨 Starting Enhanced GUI Server...${NC}"

    # Kill any existing process on port 3000
    kill_port 3000

    # Check if enhanced_gui.html exists
    if [ ! -f "enhanced_gui.html" ]; then
        echo -e "${RED}❌ Enhanced GUI file not found!${NC}"
        return 1
    fi

    # Start HTTP server for GUI
    echo -e "${GREEN}✅ Starting GUI server on port 3000...${NC}"
    if command_exists python3; then
        nohup python3 -m http.server 3000 > gui_server.log 2>&1 &
    elif command_exists python; then
        nohup python -m http.server 3000 > gui_server.log 2>&1 &
    else
        echo -e "${RED}❌ Python not available for GUI server${NC}"
        return 1
    fi

    GUI_PID=$!
    echo $GUI_PID > gui_server.pid

    # Wait for GUI server to start
    echo -e "${YELLOW}⏳ Waiting for GUI server to initialize...${NC}"
    sleep 3

    if port_available 3000; then
        echo -e "${RED}❌ GUI server failed to start${NC}"
        return 1
    else
        echo -e "${GREEN}✅ GUI Server running on http://localhost:3000${NC}"
        return 0
    fi
}

# Function to open browser
open_browser() {
    local url="http://localhost:3000/enhanced_gui.html"
    echo -e "${CYAN}🌐 Opening CyberSentinel Pro in browser...${NC}"

    # Try different browser opening methods
    if command_exists xdg-open; then
        xdg-open "$url" >/dev/null 2>&1 &
    elif command_exists open; then
        open "$url" >/dev/null 2>&1 &
    elif command_exists firefox; then
        firefox "$url" >/dev/null 2>&1 &
    elif command_exists chromium-browser; then
        chromium-browser "$url" >/dev/null 2>&1 &
    elif command_exists google-chrome; then
        google-chrome "$url" >/dev/null 2>&1 &
    else
        echo -e "${YELLOW}⚠️  Could not auto-open browser. Please navigate to: ${url}${NC}"
        return 1
    fi

    echo -e "${GREEN}✅ Browser should open automatically${NC}"
}

# Function to show status
show_status() {
    echo -e "\n${WHITE}📊 SYSTEM STATUS:${NC}"
    echo -e "${GREEN}═══════════════════════════════════════${NC}"

    # Check API server
    if curl -s http://localhost:8000/health >/dev/null 2>&1; then
        echo -e "   🟢 API Server: ${GREEN}Online${NC} (http://localhost:8000)"
    else
        echo -e "   🔴 API Server: ${RED}Offline${NC}"
    fi

    # Check GUI server
    if ! port_available 3000; then
        echo -e "   🟢 GUI Server: ${GREEN}Online${NC} (http://localhost:3000)"
    else
        echo -e "   🔴 GUI Server: ${RED}Offline${NC}"
    fi

    # Check processes
    if [ -f "api_server.pid" ]; then
        local api_pid=$(cat api_server.pid)
        if ps -p $api_pid >/dev/null 2>&1; then
            echo -e "   📊 API Process: ${GREEN}Running${NC} (PID: $api_pid)"
        else
            echo -e "   📊 API Process: ${RED}Not Running${NC}"
        fi
    fi

    if [ -f "gui_server.pid" ]; then
        local gui_pid=$(cat gui_server.pid)
        if ps -p $gui_pid >/dev/null 2>&1; then
            echo -e "   🎨 GUI Process: ${GREEN}Running${NC} (PID: $gui_pid)"
        else
            echo -e "   🎨 GUI Process: ${RED}Not Running${NC}"
        fi
    fi

    echo ""
}

# Function to stop all servers
stop_servers() {
    echo -e "${YELLOW}🛑 Stopping all CyberSentinel servers...${NC}"

    # Stop API server
    if [ -f "api_server.pid" ]; then
        local api_pid=$(cat api_server.pid)
        if ps -p $api_pid >/dev/null 2>&1; then
            echo -e "${YELLOW}⏹️  Stopping API server (PID: $api_pid)${NC}"
            kill $api_pid 2>/dev/null || kill -9 $api_pid 2>/dev/null
        fi
        rm -f api_server.pid
    fi

    # Stop GUI server
    if [ -f "gui_server.pid" ]; then
        local gui_pid=$(cat gui_server.pid)
        if ps -p $gui_pid >/dev/null 2>&1; then
            echo -e "${YELLOW}⏹️  Stopping GUI server (PID: $gui_pid)${NC}"
            kill $gui_pid 2>/dev/null || kill -9 $gui_pid 2>/dev/null
        fi
        rm -f gui_server.pid
    fi

    # Kill any remaining processes on our ports
    kill_port 8000
    kill_port 3000

    echo -e "${GREEN}✅ All servers stopped${NC}"
}

# Function to view logs
view_logs() {
    echo -e "${CYAN}📋 Recent logs:${NC}"
    echo -e "${GREEN}═══════════════════════════════════════${NC}"

    if [ -f "api_server.log" ]; then
        echo -e "${YELLOW}🔧 API Server Log (last 10 lines):${NC}"
        tail -n 10 api_server.log 2>/dev/null || echo "No API logs available"
        echo ""
    fi

    if [ -f "gui_server.log" ]; then
        echo -e "${YELLOW}🎨 GUI Server Log (last 10 lines):${NC}"
        tail -n 10 gui_server.log 2>/dev/null || echo "No GUI logs available"
        echo ""
    fi
}

# Function to create demo API server if not exists
create_demo_api() {
    if [ ! -f "api_server.py" ]; then
        echo -e "${YELLOW}📝 Creating demo API server...${NC}"
        cat > api_server.py << 'EOF'
#!/usr/bin/env python3
"""
Demo API Server for CyberSentinel Pro
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import json
from datetime import datetime

app = FastAPI(title="CyberSentinel Pro API", version="1.0.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/scan/network")
async def network_scan(request: dict):
    return {
        "task_id": f"network_{datetime.now().timestamp()}",
        "status": "started",
        "target": request.get("target"),
        "scan_type": request.get("scan_type")
    }

@app.post("/scan/web")
async def web_scan(request: dict):
    return {
        "task_id": f"web_{datetime.now().timestamp()}",
        "status": "started",
        "target": request.get("target"),
        "scan_type": request.get("scan_type")
    }

@app.post("/ai/analyze")
async def ai_analyze(request: dict):
    return {
        "analysis": "Demo AI analysis completed. Configure OpenAI API key for full functionality.",
        "confidence": 0.85,
        "recommendations": ["Configure real scanning modules", "Set up OpenAI integration"]
    }

if __name__ == "__main__":
    print("🚀 Starting CyberSentinel Pro Demo API Server...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
EOF
        echo -e "${GREEN}✅ Demo API server created${NC}"
    fi
}

# Function to install dependencies
install_deps() {
    echo -e "${YELLOW}📦 Installing dependencies...${NC}"

    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        echo -e "${BLUE}🐍 Creating virtual environment...${NC}"
        python3 -m venv venv
    fi

    # Activate virtual environment
    source venv/bin/activate

    # Create requirements.txt if it doesn't exist
    if [ ! -f "requirements.txt" ]; then
        cat > requirements.txt << 'EOF'
fastapi==0.104.1
uvicorn==0.24.0
python-multipart==0.0.6
aiofiles==23.2.1
aiohttp==3.9.1
requests==2.31.0
pydantic==2.5.0
EOF
    fi

    # Install requirements
    pip install -r requirements.txt
    echo -e "${GREEN}✅ Dependencies installed${NC}"
}

# Main menu function
show_menu() {
    clear
    print_banner
    echo -e "${WHITE}🎮 CYBERSENTINEL PRO ENHANCED GUI LAUNCHER${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${CYAN}Available Options:${NC}"
    echo -e "   ${GREEN}1.${NC} 🚀 Launch Full Platform (API + GUI)"
    echo -e "   ${GREEN}2.${NC} 🎨 Launch GUI Only"
    echo -e "   ${GREEN}3.${NC} 🔧 Launch API Only"
    echo -e "   ${GREEN}4.${NC} 📊 Show Status"
    echo -e "   ${GREEN}5.${NC} 📋 View Logs"
    echo -e "   ${GREEN}6.${NC} 📦 Install Dependencies"
    echo -e "   ${GREEN}7.${NC} 🛑 Stop All Servers"
    echo -e "   ${GREEN}8.${NC} 🌐 Open Browser"
    echo -e "   ${GREEN}9.${NC} ❓ Help"
    echo -e "   ${GREEN}0.${NC} 🚪 Exit"
    echo ""
    echo -ne "${YELLOW}Select option (0-9): ${NC}"
}

# Help function
show_help() {
    clear
    echo -e "${CYAN}🆘 CYBERSENTINEL PRO HELP${NC}"
    echo -e "${GREEN}═══════════════════════════════════════${NC}"
    echo ""
    echo -e "${WHITE}📖 Quick Start Guide:${NC}"
    echo -e "   1. Run option 6 to install dependencies first"
    echo -e "   2. Use option 1 to launch the full platform"
    echo -e "   3. GUI will open at: http://localhost:3000/enhanced_gui.html"
    echo -e "   4. API server runs at: http://localhost:8000"
    echo ""
    echo -e "${WHITE}🔧 Troubleshooting:${NC}"
    echo -e "   • If ports are busy, use option 7 to stop all servers"
    echo -e "   • Check logs with option 5 for error details"
    echo -e "   • Use option 4 to check system status"
    echo ""
    echo -e "${WHITE}🌐 URLs:${NC}"
    echo -e "   • Enhanced GUI: http://localhost:3000/enhanced_gui.html"
    echo -e "   • API Health: http://localhost:8000/health"
    echo -e "   • API Docs: http://localhost:8000/docs"
    echo ""
    echo -ne "${YELLOW}Press Enter to continue...${NC}"
    read
}

# Main execution
main() {
    # Trap to cleanup on exit
    trap 'echo -e "\n${YELLOW}🛑 Interrupted. Cleaning up...${NC}"; stop_servers; exit 0' INT TERM

    while true; do
        show_menu
        read -r choice

        case $choice in
            1)
                clear
                print_banner
                echo -e "${PURPLE}🚀 LAUNCHING FULL PLATFORM${NC}"
                echo -e "${GREEN}═══════════════════════════════════════${NC}"
                create_demo_api
                install_deps
                start_api_server
                start_gui_server
                sleep 2
                open_browser
                show_status
                echo -e "\n${GREEN}✅ CyberSentinel Pro Enhanced Platform is now running!${NC}"
                echo -e "${CYAN}📱 Access the GUI at: http://localhost:3000/enhanced_gui.html${NC}"
                echo -e "\n${YELLOW}Press Enter to return to menu...${NC}"
                read
                ;;
            2)
                clear
                print_banner
                echo -e "${PURPLE}🎨 LAUNCHING GUI SERVER${NC}"
                echo -e "${GREEN}═══════════════════════════════════════${NC}"
                start_gui_server
                sleep 2
                open_browser
                show_status
                echo -e "\n${YELLOW}Press Enter to return to menu...${NC}"
                read
                ;;
            3)
                clear
                print_banner
                echo -e "${PURPLE}🔧 LAUNCHING API SERVER${NC}"
                echo -e "${GREEN}═══════════════════════════════════════${NC}"
                create_demo_api
                install_deps
                start_api_server
                show_status
                echo -e "\n${YELLOW}Press Enter to return to menu...${NC}"
                read
                ;;
            4)
                clear
                print_banner
                show_status
                echo -e "\n${YELLOW}Press Enter to return to menu...${NC}"
                read
                ;;
            5)
                clear
                print_banner
                view_logs
                echo -e "\n${YELLOW}Press Enter to return to menu...${NC}"
                read
                ;;
            6)
                clear
                print_banner
                echo -e "${PURPLE}📦 INSTALLING DEPENDENCIES${NC}"
                echo -e "${GREEN}═══════════════════════════════════════${NC}"
                install_deps
                echo -e "\n${YELLOW}Press Enter to return to menu...${NC}"
                read
                ;;
            7)
                clear
                print_banner
                stop_servers
                echo -e "\n${YELLOW}Press Enter to return to menu...${NC}"
                read
                ;;
            8)
                clear
                print_banner
                open_browser
                echo -e "\n${YELLOW}Press Enter to return to menu...${NC}"
                read
                ;;
            9)
                show_help
                ;;
            0)
                clear
                echo -e "${CYAN}👋 Stopping CyberSentinel Pro...${NC}"
                stop_servers
                echo -e "${GREEN}✅ Thank you for using CyberSentinel Pro Enhanced!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Invalid option! Please select 0-9${NC}"
                sleep 2
                ;;
        esac
    done
}

# Check if script is being run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
