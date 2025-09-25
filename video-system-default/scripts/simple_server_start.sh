#\!/bin/bash

LOG_DIR="/home/gus/video-system/logs"
LOG_FILE="$LOG_DIR/server.log"

# Create log directory
mkdir -p "$LOG_DIR"

# Function to add timestamp to each line and filter broken pipe errors
filter_and_timestamp() {
    local skip_traceback=0
    local traceback_lines=0
    
    while IFS= read -r line; do
        # Check if this is a broken pipe error start
        if [[ $line == *"BrokenPipeError: [Errno 32] Broken pipe"* ]] || [[ $line == *"ConnectionResetError"* ]]; then
            skip_traceback=1
            traceback_lines=0
            echo "[2025-08-29 15:51:56] Client disconnected unexpectedly"
            continue
        fi
        
        # Skip traceback lines that follow broken pipe errors
        if [[ $skip_traceback -eq 1 ]]; then
            if [[ $line == *"Traceback (most recent call last):"* ]] || [[ $line == *"File "* ]] || [[ $line == "    "* ]] || [[ $line == ""* ]]; then
                traceback_lines=$((traceback_lines + 1))
                # Skip up to 20 lines of traceback
                if [[ $traceback_lines -gt 20 ]]; then
                    skip_traceback=0
                fi
                continue
            else
                skip_traceback=0
            fi
        fi
        
        # Check for exception separator lines and skip them if they're part of broken pipe errors
        if [[ $line == "----------------------------------------"* ]] && [[ $skip_traceback -eq 1 ]]; then
            continue
        fi
        
        # Check for "During handling of the above exception" lines
        if [[ $line == *"During handling of the above exception"* ]]; then
            skip_traceback=1
            traceback_lines=0
            continue
        fi
        
        # Normal line processing
        if [[ $skip_traceback -eq 0 ]]; then
            echo "[2025-08-29 15:51:56] $line"
        fi
    done
}

# Clear the log file and add startup message
echo "[2025-08-29 15:51:56] === Server Starting ===" > "$LOG_FILE"

# Start the server and capture all output with timestamps and filtering
cd "/home/gus/video-system/scripts"
exec python3 -u auth_api_server.py 2>&1 < /dev/null  < /dev/null |  filter_and_timestamp | tee -a "$LOG_FILE"
