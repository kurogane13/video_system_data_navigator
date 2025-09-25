#\!/usr/bin/env python3
import subprocess
import sys
import os
from datetime import datetime

def log_with_timestamp(line):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return f'[{timestamp}] {line}'

# Ensure logs directory exists
log_dir = '/home/gus/video-system/logs'
os.makedirs(log_dir, exist_ok=True)

# Start the server process
process = subprocess.Popen(
    [sys.executable, 'auth_api_server.py'],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    universal_newlines=True,
    bufsize=1
)

print(log_with_timestamp('Starting server with log wrapper...'))

try:
    with open(f'{log_dir}/server.log', 'w', encoding='utf-8') as log_file:
        log_file.write(log_with_timestamp('=== Server Started ===') + '\n')
        log_file.flush()
        
        for line in process.stdout:
            line = line.rstrip()
            if line:
                # Filter out the long broken pipe tracebacks but keep the essential error
                if 'BrokenPipeError: [Errno 32] Broken pipe' in line:
                    timestamped_line = log_with_timestamp('CLIENT_DISCONNECT: Client disconnected unexpectedly')
                elif 'Exception happened during processing of request' in line:
                    timestamped_line = log_with_timestamp('CLIENT_DISCONNECT: Connection error from client')
                elif line.startswith('Traceback') or line.startswith('  File') or line.startswith('    ') or '----------------------------------------' in line:
                    # Skip traceback noise for broken pipes, but log other tracebacks
                    if 'BrokenPipe' not in line:
                        timestamped_line = log_with_timestamp(f'ERROR_TRACE: {line}')
                    else:
                        continue
                else:
                    timestamped_line = log_with_timestamp(line)
                
                # Write to log file
                log_file.write(timestamped_line + '\n')
                log_file.flush()
                
                # Also print to console
                print(timestamped_line)
                sys.stdout.flush()
                
except KeyboardInterrupt:
    log_with_timestamp('Server stopped by user')
    process.terminate()
except Exception as e:
    error_msg = log_with_timestamp(f'Log wrapper error: {e}')
    print(error_msg)
    with open(f'{log_dir}/server.log', 'a') as log_file:
        log_file.write(error_msg + '\n')
finally:
    process.wait()
