#\!/usr/bin/env python3
import subprocess
import sys
import os
import threading
import queue
import time
from datetime import datetime

def log_with_timestamp(line, prefix='INFO'):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return f'[{timestamp}] {prefix}: {line}'

def read_output(pipe, output_queue, name):
    """Read output from pipe and put it in queue"""
    try:
        for line in iter(pipe.readline, ''):
            if line:
                output_queue.put((name, line.rstrip()))
    except Exception as e:
        output_queue.put(('ERROR', f'Error reading {name}: {e}'))
    finally:
        pipe.close()

# Ensure logs directory exists
log_dir = '/home/gus/video-system/logs'
os.makedirs(log_dir, exist_ok=True)

print(log_with_timestamp('Starting enhanced server logger...'))

# Start the server process with unbuffered output
env = os.environ.copy()
env['PYTHONUNBUFFERED'] = '1'

process = subprocess.Popen(
    [sys.executable, '-u', 'auth_api_server.py'],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    universal_newlines=True,
    env=env,
    bufsize=0
)

# Create queues for output
output_queue = queue.Queue()

# Start threads to read stdout and stderr
stdout_thread = threading.Thread(target=read_output, args=(process.stdout, output_queue, 'STDOUT'))
stderr_thread = threading.Thread(target=read_output, args=(process.stderr, output_queue, 'STDERR'))

stdout_thread.daemon = True
stderr_thread.daemon = True

stdout_thread.start()
stderr_thread.start()

# Open log file
try:
    with open(f'{log_dir}/server.log', 'w', encoding='utf-8') as log_file:
        startup_msg = log_with_timestamp('=== Enhanced Server Logger Started ===')
        log_file.write(startup_msg + '\n')
        log_file.flush()
        print(startup_msg)
        
        # Monitor for output
        while True:
            try:
                # Check if process is still running
                if process.poll() is not None:
                    # Process ended, read remaining output
                    while not output_queue.empty():
                        source, line = output_queue.get_nowait()
                        if line.strip():
                            if 'BrokenPipeError' in line or 'Traceback' in line or 'File "' in line:
                                if 'BrokenPipeError' in line:
                                    log_line = log_with_timestamp('Client disconnected unexpectedly', 'DISCONNECT')
                                else:
                                    continue  # Skip traceback noise
                            else:
                                log_line = log_with_timestamp(line, source)
                            
                            log_file.write(log_line + '\n')
                            log_file.flush()
                            print(log_line)
                    break
                
                # Get output from queue with timeout
                try:
                    source, line = output_queue.get(timeout=1.0)
                    if line.strip():
                        # Filter and format the line
                        if 'BrokenPipeError' in line:
                            log_line = log_with_timestamp('Client disconnected unexpectedly', 'DISCONNECT')
                        elif 'Traceback' in line or 'File "' in line or line.strip().startswith('at '):
                            continue  # Skip traceback noise
                        elif '🔐' in line or '🔒' in line or '🎬' in line or '⏹️' in line:
                            log_line = log_with_timestamp(line, 'SERVER')
                        elif 'Error' in line or 'error' in line:
                            log_line = log_with_timestamp(line, 'ERROR')
                        else:
                            log_line = log_with_timestamp(line, source)
                        
                        # Write to log file and console
                        log_file.write(log_line + '\n')
                        log_file.flush()
                        print(log_line)
                        
                except queue.Empty:
                    # No output, but process is still running
                    continue
                    
            except KeyboardInterrupt:
                print(log_with_timestamp('Received interrupt signal, stopping server...'))
                process.terminate()
                break
            except Exception as e:
                error_msg = log_with_timestamp(f'Logger error: {e}', 'ERROR')
                log_file.write(error_msg + '\n')
                log_file.flush()
                print(error_msg)
                break
                
        # Final message
        final_msg = log_with_timestamp('=== Server Logger Stopped ===')
        log_file.write(final_msg + '\n')
        log_file.flush()
        print(final_msg)
        
except Exception as e:
    print(f'Fatal error in logger: {e}')
finally:
    if process.poll() is None:
        process.terminate()
        process.wait()
