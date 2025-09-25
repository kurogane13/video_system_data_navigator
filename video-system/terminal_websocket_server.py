#!/usr/bin/env python3
"""
WebSocket Terminal Server
Provides real-time terminal access via WebSocket using pty
"""

import asyncio
import websockets
import json
import pty
import os
import fcntl
import struct
import termios
import select
import subprocess
import threading
import time
import signal

# Store active terminal sessions
terminal_sessions = {}

class TerminalSession:
    def __init__(self, websocket):
        self.websocket = websocket
        self.master = None
        self.slave = None
        self.process = None
        self.running = False
        
    async def start_terminal(self):
        """Start a new bash terminal session"""
        try:
            # Create pseudo-terminal
            self.master, self.slave = pty.openpty()
            
            # Start bash process with proper environment
            env = os.environ.copy()
            env.update({
                'HOME': '/home/gus',
                'USER': 'gus',
                'SHELL': '/bin/bash',
                'TERM': 'xterm-256color',
                'PATH': '/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin',
                'LANG': 'en_US.UTF-8',
                'LC_ALL': 'en_US.UTF-8',
                'PS1': 'gus@test-pf-01:~$ '
            })
            
            self.process = subprocess.Popen(
                ['/bin/bash', '-i'],
                stdin=self.slave,
                stdout=self.slave,
                stderr=self.slave,
                preexec_fn=os.setsid,
                cwd='/home/gus',
                env=env
            )
            
            # Close slave in parent process
            os.close(self.slave)
            
            # Set terminal size
            self.set_terminal_size(80, 24)
            
            # Make master non-blocking
            fcntl.fcntl(self.master, fcntl.F_SETFL, os.O_NONBLOCK)
            
            self.running = True
            
            # Start output reading loop
            await self.read_terminal_output()
            
        except Exception as e:
            print(f"Error starting terminal: {e}")
            await self.send_error(f"Failed to start terminal: {str(e)}")
    
    def set_terminal_size(self, cols, rows):
        """Set terminal size"""
        try:
            # Set window size
            s = struct.pack('HHHH', rows, cols, 0, 0)
            fcntl.ioctl(self.master, termios.TIOCSWINSZ, s)
        except Exception as e:
            print(f"Error setting terminal size: {e}")
    
    async def read_terminal_output(self):
        """Read output from terminal and send to WebSocket"""
        try:
            while self.running and self.process.poll() is None:
                try:
                    # Use select to check if data is available
                    ready, _, _ = select.select([self.master], [], [], 0.1)
                    
                    if ready:
                        # Read available data
                        data = os.read(self.master, 4096)
                        if data:
                            # Send output to WebSocket
                            await self.websocket.send(json.dumps({
                                'type': 'output',
                                'data': data.decode('utf-8', errors='ignore')
                            }))
                    
                    # Small delay to prevent busy waiting
                    await asyncio.sleep(0.01)
                        
                except OSError:
                    # Terminal closed or error reading
                    break
                except Exception as e:
                    print(f"Error reading terminal output: {e}")
                    break
                    
        except Exception as e:
            print(f"Error in output reading loop: {e}")
        finally:
            await self.cleanup()
    
    async def write_to_terminal(self, data):
        """Write data to terminal"""
        try:
            if self.master and self.running:
                os.write(self.master, data.encode('utf-8'))
        except Exception as e:
            print(f"Error writing to terminal: {e}")
    
    async def resize_terminal(self, cols, rows):
        """Resize terminal"""
        try:
            self.set_terminal_size(cols, rows)
        except Exception as e:
            print(f"Error resizing terminal: {e}")
    
    async def send_error(self, message):
        """Send error message to WebSocket"""
        try:
            await self.websocket.send(json.dumps({
                'type': 'error',
                'message': message
            }))
        except:
            pass
    
    async def cleanup(self):
        """Clean up terminal session"""
        self.running = False
        
        try:
            if self.process:
                # Kill the bash process and its children
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                time.sleep(0.1)
                if self.process.poll() is None:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
        except:
            pass
        
        try:
            if self.master:
                os.close(self.master)
        except:
            pass

async def authenticate_user(token):
    """Authenticate user token (simplified)"""
    # For now, just check if token exists and is not empty
    # This should match the authentication from the main server
    return token and len(token) > 5

async def handle_terminal_connection(websocket, path):
    """Handle new terminal WebSocket connection"""
    print(f"New terminal connection from {websocket.remote_address}")
    
    session = TerminalSession(websocket)
    session_id = id(session)
    terminal_sessions[session_id] = session
    
    authenticated = False
    
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                message_type = data.get('type')
                
                if message_type == 'auth':
                    # Authenticate user
                    token = data.get('token')
                    if await authenticate_user(token):
                        authenticated = True
                        print(f"User authenticated, starting terminal session {session_id}")
                        # Start terminal session
                        await session.start_terminal()
                        # Send initial prompt
                        await session.websocket.send(json.dumps({
                            'type': 'output',
                            'data': 'gus@test-pf-01:~$ '
                        }))
                    else:
                        await session.send_error("Authentication failed")
                        break
                
                elif message_type == 'input' and authenticated:
                    # Handle terminal input
                    input_data = data.get('data', '')
                    await session.write_to_terminal(input_data)
                
                elif message_type == 'resize' and authenticated:
                    # Handle terminal resize
                    cols = data.get('cols', 80)
                    rows = data.get('rows', 24)
                    await session.resize_terminal(cols, rows)
                
                else:
                    await session.send_error("Invalid message type or not authenticated")
                    
            except json.JSONDecodeError:
                await session.send_error("Invalid JSON message")
            except Exception as e:
                print(f"Error handling message: {e}")
                break
                
    except websockets.exceptions.ConnectionClosed:
        print(f"Terminal connection closed for session {session_id}")
    except Exception as e:
        print(f"Error in terminal connection: {e}")
    finally:
        # Clean up session
        if session_id in terminal_sessions:
            await terminal_sessions[session_id].cleanup()
            del terminal_sessions[session_id]
        print(f"Cleaned up terminal session {session_id}")

async def main():
    """Main WebSocket server"""
    print("🖥️  Starting Terminal WebSocket Server on port 9091")
    
    # Start WebSocket server
    server = await websockets.serve(
        handle_terminal_connection,
        "0.0.0.0",
        9091,
        ping_interval=20,
        ping_timeout=10
    )
    
    print("✅ Terminal WebSocket Server is running")
    print("🔌 Clients can connect to ws://hostname:9091/terminal")
    
    # Keep server running
    await server.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Terminal WebSocket Server stopped")
    except Exception as e:
        print(f"❌ Server error: {e}")