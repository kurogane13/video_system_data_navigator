#!/usr/bin/env python3
"""
Simple WebSocket Terminal Server - Minimal Working Version
"""

import asyncio
import websockets
import json
import subprocess
import os
import signal
import threading
import queue
import time

# Store active sessions
sessions = {}

class SimpleTerminalSession:
    def __init__(self, websocket):
        self.websocket = websocket
        self.process = None
        self.running = False
        self.output_queue = queue.Queue()
        
    async def start(self):
        """Start terminal session"""
        try:
            print("Starting terminal session...")
            
            # Send welcome message immediately
            await self.send_output("Welcome to Linux Terminal\r\n")
            await self.send_output("gus@test-pf-01:~$ ")
            
            self.running = True
            print("Terminal session started successfully")
            
        except Exception as e:
            print(f"Error starting terminal: {e}")
            await self.send_error(str(e))
    
    async def execute_command(self, command):
        """Execute a command and return output"""
        try:
            print(f"Executing command: {command}")
            
            if command.strip() == 'clear':
                await self.send_output('\x1b[2J\x1b[H')
                await self.send_output("gus@test-pf-01:~$ ")
                return
            
            # Execute command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
                cwd='/home/gus'
            )
            
            # Send command echo
            await self.send_output(command + '\r\n')
            
            # Send output
            if result.stdout:
                await self.send_output(result.stdout)
            if result.stderr:
                await self.send_output(result.stderr)
            
            # Send new prompt
            await self.send_output("gus@test-pf-01:~$ ")
            
        except subprocess.TimeoutExpired:
            await self.send_output("Command timed out\r\n")
            await self.send_output("gus@test-pf-01:~$ ")
        except Exception as e:
            print(f"Error executing command: {e}")
            await self.send_output(f"Error: {str(e)}\r\n")
            await self.send_output("gus@test-pf-01:~$ ")
    
    async def send_output(self, data):
        """Send output to WebSocket"""
        try:
            await self.websocket.send(json.dumps({
                'type': 'output',
                'data': data
            }))
        except Exception as e:
            print(f"Error sending output: {e}")
    
    async def send_error(self, message):
        """Send error message"""
        try:
            await self.websocket.send(json.dumps({
                'type': 'error',
                'message': message
            }))
        except Exception as e:
            print(f"Error sending error: {e}")
    
    def cleanup(self):
        """Clean up session"""
        self.running = False
        if self.process:
            try:
                self.process.terminate()
            except:
                pass

async def handle_websocket(websocket, path):
    """Handle WebSocket connection"""
    session_id = id(websocket)
    print(f"New WebSocket connection: {session_id}")
    
    session = SimpleTerminalSession(websocket)
    sessions[session_id] = session
    
    authenticated = False
    current_command = ""
    
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                msg_type = data.get('type')
                
                if msg_type == 'auth':
                    print("Authentication request received")
                    # Simple auth - just accept any token
                    token = data.get('token', '')
                    if len(token) > 0:
                        authenticated = True
                        print("User authenticated")
                        await session.start()
                    else:
                        await session.send_error("Authentication failed")
                
                elif msg_type == 'input' and authenticated:
                    input_data = data.get('data', '')
                    print(f"Input received: {repr(input_data)}")
                    
                    if input_data == '\r':
                        # Execute command on Enter
                        if current_command.strip():
                            await session.execute_command(current_command.strip())
                        else:
                            await session.send_output("gus@test-pf-01:~$ ")
                        current_command = ""
                    elif input_data == '\x7f':  # Backspace
                        if current_command:
                            current_command = current_command[:-1]
                            await session.send_output('\b \b')
                    elif input_data == '\x03':  # Ctrl+C
                        await session.send_output('^C\r\n')
                        await session.send_output("gus@test-pf-01:~$ ")
                        current_command = ""
                    else:
                        # Regular character
                        current_command += input_data
                        await session.send_output(input_data)
                
                else:
                    print(f"Unknown message type or not authenticated: {msg_type}")
                    
            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}")
            except Exception as e:
                print(f"Error handling message: {e}")
                break
    
    except websockets.exceptions.ConnectionClosed:
        print(f"WebSocket connection closed: {session_id}")
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        if session_id in sessions:
            sessions[session_id].cleanup()
            del sessions[session_id]
        print(f"Cleaned up session: {session_id}")

async def main():
    """Start WebSocket server"""
    print("🔌 Starting Simple Terminal WebSocket Server on port 9091")
    
    server = await websockets.serve(
        handle_websocket,
        "0.0.0.0",
        9091,
        ping_interval=30,
        ping_timeout=10
    )
    
    print("✅ Terminal WebSocket Server is running on port 9091")
    
    await server.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")
    except Exception as e:
        print(f"❌ Server error: {e}")