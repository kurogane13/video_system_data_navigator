#!/usr/bin/env python3
"""
Authenticated API Server with Login System
"""

import http.server
import socketserver
import json
import os
import urllib.parse
import mimetypes
import stat
import hashlib
import secrets
import time
import shutil
import tempfile
import cgi
import zipfile
import io
import re
import subprocess
import threading

from debug_logger import debug_logger
import logging
import sys

# Setup logging
log_dir = '/home/gus/video-system/logs'
import os
os.makedirs(log_dir, exist_ok=True)

# Configure logging  
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'{log_dir}/server.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


PORT = 9090

# Session storage
active_sessions = {}

# Terminal session storage - maintains state per user session
terminal_sessions = {}

# Large file upload threshold (400MB) - DISABLED per user request
# LARGE_FILE_THRESHOLD = 400 * 1024 * 1024

def read_scp_credentials():
    """Read SCP credentials from .scpcrds file"""
    try:
        creds_file = '/home/gus/video-system/docs/.scpcrds'
        if not os.path.exists(creds_file):
            return None
        
        credentials = {}
        with open(creds_file, 'r') as f:
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    credentials[key] = value
        
        return credentials
    except Exception as e:
        logger.error(f"Error reading SCP credentials: {e}")
        return None

def upload_via_scp(local_file_path, remote_path, file_type='video'):
    """Upload large file via SCP"""
    try:
        credentials = read_scp_credentials()
        if not credentials:
            logger.error("No SCP credentials found")
            return False, "SCP credentials not configured"
        
        username = credentials.get('username')
        host = credentials.get('host')
        key_path = credentials.get('key_path')
        
        if not all([username, host, key_path]):
            logger.error("Incomplete SCP credentials")
            return False, "Incomplete SCP credentials"
        
        # Determine target directory based on file type
        if file_type == 'video':
            target_dir = '/home/gus/video-system/videos/'
        else:
            target_dir = '/home/gus/random_files/'
        
        remote_file_path = f"{username}@{host}:{target_dir}{os.path.basename(remote_path)}"
        
        # Build SCP command
        scp_cmd = [
            'scp',
            '-i', key_path,
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            local_file_path,
            remote_file_path
        ]
        
        logger.info(f"Starting SCP upload: {local_file_path} -> {remote_file_path}")
        
        # Execute SCP command
        result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=1800)  # 30 min timeout
        
        if result.returncode == 0:
            logger.info(f"SCP upload successful: {os.path.basename(local_file_path)}")
            return True, "Upload completed successfully"
        else:
            logger.error(f"SCP upload failed: {result.stderr}")
            return False, f"SCP upload failed: {result.stderr}"
    
    except subprocess.TimeoutExpired:
        logger.error("SCP upload timed out")
        return False, "Upload timed out"
    except Exception as e:
        logger.error(f"SCP upload error: {e}")
        return False, f"SCP upload error: {str(e)}"

class AuthenticatedAPIHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            parsed_url = urllib.parse.urlparse(self.path)
            path = parsed_url.path
            query = urllib.parse.parse_qs(parsed_url.query)
            
            # Serve connection data file
            if path == '/.client_side_data_for_video_system':
                self.serve_connection_data_file()
            # Serve login page
            elif path == '/' or path == '/login.html':
                self.serve_login_page()
            # Serve simple login test page
            elif path == '/simple_login.html':
                self.serve_simple_login()
            # Serve debug dashboard
            elif path == '/dashboard_debug.html':
                self.serve_dashboard_debug()
            # Serve basic test
            elif path == '/test_basic.html':
                self.serve_basic_test()
            # Serve dashboard (authentication handled by JavaScript)
            elif path == '/dashboard.html':
                self.serve_dashboard()
            # Serve API console
            elif path == "/api_console.html":
                self.serve_api_console()
            # API endpoints
            elif path.startswith('/api/'):
                if path == '/api/auth':
                    self.send_error(405, "Method not allowed")
                elif path == '/api/video/welcome':
                    # Handle video endpoint without authentication (temporary for testing)
                    self.handle_welcome_video()
                elif self.is_authenticated() or path == '/api/auth':
                    if path == '/api/list':
                        self.handle_list_directory(query)
                    elif path == '/api/videos':
                        self.handle_video_library()
                    elif path == '/api/file':
                        self.handle_file_content(query)
                    elif path == '/api/download':
                        self.handle_file_download(query)
                    elif path == '/api/view':
                        self.handle_file_view(query)
                    elif path == '/api/instructions':
                        self.serve_instructions()
                    elif path == '/api/instructions-info':
                        self.handle_instructions_info()
                    elif path == '/api/storage':
                        self.handle_storage_info()
                    elif path == "/api/debug-log":
                        self.handle_debug_log_view()
                    elif path == "/api/debug-log-viewer":
                        self.handle_debug_log_viewer()
                    elif path == '/api/file-operations':
                        self.handle_file_operations(query)
                    elif path == '/api/reserve-config':
                        self.handle_reserve_config()
                    elif path == '/api/playlists':
                        self.handle_get_playlists_with_metadata()
                    elif path == '/api/check-youtube-dl':
                        self.handle_check_youtube_dl()
                    else:
                        self.send_error(404, "API endpoint not found")
                else:
                    self.send_error(401, "Authentication required")
            else:
                self.send_error(404, "Not found")
                
        except (BrokenPipeError, ConnectionResetError, OSError):
            # Client disconnected, ignore silently
            return
        except Exception as e:
            print(f"Error handling request: {e}")
            try:
                self.send_error(500, f"Internal Server Error: {str(e)}")
            except (BrokenPipeError, ConnectionResetError, OSError):
                # Client disconnected while sending error, ignore
                return
    
    def do_POST(self):
        try:
            parsed_url = urllib.parse.urlparse(self.path)
            path = parsed_url.path
            
            if path == '/api/auth':
                self.handle_authentication()
            elif path == "/api/video/welcome":
                # Temporarily bypass authentication for testing
                self.handle_welcome_video()
            elif path == '/api/upload' and self.is_authenticated():
                self.handle_file_upload()
            elif path == '/api/download-zip' and self.is_authenticated():
                self.handle_zip_download()
            elif path == '/api/download-files-zip' and self.is_authenticated():
                self.handle_files_zip_download()
            elif path == '/api/create-file' and self.is_authenticated():
                self.handle_create_file()
            elif path == '/api/create-folder' and self.is_authenticated():
                self.handle_create_folder()
            elif path == '/api/delete-item' and self.is_authenticated():
                self.handle_delete_item()
            elif path == '/api/sudo-auth' and self.is_authenticated():
                self.handle_sudo_auth()
            elif path == '/api/general-upload' and self.is_authenticated():
                self.handle_general_upload()
            elif path == '/api/delete-video' and self.is_authenticated():
                self.handle_delete_video()
            elif path == '/api/verify-file-deletion' and self.is_authenticated():
                self.handle_verify_file_deletion()
            elif path == '/api/delete-file' and self.is_authenticated():
                self.handle_delete_file()
            elif path == "/api/log-action" and self.is_authenticated():
                self.handle_log_action_post()
            elif path == '/api/terminal' and self.is_authenticated():
                self.handle_terminal_command()
            elif path == "/api/storage_reserve_value_update" and self.is_authenticated():
                self.handle_storage_update()
            elif path == "/api/system-specs" and self.is_authenticated():
                self.handle_system_specs()
            elif path == "/api/validate_existing_playlist" and self.is_authenticated():
                self.handle_validate_existing_playlist()
            elif path == "/api/add_videos_to_playlist" and self.is_authenticated():
                self.handle_add_videos_to_playlist()
            elif path == "/api/load_playlist_content" and self.is_authenticated():
                self.handle_load_playlist_content()
            elif path == "/api/save_playlist_order" and self.is_authenticated():
                self.handle_save_playlist_order()
            elif path == "/api/remove_all_videos_from_playlist" and self.is_authenticated():
                self.handle_remove_all_videos_from_playlist()
            elif path == "/api/add_all_videos_to_playlist" and self.is_authenticated():
                self.handle_add_all_videos_to_playlist()
            elif path == "/api/add_single_video_to_playlist" and self.is_authenticated():
                self.handle_add_single_video_to_playlist()
            elif path == "/api/delete_single_playlist" and self.is_authenticated():
                self.handle_delete_single_playlist()
            elif path == "/api/delete_selected_playlists" and self.is_authenticated():
                self.handle_delete_selected_playlists()
            elif path == "/api/delete_all_playlists" and self.is_authenticated():
                self.handle_delete_all_playlists()
            elif path == "/api/open_playlist_content" and self.is_authenticated():
                self.handle_open_playlist_content()
            elif path == "/api/refresh_playlist_modal_metadata" and self.is_authenticated():
                self.handle_refresh_playlist_modal_metadata()
            else:
                self.send_error(404, "Not found")
                
        except (BrokenPipeError, ConnectionResetError, OSError):
            # Client disconnected, ignore silently
            return
        except Exception as e:
            print(f"Error handling POST request: {e}")
            try:
                self.send_error(500, f"Internal Server Error: {str(e)}")
            except (BrokenPipeError, ConnectionResetError, OSError):
                # Client disconnected while sending error, ignore
                return
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        try:
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
            self.send_header('Access-Control-Max-Age', '86400')
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
    
    def serve_login_page(self):
        """Serve the login page"""
        try:
            login_path = os.path.join('/home/gus/video-system/docs', 'login.html')
            if os.path.exists(login_path):
                with open(login_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
            else:
                self.send_error(404, "Login page not found")
        except Exception as e:
            self.send_error(500, f"Error serving login page: {str(e)}")
    
    def serve_dashboard(self):
        """Serve the dashboard (main application)"""
        try:
            dashboard_path = os.path.join('/home/gus/video-system/docs', 'dashboard.html')
            if os.path.exists(dashboard_path):
                with open(dashboard_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                self.send_header('Pragma', 'no-cache')
                self.send_header('Expires', '0')
                
                try:
                    self.end_headers()
                    self.wfile.write(content.encode('utf-8'))
                except (BrokenPipeError, ConnectionResetError, OSError):
                    # Client disconnected, ignore silently
                    return
                    
            else:
                self.send_error(404, "Dashboard not found")
        except (BrokenPipeError, ConnectionResetError, OSError):
            # Client disconnected, ignore silently
            return
        except Exception as e:
            try:
                self.send_error(500, f"Error serving dashboard: {str(e)}")
            except (BrokenPipeError, ConnectionResetError, OSError):
                # Client disconnected while sending error, ignore
                return
    
    def serve_api_console(self):
        """Serve the API console"""
        try:
            api_console_path = os.path.join("/home/gus/video-system/docs", "api_console.html")
            if os.path.exists(api_console_path):
                with open(api_console_path, "r", encoding="utf-8") as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header("Content-type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))
            else:
                self.send_error(404, "API console not found")
        except Exception as e:
            self.send_error(500, f"Error serving API console: {str(e)}")


    def serve_simple_login(self):
        """Serve the simple login test page"""
        try:
            simple_login_path = os.path.join('/home/gus/video-system/docs', 'simple_login.html')
            if os.path.exists(simple_login_path):
                with open(simple_login_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
            else:
                self.send_error(404, "Simple login page not found")
        except Exception as e:
            self.send_error(500, f"Error serving simple login page: {str(e)}")
    
    def serve_dashboard_debug(self):
        """Serve the dashboard debug page"""
        try:
            debug_path = os.path.join('/home/gus/video-system/docs', 'dashboard_debug.html')
            if os.path.exists(debug_path):
                with open(debug_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
            else:
                self.send_error(404, "Dashboard debug page not found")
        except Exception as e:
            self.send_error(500, f"Error serving dashboard debug page: {str(e)}")
    
    def serve_basic_test(self):
        """Serve the basic test page"""
        try:
            test_path = os.path.join('/home/gus/video-system/docs', 'test_basic.html')
            if os.path.exists(test_path):
                with open(test_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
            else:
                self.send_error(404, "Basic test page not found")
        except Exception as e:
            self.send_error(500, f"Error serving basic test page: {str(e)}")
    
    def serve_connection_data_file(self):
        """Serve the connection data file"""
        try:
            connection_data_path = '.client_side_data_for_video_system'
            if os.path.exists(connection_data_path):
                with open(connection_data_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json; charset=utf-8')
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
            else:
                self.send_error(404, "Connection data file not found")
        except Exception as e:
            self.send_error(500, f"Error serving connection data file: {str(e)}")
    
    def handle_authentication(self):
        """Handle login authentication"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                credentials = json.loads(post_data.decode('utf-8'))
                username = credentials.get('username', '')
                password = credentials.get('password', '')
            except json.JSONDecodeError:
                self.send_json_response({'success': False, 'message': 'Invalid request format'}, 400)
                return
            
            if self.validate_credentials(username, password):
                # Generate session token
                token = secrets.token_urlsafe(32)
                session_data = {
                    'username': username,
                    'created': time.time(),
                    'last_access': time.time()
                }
                active_sessions[token] = session_data
                
                self.send_json_response({
                    'success': True, 
                    'token': token,
                    'message': 'Authentication successful'
                })
            else:
                self.send_json_response({
                    'success': False, 
                    'message': 'Invalid username or password. Access denied.'
                }, 401)
                
        except Exception as e:
            self.send_json_response({
                'success': False, 
                'message': 'Authentication error'
            }, 500)
    
    def validate_credentials(self, username, password):
        """Validate credentials against .crds file"""
        try:
            crds_file = os.path.join(os.path.expanduser('~'), '.crds')
            if not os.path.exists(crds_file):
                return False
            
            with open(crds_file, 'r') as f:
                stored_credentials = f.read().strip()
            
            if ':' not in stored_credentials:
                return False
            
            stored_username, stored_password = stored_credentials.split(':', 1)
            return username == stored_username and password == stored_password
            
        except Exception as e:
            print(f"Error validating credentials: {e}")
            return False
    
    def is_authenticated(self):
        """Check if request is authenticated"""
        try:
            auth_header = self.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
                if token in active_sessions:
                    session = active_sessions[token]
                    # Update last access time
                    session['last_access'] = time.time()
                    return True
            return False
        except Exception:
            return False

    def get_auth_token(self):
        """Extract the bearer token from request headers"""
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        return "TOKEN"
    
    def redirect_to_login(self):
        """Redirect to login page"""
        self.send_response(302)
        self.send_header('Location', '/login.html')
        self.end_headers()
    
    def handle_list_directory(self, query):
        """Handle directory listing API endpoint"""
        try:
            target_path = query.get('path', ['/home/gus'])[0]
            
            if '..' in target_path or not os.path.isabs(target_path):
                self.send_error(403, "Access denied")
                return
            
            if not os.path.exists(target_path) or not os.path.isdir(target_path):
                self.send_error(404, "Directory not found")
                return
            
            files = []
            
            try:
                for item in sorted(os.listdir(target_path)):
                    # Skip hidden files except videos
                    if item.startswith('.') and not item.lower().endswith(('.mp4', '.webm', '.ogg', '.avi', '.mov', '.mkv', '.flv')):
                        continue
                        
                    item_path = os.path.join(target_path, item)
                    
                    try:
                        file_stat = os.stat(item_path)
                        is_dir = stat.S_ISDIR(file_stat.st_mode)
                        
                        def get_directory_size(path):
                            """Calculate total size of directory recursively"""
                            total_size = 0
                            try:
                                for dirpath, dirnames, filenames in os.walk(path):
                                    for filename in filenames:
                                        file_path = os.path.join(dirpath, filename)
                                        try:
                                            total_size += os.path.getsize(file_path)
                                        except (OSError, FileNotFoundError):
                                            continue
                            except (OSError, PermissionError):
                                pass
                            return total_size
                        
                        def format_size(size_bytes):
                            """Format bytes into human readable format with multiple units"""
                            if size_bytes == 0:
                                return "0 bytes"
                            elif size_bytes == 1:
                                return "1 byte"
                            elif size_bytes < 1024:
                                return f"{size_bytes} bytes"
                            elif size_bytes < 1024 * 1024:
                                kb = size_bytes / 1024
                                return f"{kb:.1f} KB ({size_bytes:,} bytes)"
                            elif size_bytes < 1024 * 1024 * 1024:
                                mb = size_bytes / (1024 * 1024)
                                kb = size_bytes / 1024
                                return f"{mb:.1f} MB ({kb:.0f} KB, {size_bytes:,} bytes)"
                            else:
                                gb = size_bytes / (1024 * 1024 * 1024)
                                mb = size_bytes / (1024 * 1024)
                                return f"{gb:.2f} GB ({mb:.0f} MB, {size_bytes:,} bytes)"
                        
                        if is_dir:
                            # Calculate actual directory size
                            dir_size_bytes = get_directory_size(item_path)
                            size = format_size(dir_size_bytes)
                        else:
                            # Format file size
                            size_bytes = file_stat.st_size
                            size = format_size(size_bytes)
                        
                        mime_type, _ = mimetypes.guess_type(item_path)
                        
                        file_info = {
                            'name': item,
                            'isDirectory': is_dir,
                            'size': size,
                            'type': mime_type
                        }
                        
                        files.append(file_info)
                    
                    except (OSError, PermissionError):
                        continue
            
            except PermissionError:
                self.send_error(403, "Permission denied")
                return
            
            response_data = {
                'path': target_path,
                'files': files
            }
            
            self.send_json_response(response_data)
            
        except Exception as e:
            self.send_error(500, f"Error listing directory: {str(e)}")
    
    def handle_video_library(self):
        """Handle video library API endpoint"""
        try:
            videos = []
            video_dirs = ['/home/gus/video-system/videos']
            video_extensions = ('.mp4', '.webm', '.ogg', '.avi', '.mov', '.mkv', '.flv')
            
            for base_dir in video_dirs:
                if not os.path.exists(base_dir):
                    continue
                    
                try:
                    for entry in os.scandir(base_dir):
                        try:
                            if entry.is_file() and entry.name.lower().endswith(video_extensions):
                                stat_info = entry.stat()
                                size_bytes = stat_info.st_size
                                
                                if size_bytes < 1024:
                                    size = f"{size_bytes} B"
                                elif size_bytes < 1024 * 1024:
                                    size = f"{size_bytes / 1024:.1f} KB"
                                elif size_bytes < 1024 * 1024 * 1024:
                                    size = f"{size_bytes / (1024 * 1024):.1f} MB"
                                else:
                                    size = f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
                                
                                video_info = {
                                    'name': entry.name,
                                    'path': entry.path,
                                    'size': size,
                                    'directory': base_dir
                                }
                                
                                videos.append(video_info)
                        
                        except (OSError, PermissionError):
                            continue
                
                except (OSError, PermissionError):
                    continue
            
            videos.sort(key=lambda x: x['name'].lower())
            
            response_data = {
                'videos': videos,
                'count': len(videos)
            }
            
            self.send_json_response(response_data)
            
        except Exception as e:
            self.send_error(500, f"Error loading video library: {str(e)}")
    
    def handle_file_content(self, query):
        """Handle file content API endpoint for text files"""
        try:
            file_path = query.get('path', [''])[0]
            
            if '..' in file_path or not os.path.isabs(file_path):
                self.send_error(403, "Access denied")
                return
            
            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                self.send_error(404, "File not found")
                return
            
            file_size = os.path.getsize(file_path)
            if file_size > 5 * 1024 * 1024:  # 5MB limit for text files
                self.send_error(413, "File too large to display")
                return
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header('Content-type', 'text/plain; charset=utf-8')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
                
            except UnicodeDecodeError:
                self.send_error(415, "Binary file - cannot display as text")
            
        except Exception as e:
            self.send_error(500, f"Error reading file: {str(e)}")
    
    def handle_file_download(self, query):
        """Handle file download endpoint"""
        try:
            file_path = query.get('path', [''])[0]
            
            if '..' in file_path or not os.path.isabs(file_path):
                self.send_error(403, "Access denied")
                return
            
            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                self.send_error(404, "File not found")
                return
            
            file_size = os.path.getsize(file_path)
            # Removed file size limit for downloads to allow large video files
            
            # Get MIME type
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type is None:
                mime_type = 'application/octet-stream'
            
            # Get filename
            filename = os.path.basename(file_path)
            
            try:
                self.send_response(200)
                self.send_header('Content-Type', mime_type)
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.send_header('Content-Length', str(file_size))
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                # Stream large files instead of loading into memory
                with open(file_path, 'rb') as f:
                    while True:
                        chunk = f.read(8192)  # Read in 8KB chunks
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                
            except Exception as e:
                self.send_error(500, f"Error reading file: {str(e)}")
            
        except Exception as e:
            self.send_error(500, f"Error downloading file: {str(e)}")
    
    def handle_file_view(self, query):
        """Handle file viewing endpoint for images and other viewable files"""
        try:
            file_path = query.get('path', [''])[0]
            
            if '..' in file_path or not os.path.isabs(file_path):
                self.send_error(403, "Access denied")
                return
            
            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                self.send_error(404, "File not found")
                return
            
            # Get MIME type
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type is None:
                mime_type = 'application/octet-stream'
            
            file_size = os.path.getsize(file_path)

            # Log video playback if it is a video file
            if mime_type and mime_type.startswith("video/"):
                filename = os.path.basename(file_path)
                debug_logger.log_action(
                    f"User played video: {filename}",
                    f"File size: {file_size / (1024 * 1024):.2f} MB  |  Type: {mime_type} | Path: {file_path}",
                    f"curl -X GET 'http://gcppftest01:9090/api/file?path={file_path}' -H 'Authorization: Bearer {self.get_auth_token()}'"
                )
            
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header('Content-Type', mime_type)
                self.send_header('Content-Length', str(len(content)))
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Cache-Control', 'public, max-age=3600')
                self.end_headers()
                self.wfile.write(content)
                
            except Exception as e:
                self.send_error(500, f"Error reading file: {str(e)}")
            
        except Exception as e:
            self.send_error(500, f"Error viewing file: {str(e)}")
    
    def serve_instructions(self):
        """Serve the setup instructions"""
        try:
            instructions_path = os.path.join('/home/gus/video-system/docs', 'VIDEO_SETUP_INSTRUCTIONS.txt')
            if os.path.exists(instructions_path):
                with open(instructions_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header('Content-type', 'text/plain; charset=utf-8')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
            else:
                self.send_error(404, "Instructions not found")
        except Exception as e:
            self.send_error(500, f"Error serving instructions: {str(e)}")
    
    def send_json_response(self, data, status_code=200):
        """Send JSON response"""
        json_data = json.dumps(data, separators=(',', ':'))
        
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(json_data.encode('utf-8'))
    
    def end_headers(self):
        """Add CORS headers"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        super().end_headers()
    
    def log_message(self, format, *args):
        """Minimal logging"""
        pass

    def handle_storage_info(self):
        """Handle storage information API endpoint"""
        try:
            # Get disk usage information
            video_dir = '/home/gus/video-system/videos'
            
            # Get filesystem stats
            statvfs = os.statvfs(video_dir)
            
            # Calculate storage information
            total_bytes = statvfs.f_frsize * statvfs.f_blocks
            available_bytes = statvfs.f_frsize * statvfs.f_bavail
            used_bytes = total_bytes - available_bytes
            
            # Read dynamic reserve value from config file
            config_file = '/home/gus/video-system/docs/reserved_value.txt'
            reserve_bytes = 0
            
            try:
                if os.path.exists(config_file):
                    with open(config_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Parse reserve value
                    reserve_match = re.search(r'reserved_value\s*=\s*([\d.]+)', content)
                    flag_match = re.search(r'reserved_value_flag\s*=\s*(True|False)', content)
                    
                    if reserve_match:
                        reserve_value_gb = float(reserve_match.group(1))
                        reserve_flag = flag_match and flag_match.group(1) == 'True'
                        
                        # If flag is True, reserve is disabled (value = 0)
                        if reserve_flag:
                            reserve_bytes = 0
                        else:
                            reserve_bytes = int(reserve_value_gb * 1024 * 1024 * 1024)
            except Exception as e:
                print(f"Error reading reserve config: {e}")
            
            storage_info = {
                'total': total_bytes,
                'used': used_bytes,
                'available': available_bytes,
                'video_directory': video_dir,
                'reserve_required': reserve_bytes,
                'upload_limit': max(0, available_bytes - reserve_bytes)
            }
            
            self.send_json_response(storage_info)
            
        except Exception as e:
            self.send_error(500, f"Error getting storage info: {str(e)}")
    
    def handle_reserve_config(self):
        """Handle reserve configuration file reading"""
        try:
            config_file = '/home/gus/video-system/docs/reserved_value.txt'
            
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header('Content-type', 'text/plain; charset=utf-8')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
            else:
                self.send_error(404, "Reserve configuration file not found")
                
        except Exception as e:
            self.send_error(500, f"Error reading reserve config: {str(e)}")
    
    def handle_storage_update(self):
        """Handle storage reserve value update API endpoint"""
        try:
            # Get POST data
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error(400, "No data provided")
                return
            
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            # Path to the configuration file
            config_file = '/home/gus/video-system/docs/reserved_value.txt'
            
            # Update values using sed commands
            import subprocess
            
            # Convert bytes to GB and update each value
            if 'total_disk_space' in data:
                total_gb = data['total_disk_space']
                subprocess.run(['sed', '-i', f's/^total_disk_space = .*/total_disk_space = {total_gb}/', config_file])
            
            if 'used_disk_space' in data:
                used_gb = data['used_disk_space']
                subprocess.run(['sed', '-i', f's/^used_disk_space = .*/used_disk_space = {used_gb}/', config_file])
            
            if 'reserved_value' in data:
                reserved = data['reserved_value']
                subprocess.run(['sed', '-i', f's/^reserved_value = .*/reserved_value = {reserved}/', config_file])
            
            if 'upload_limit_value' in data:
                upload_limit = data['upload_limit_value']
                subprocess.run(['sed', '-i', f's/^upload_limit_value = .*/upload_limit_value = {upload_limit}/', config_file])
            
            if 'reserved_value_flag' in data:
                flag = data['reserved_value_flag']
                subprocess.run(['sed', '-i', f's/^reserved_value_flag = .*/reserved_value_flag = {flag}/', config_file])
            
            self.send_json_response({"success": True, "message": "Storage values updated successfully"})
            
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON data")
        except Exception as e:
            self.send_error(500, f"Error updating storage values: {str(e)}")

    def handle_system_specs(self):
        """Handle Linux system specifications API endpoint"""
        try:
            start_time = time.time()
            
            # Initialize response data
            response_data = {
                'timestamp': time.time(),
                'method': None,
                'inxi_available': False,
                'system': {},
                'hardware': {},
                'network': {},
                'memory': {},
                'inxi_output': None
            }
            
            try:
                # First, check if inxi is available
                inxi_check = subprocess.run(['which', 'inxi'], capture_output=True, text=True)
                if inxi_check.returncode == 0:
                    response_data['inxi_available'] = True
                    response_data['method'] = 'inxi -Fx'
                    
                    # Run inxi -Fx for comprehensive system information
                    inxi_result = subprocess.run(['inxi', '-Fx'], capture_output=True, text=True, timeout=30)
                    if inxi_result.returncode == 0:
                        response_data['inxi_output'] = inxi_result.stdout
                        
                        # Parse some key information from inxi output
                        lines = inxi_result.stdout.split('\n')
                        for line in lines:
                            if 'System:' in line:
                                response_data['system']['raw_system'] = line.strip()
                            elif 'Machine:' in line or 'Host:' in line:
                                response_data['system']['machine'] = line.strip()
                            elif 'CPU:' in line:
                                response_data['hardware']['cpu'] = line.strip()
                            elif 'Memory:' in line:
                                response_data['memory']['ram'] = line.strip()
                else:
                    response_data['method'] = 'multiple system commands'
                
                # Always gather additional network information
                try:
                    # Get network interfaces and IP addresses
                    ip_result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=10)
                    if ip_result.returncode == 0:
                        response_data['network']['interfaces'] = ip_result.stdout
                    
                    # Get routing table
                    route_result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True, timeout=10)
                    if route_result.returncode == 0:
                        response_data['network']['routing'] = route_result.stdout
                    
                    # Get hostname
                    hostname_result = subprocess.run(['hostname'], capture_output=True, text=True, timeout=5)
                    if hostname_result.returncode == 0:
                        response_data['system']['hostname'] = hostname_result.stdout.strip()
                    
                    # Get system uptime
                    uptime_result = subprocess.run(['uptime'], capture_output=True, text=True, timeout=5)
                    if uptime_result.returncode == 0:
                        response_data['system']['uptime'] = uptime_result.stdout.strip()
                    
                    # Get kernel version
                    kernel_result = subprocess.run(['uname', '-a'], capture_output=True, text=True, timeout=5)
                    if kernel_result.returncode == 0:
                        response_data['system']['kernel'] = kernel_result.stdout.strip()
                    
                    # Get OS information
                    if os.path.exists('/etc/os-release'):
                        with open('/etc/os-release', 'r') as f:
                            response_data['system']['os_release'] = f.read()
                    
                    # Get memory information
                    if os.path.exists('/proc/meminfo'):
                        with open('/proc/meminfo', 'r') as f:
                            meminfo = f.read()
                            response_data['memory']['meminfo'] = meminfo
                    
                    # Get CPU information
                    if os.path.exists('/proc/cpuinfo'):
                        with open('/proc/cpuinfo', 'r') as f:
                            cpuinfo = f.read()
                            response_data['hardware']['cpuinfo'] = cpuinfo
                    
                    # Get disk usage
                    df_result = subprocess.run(['df', '-h'], capture_output=True, text=True, timeout=10)
                    if df_result.returncode == 0:
                        response_data['memory']['disk_usage'] = df_result.stdout
                    
                    # Get network configuration details
                    ifconfig_result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=10)
                    if ifconfig_result.returncode == 0:
                        response_data['network']['ifconfig'] = ifconfig_result.stdout
                    
                except Exception as network_error:
                    response_data['network']['error'] = str(network_error)
                
            except subprocess.TimeoutExpired:
                response_data['error'] = 'Command timeout'
            except Exception as cmd_error:
                response_data['error'] = str(cmd_error)
            
            # Calculate response time
            response_data['response_time'] = int((time.time() - start_time) * 1000)
            
            # Log system specs request
            debug_logger.log_action(
                "User requested system specifications",
                f"Method: {response_data['method']} | Inxi available: {response_data['inxi_available']} | Response time: {response_data['response_time']}ms",
                f"curl -X POST 'http://gcppftest01:9090/api/system-specs' -H 'Authorization: Bearer {self.get_auth_token()}'"
            )
            
            self.send_json_response(response_data)
            
        except Exception as e:
            logger.error(f"Error getting system specs: {e}")
            self.send_error(500, f"Error retrieving system specifications: {str(e)}")

    def handle_debug_log_view(self):
        """Handle debug log viewing API endpoint"""
        try:
            debug_log_path = "/home/gus/video-system/logs/debug.log"
            if os.path.exists(debug_log_path):
                with open(debug_log_path, "r", encoding="utf-8") as f:
                    content = f.read()

                self.send_response(200)
                self.send_header("Content-type", "text/plain; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))
            else:
                self.send_response(200)
                self.send_header("Content-type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Debug log is empty or does not exist.")
        except Exception as e:
            self.send_error(500, f"Error reading debug log: {str(e)}")

    def handle_log_action_post(self):
        """Handle logging user actions via POST"""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode("utf-8"))

                action = data.get("action", "Unknown action")
                details = data.get("details", "")
                endpoint = data.get("endpoint", "")
                method = data.get("method", "GET")
                
                # Get the authentication token
                auth_header = self.headers.get("Authorization", "")
                token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else "NO_TOKEN"
                
                # Create proper API curl command based on section
                host = self.headers.get("Host", "localhost:9090")
                
                # Map sections to their actual API endpoints
                # Handle file-specific operations first
                if "deleted file:" in action.lower():
                    filename = re.sub(r"[<> | &;\s]+.*$", "", action.split("deleted file: ")[1].strip()) if "deleted file: " in action else "FILENAME"
                    curl_cmd = f"curl -X POST http://{host}/api/delete-file -H \'Content-Type: application/json\' -H \'Authorization: Bearer {token}\' -d \'{{\"path\": \"/home/gus/video-system/videos/{filename}\"}}\'";
                elif "uploaded video:" in action.lower():
                    filename = re.sub(r"[<>|&;\s]+.*$", "", action.split("uploaded video: ")[1].strip()) if "uploaded video: " in action else "VIDEO_FILE"
                    curl_cmd = f"curl -X POST http://{host}/api/upload -H \'Authorization: Bearer {token}\' -F \'file=@{filename}\'";
                elif "uploaded file:" in action.lower() and "general upload" not in action.lower():
                    filename = re.sub(r"[<>|&;\s]+.*$", "", action.split("uploaded file: ")[1].strip()) if "uploaded file: " in action else "FILE"
                    curl_cmd = f"curl -X POST http://{host}/api/general-upload -H \'Authorization: Bearer {token}\' -F \'file=@{filename}\'";
                elif "video section" in action.lower():
                    curl_cmd = f"curl -X GET http://{host}/api/videos -H \"Authorization: Bearer {token}\""
                elif "file section" in action.lower() or "navigat" in action.lower():
                    curl_cmd = f"curl -X GET http://{host}/api/list?path=/home/gus -H \"Authorization: Bearer {token}\""
                elif "upload section" in action.lower():
                    curl_cmd = f"curl -X POST http://{host}/api/general-upload -H \"Authorization: Bearer {token}\" -F \"file=@filename.ext\""
                elif "download section" in action.lower():
                    curl_cmd = f"curl -X GET http://{host}/api/videos -H \"Authorization: Bearer {token}\""
                elif "general-upload section" in action.lower():
                    curl_cmd = f"curl -X POST http://{host}/api/general-upload -H \"Authorization: Bearer {token}\" -F \"file=@filename.ext\""
                elif endpoint.startswith("/api/"):
                    # Real API call with actual endpoint
                    if method == "POST":
                        curl_cmd = f"curl -X POST http://{host}{endpoint} -H \"Content-Type: application/json\" -H \"Authorization: Bearer {token}\" -d '{{data}}\""
                    else:
                        curl_cmd = f"curl -X {method} http://{host}{endpoint} -H \"Authorization: Bearer {token}\""
                else:
                    # Default - don't show curl for non-API actions
                    curl_cmd = None
                
                # Log the action
                debug_logger.log_action(action, details, curl_cmd)

                response = {"status": "success", "message": "Action logged"}
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
            else:
                self.send_error(400, "No data provided")
        except Exception as e:
            self.send_error(500, f"Error logging action: {str(e)}")


    def handle_video_play_log(self):
        """Handle video playback logging"""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data.decode("utf-8"))

                filename = data.get("filename", "unknown_video")
                video_path = data.get("path", "/home/gus/video-system/videos/")
                duration = data.get("duration", "unknown")
                file_size = data.get("size", "unknown")
                
                # Get authentication token
                auth_header = self.headers.get("Authorization", "")
                token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else "NO_TOKEN"
                
                host = self.headers.get("Host", "localhost:9090")
                
                action = f"User played video: {filename}"
                details = f"Duration: {duration} |  Size: {file_size} | Path: {video_path}"
                curl_cmd = f"curl -X GET http://{host}/api/videos -H Authorization: Bearer {token} | grep {filename}"
                
                # Log the video play action
                debug_logger.log_action(action, details, curl_cmd)

                response = {"status": "success", "message": "Video play logged"}
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
            else:
                self.send_error(400, "No data provided")
        except Exception as e:
            self.send_error(500, f"Error logging video play: {str(e)}")

    def handle_instructions_info(self):
        """Handle instructions information API endpoint - returns full text content"""
        try:
            instructions_path = os.path.join("/home/gus/video-system/docs", "VIDEO_SETUP_INSTRUCTIONS.txt")
            
            if os.path.exists(instructions_path):
                with open(instructions_path, "r", encoding="utf-8") as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header('Content-type', 'text/plain; charset=utf-8')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
            else:
                self.send_error(404, "Instructions file not found")
            
        except Exception as e:
            self.send_error(500, f"Error getting instructions: {str(e)}")
    
    def handle_file_upload(self):
        """Handle file upload API endpoint with SCP support for large files"""
        try:
            # Parse the multipart form data using same approach as general upload
            content_length = int(self.headers['Content-Length'])
            
            # Check if this is a large file upload
            
            # Create a temporary file for parsing
            temp_file = tempfile.NamedTemporaryFile()
            temp_file.write(self.rfile.read(content_length))
            temp_file.seek(0)
            
            # Parse multipart data
            env = {
                'REQUEST_METHOD': 'POST',
                'CONTENT_TYPE': self.headers['Content-Type'],
                'CONTENT_LENGTH': str(content_length)
            }
            
            form = cgi.FieldStorage(
                fp=temp_file,
                headers=self.headers,
                environ=env
            )
            
            if 'video' not in form:
                self.send_error(400, "No video file uploaded")
                return
            
            file_item = form['video']
            if not file_item.filename:
                self.send_error(400, "No filename provided")
                return
            
            # Validate file type
            if not file_item.filename.lower().endswith(('.mp4', '.webm', '.ogg', '.avi', '.mov', '.mkv', '.flv')):
                self.send_error(400, "Invalid file type. Only video files allowed.")
                return
            
            video_dir = '/home/gus/video-system/videos'
            
            # Generate safe filename
            safe_filename = self.sanitize_filename(file_item.filename)
            file_path = os.path.join(video_dir, safe_filename)
            
            # Handle filename conflicts
            counter = 1
            base_name, ext = os.path.splitext(safe_filename)
            while os.path.exists(file_path):
                safe_filename = f"{base_name}_{counter}{ext}"
                file_path = os.path.join(video_dir, safe_filename)
                counter += 1
            
            # Save the file
            with open(file_path, 'wb') as f:
                f.write(file_item.file.read())
            
            # Get file size after writing
            file_size = os.path.getsize(file_path)
            
            # Set proper permissions
            os.chmod(file_path, 0o644)
            
            # Log the video upload
            debug_logger.log_action(
                f"User uploaded video: {safe_filename}",
                f"File size: {file_size / (1024 * 1024):.2f} MB  |  Type: video | Path: {file_path}",
                f'curl -X POST http://gcppftest01:9090/api/upload -H "Authorization: Bearer {self.get_auth_token()}" -F "video=@/path/to/your/video/{safe_filename}"'
            )
            
            # Return success response
            response_data = {
                'success': True,
                'filename': safe_filename,
                'size': file_size,
                'path': file_path,
                'message': f'Successfully uploaded {safe_filename}'
            }
            
            self.send_json_response(response_data)
            
        except Exception as e:
            print(f"Upload error: {e}")
            self.send_error(500, f"Error uploading file: {str(e)}")
    
    def handle_general_upload(self):
        """Handle general file upload to ~/random_files/ with SCP support for large files"""
        try:
            # Parse the multipart form data
            content_length = int(self.headers['Content-Length'])
            
            # Check if this is a large file upload
            
            # Create a temporary file for parsing
            temp_file = tempfile.NamedTemporaryFile()
            temp_file.write(self.rfile.read(content_length))
            temp_file.seek(0)
            
            # Parse multipart data
            env = {
                'REQUEST_METHOD': 'POST',
                'CONTENT_TYPE': self.headers['Content-Type'],
                'CONTENT_LENGTH': str(content_length)
            }
            
            form = cgi.FieldStorage(
                fp=temp_file,
                headers=self.headers,
                environ=env
            )
            
            # Get the uploaded file
            if 'file' not in form:
                self.send_error(400, "No file uploaded")
                return
            
            file_item = form['file']
            
            if not file_item.filename:
                self.send_error(400, "No file selected")
                return
            
            # Create random_files directory if it doesn't exist
            random_files_dir = os.path.join('/home/gus', 'random_files')
            if not os.path.exists(random_files_dir):
                os.makedirs(random_files_dir, exist_ok=True)
            
            # Sanitize filename for general files
            safe_filename = self.sanitize_general_filename(file_item.filename)
            file_path = os.path.join(random_files_dir, safe_filename)
            
            # Handle duplicate filenames
            counter = 1
            original_path = file_path
            while os.path.exists(file_path):
                name, ext = os.path.splitext(original_path)
                file_path = f"{name}_{counter}{ext}"
                counter += 1
            
            # Save the file
            with open(file_path, 'wb') as f:
                f.write(file_item.file.read())
            
            file_size = os.path.getsize(file_path)
            
            print(f"General file uploaded: {file_path} ({file_size} bytes)")
            
            # Log the general file upload
            debug_logger.log_action(
                f"User uploaded file: {safe_filename}",
                f"File size: {file_size / (1024 * 1024):.2f} MB  |  Type: general | Path: {file_path}",
                f'curl -X POST http://gcppftest01:9090/api/general-upload -H "Authorization: Bearer {self.get_auth_token()}" -F "file=@/path/to/your/file/{safe_filename}"'
            )
            
            response_data = {
                'success': True,
                'filename': safe_filename,
                'size': file_size,
                'path': file_path,
                'message': f'Successfully uploaded {safe_filename} to random_files/'
            }
            
            self.send_json_response(response_data)
            
        except Exception as e:
            print(f"General upload error: {e}")
            self.send_error(500, f"Error uploading file: {str(e)}")
    
    # handle_large_file_upload function DISABLED per user request
    # File size restrictions removed - uploads controlled by client-side reserve value only
    
    def sanitize_general_filename(self, filename):
        """Sanitize filename for general files"""
        # Allow more characters for general files
        safe_chars = "-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        safe_filename = ''.join(c for c in filename if c in safe_chars)
        
        # Remove leading/trailing spaces and dots
        safe_filename = safe_filename.strip(' .')
        
        # Ensure we have a filename
        if not safe_filename:
            safe_filename = f"file_{int(time.time())}.dat"
        
        # Limit length
        if len(safe_filename) > 100:
            name, ext = os.path.splitext(safe_filename)
            safe_filename = name[:90] + ext
        
        return safe_filename

    def handle_delete_video(self):
        """Handle video deletion"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length:
                request_body = self.rfile.read(content_length)
                data = json.loads(request_body.decode('utf-8'))
            else:
                self.send_error(400, "Missing request body")
                return
            
            video_path = data.get('path')
            if not video_path:
                self.send_error(400, "Missing video path")
                return
            
            # Security check: ensure the path is within the videos directory
            video_dir = '/home/gus/video-system/videos'
            if video_path.startswith('/home/gus/video-system/videos/'):
                full_path = video_path
            else:
                full_path = os.path.join(video_dir, video_path)
            
            # Additional security check
            if '..' in full_path or not full_path.startswith(video_dir):
                self.send_error(403, "Access denied")
                return
            
            if not os.path.exists(full_path):
                self.send_error(404, "Video not found")
                return
            
            if not os.path.isfile(full_path):
                self.send_error(400, "Path is not a file")
                return
            
            # Delete the file
            os.remove(full_path)
            
            print(f"Video deleted: {full_path}")
            
            response_data = {
                'success': True,
                'message': f'Successfully deleted {os.path.basename(full_path)}',
                'path': full_path
            }
            
            self.send_json_response(response_data)
            
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
        except Exception as e:
            print(f"Delete video error: {e}")
            self.send_error(500, f"Error deleting video: {str(e)}")
    
    def handle_verify_file_deletion(self):
        """Verify if a file was successfully deleted from the server"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length:
                request_body = self.rfile.read(content_length)
                data = json.loads(request_body.decode('utf-8'))
            else:
                self.send_error(400, "Missing request body")
                return
            
            file_path = data.get('path')
            if not file_path:
                self.send_error(400, "Missing file path")
                return
            
            # Security check: ensure the path is within allowed directories
            allowed_dirs = [
                '/home/gus/video-system/videos',
                '/home/gus/random_files'
            ]
            
            # Determine full path
            if file_path.startswith('/home/gus/'):
                full_path = file_path
            else:
                # Default to video directory if relative path
                full_path = os.path.join('/home/gus/video-system/videos', file_path)
            
            # Security check: ensure the path is within allowed directories
            is_allowed = any(full_path.startswith(allowed_dir) for allowed_dir in allowed_dirs)
            if not is_allowed or '..' in full_path:
                self.send_error(403, "Access denied - path not in allowed directories")
                return
            
            # Check if file exists using ls command on the server
            try:
                import subprocess
                # Use ls command to verify file exists
                result = subprocess.run(['ls', full_path], capture_output=True, text=True)
                file_exists = (result.returncode == 0)
            except Exception:
                # Fallback to os.path.exists if subprocess fails
                file_exists = os.path.exists(full_path)
            
            response_data = {
                'success': True,
                'exists': file_exists,
                'path': full_path,
                'message': f'File {"exists" if file_exists else "does not exist"} on server (verified with ls)'
            }
            
            self.send_json_response(response_data)
            
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
        except Exception as e:
            print(f"Verify file deletion error: {e}")
            self.send_error(500, f"Error verifying file deletion: {str(e)}")
    
    def handle_delete_file(self):
        """Handle file deletion with enhanced security checks"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length:
                request_body = self.rfile.read(content_length)
                data = json.loads(request_body.decode('utf-8'))
            else:
                self.send_error(400, "Missing request body")
                return
            
            file_path = data.get('path')
            if not file_path:
                self.send_error(400, "Missing file path")
                return
            
            # Define allowed directories for file deletion
            allowed_dirs = [
                '/home/gus/random_files',
                '/home/gus/video-system/videos',
                '/home/gus/Downloads',
                '/home/gus/Documents',
                '/home/gus/Pictures',
                '/home/gus/Music',
                '/tmp'
            ]
            
            # Critical system files and directories that cannot be deleted
            critical_paths = [
                '/home/gus/video-system/docs/dashboard',  # Matches dashboard*.html
                '/home/gus/video-system/scripts/auth_api_server',  # Matches auth_api_server*
                '/etc/nginx',  # Matches nginx*
                '/usr/local/nginx',  # Matches nginx*
                '/var/log/nginx',  # Matches nginx*
                '/home/gus/.ssh/',
                '/home/gus/.bashrc',
                '/home/gus/.bash_profile',
                '/home/gus/.profile'
            ]
            
            # Security check: ensure the path is within allowed directories
            allowed = False
            for allowed_dir in allowed_dirs:
                if file_path.startswith(allowed_dir):
                    allowed = True
                    break
            
            if not allowed:
                self.send_error(403, "Access denied - directory not allowed")
                return
            
            # Check if file is a critical system file
            for critical_path in critical_paths:
                if file_path.startswith(critical_path) or file_path == critical_path:
                    self.send_error(403, "Access denied - critical system file")
                    return
            
            # Additional security check for path traversal
            if '..' in file_path:
                self.send_error(403, "Access denied - path traversal detected")
                return
            
            if not os.path.exists(file_path):
                self.send_error(404, "File not found")
                return
            
            if not os.path.isfile(file_path):
                self.send_error(400, "Path is not a file")
                return
            
            # Delete the file
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            os.remove(file_path)
            
            print(f"File deleted: {file_path}")
            
            # Log the file deletion
            debug_logger.log_action(
                f"User deleted file: {filename}",
                f"Full path: {file_path}  |  Directory: {os.path.dirname(file_path)} | Size: {file_size / (1024 * 1024):.2f} MB",
                f'curl -X POST http://gcppftest01:9090/api/delete-file -H "Content-Type: application/json" -H "Authorization: Bearer {self.get_auth_token()}" -d "{{"path": "{file_path}"}}"'
            )
            
            response_data = {
                'success': True,
                'message': f'Successfully deleted {os.path.basename(file_path)}',
                'path': file_path
            }
            
            self.send_json_response(response_data)
            
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
        except Exception as e:
            print(f"Delete file error: {e}")
            self.send_error(500, f"Error deleting file: {str(e)}")

    def handle_terminal_command(self):
        """Handle terminal command execution with session persistence"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length:
                request_body = self.rfile.read(content_length)
                data = json.loads(request_body.decode('utf-8'))
            else:
                self.send_error(400, "Missing request body")
                return
            
            command = data.get('command')
            session_id = data.get('session_id', 'default')
            
            # Handle special commands
            if command == 'get_cwd':
                # Return current working directory
                session = terminal_sessions.get(session_id, {'cwd': '/home/gus', 'env': {}})
                response_data = {
                    'success': True,
                    'output': session['cwd'],
                    'cwd': session['cwd']
                }
                self.send_json_response(response_data)
                return
            
            if not command:
                self.send_error(400, "Missing command")
                return
            
            # Get or create terminal session
            if session_id not in terminal_sessions:
                terminal_sessions[session_id] = {
                    'cwd': '/home/gus',
                    'env': {
                        'HOME': '/home/gus', 
                        'USER': 'gus', 
                        'PATH': '/usr/local/bin:/usr/bin:/bin',
                        'SHELL': '/bin/bash'
                    }
                }
            
            session = terminal_sessions[session_id]
            
            # Security: Block dangerous commands
            dangerous_commands = [
                'rm -rf /', 'sudo rm', 'dd if=', 'mkfs', 'fdisk',
                'shutdown', 'reboot', 'halt', 'init 0', 'init 6',
                'passwd', 'su ', 'sudo su', 'chmod 777', 'chown root',
                '> /etc/', '> /var/', '> /usr/', '> /bin/', '> /sbin/',
                '/dev/null', '/dev/zero', 'fork()', 'while true',
                'curl http', 'wget http', 'nc -l', 'netcat -l'
            ]
            
            command_lower = command.lower().strip()
            for dangerous in dangerous_commands:
                if dangerous in command_lower:
                    response_data = {
                        'success': False,
                        'error': f'Command blocked for security: {dangerous}',
                        'output': '',
                        'cwd': session['cwd']
                    }
                    self.send_json_response(response_data)
                    return
            
            # Handle cd command specially to update session state
            if command_lower.startswith('cd ') or command_lower == 'cd':
                if command_lower == 'cd':
                    # cd with no arguments goes to home
                    new_dir = '/home/gus'
                else:
                    # Extract directory from cd command
                    dir_arg = command[3:].strip()
                    if dir_arg.startswith('~/'):
                        new_dir = '/home/gus/' + dir_arg[2:]
                    elif dir_arg == '~':
                        new_dir = '/home/gus'
                    elif dir_arg.startswith('/'):
                        new_dir = dir_arg
                    else:
                        new_dir = os.path.join(session['cwd'], dir_arg)
                
                # Normalize path and check if it exists
                try:
                    new_dir = os.path.abspath(new_dir)
                    if os.path.exists(new_dir) and os.path.isdir(new_dir):
                        session['cwd'] = new_dir
                        response_data = {
                            'success': True,
                            'output': f'',  # cd typically produces no output
                            'cwd': session['cwd']
                        }
                    else:
                        response_data = {
                            'success': False,
                            'output': f'bash: cd: {dir_arg}: No such file or directory\n',
                            'cwd': session['cwd']
                        }
                except Exception as e:
                    response_data = {
                        'success': False,
                        'output': f'bash: cd: {dir_arg}: {str(e)}\n',
                        'cwd': session['cwd']
                    }
                
                self.send_json_response(response_data)
                return
            
            # Execute command with session context
            import subprocess
            try:
                # Update environment with current working directory
                env = session['env'].copy()
                env['PWD'] = session['cwd']
                
                # Execute command with session's working directory
                result = subprocess.run(
                    command,
                    shell=True,
                    cwd=session['cwd'],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=env
                )
                
                output = ''
                if result.stdout:
                    output += result.stdout
                if result.stderr:
                    output += result.stderr
                
                # Limit output size
                if len(output) > 10000:
                    output = output[:10000] + '\n... [Output truncated after 10000 characters]'
                
                response_data = {
                    'success': result.returncode == 0,
                    'output': output,
                    'return_code': result.returncode,
                    'cwd': session['cwd']
                }
                
            except subprocess.TimeoutExpired:
                response_data = {
                    'success': False,
                    'error': 'Command timed out (30 seconds)',
                    'output': '',
                    'cwd': session['cwd']
                }
            except Exception as e:
                response_data = {
                    'success': False,
                    'error': f'Execution error: {str(e)}',
                    'output': '',
                    'cwd': session['cwd']
                }
            
            self.send_json_response(response_data)
            
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
        except Exception as e:
            print(f"Terminal command error: {e}")
            self.send_error(500, f"Error executing command: {str(e)}")

    def sanitize_filename(self, filename):
        """Sanitize filename for safe storage"""
        # Remove path separators and dangerous characters
        safe_chars = "-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        safe_filename = ''.join(c for c in filename if c in safe_chars)
        
        # Remove leading/trailing spaces and dots
        safe_filename = safe_filename.strip(' .')
        
        # Ensure we have a filename
        if not safe_filename:
            safe_filename = f"video_{int(time.time())}.mp4"
        
        # Limit length
        if len(safe_filename) > 100:
            name, ext = os.path.splitext(safe_filename)
            safe_filename = name[:90] + ext
        
        return safe_filename
    
    def handle_zip_download(self):
        """Handle ZIP download of multiple videos"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                video_paths = data.get('videos', [])
            except json.JSONDecodeError:
                self.send_error(400, "Invalid JSON request")
                return
            
            if not video_paths:
                self.send_error(400, "No videos specified")
                return
            
            # Validate paths
            valid_paths = []
            for path in video_paths:
                if '..' in path or not os.path.isabs(path):
                    continue
                if os.path.exists(path) and os.path.isfile(path):
                    valid_paths.append(path)
            
            if not valid_paths:
                self.send_error(404, "No valid video files found")
                return
            
            # Create ZIP in memory
            zip_buffer = io.BytesIO()
            
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for file_path in valid_paths:
                    try:
                        # Get just the filename for the ZIP entry
                        file_name = os.path.basename(file_path)
                        
                        # Add counter if filename already exists
                        base_name, ext = os.path.splitext(file_name)
                        counter = 1
                        final_name = file_name
                        
                        while final_name in [info.filename for info in zip_file.infolist()]:
                            final_name = f"{base_name}_{counter}{ext}"
                            counter += 1
                        
                        zip_file.write(file_path, final_name)
                        
                    except Exception as e:
                        print(f"Error adding {file_path} to ZIP: {e}")
                        continue
            
            zip_buffer.seek(0)
            zip_data = zip_buffer.getvalue()
            zip_buffer.close()
            
            if not zip_data:
                self.send_error(500, "Failed to create ZIP file")
                return
            
            # Generate filename
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"videos-{timestamp}.zip"
            
            # Send ZIP file
            self.send_response(200)
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.send_header('Content-Length', str(len(zip_data)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(zip_data)
            
        except Exception as e:
            print(f"ZIP download error: {e}")
            self.send_error(500, f"Error creating ZIP download: {str(e)}")

    def handle_files_zip_download(self):
        """Handle ZIP download of multiple files (any file types)"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                file_paths = data.get('files', [])
            except json.JSONDecodeError:
                self.send_error(400, "Invalid JSON request")
                return
            
            if not file_paths:
                self.send_error(400, "No files specified")
                return
            
            # Validate paths
            valid_paths = []
            for path in file_paths:
                if '..' in path or not os.path.isabs(path):
                    continue
                if os.path.exists(path) and os.path.isfile(path):
                    valid_paths.append(path)
            
            if not valid_paths:
                self.send_error(404, "No valid files found")
                return
            
            # Create ZIP in memory
            zip_buffer = io.BytesIO()
            
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for file_path in valid_paths:
                    try:
                        # Get just the filename for the ZIP entry
                        file_name = os.path.basename(file_path)
                        
                        # Add counter if filename already exists
                        base_name, ext = os.path.splitext(file_name)
                        counter = 1
                        final_name = file_name
                        
                        while final_name in [info.filename for info in zip_file.infolist()]:
                            final_name = f"{base_name}_{counter}{ext}"
                            counter += 1
                        
                        zip_file.write(file_path, final_name)
                        
                    except Exception as e:
                        print(f"Error adding {file_path} to ZIP: {e}")
                        continue
            
            zip_buffer.seek(0)
            zip_data = zip_buffer.getvalue()
            zip_buffer.close()
            
            if not zip_data:
                self.send_error(500, "Failed to create ZIP file")
                return
            
            # Generate filename
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            filename = f"files-{timestamp}.zip"
            
            # Send ZIP file
            self.send_response(200)
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.send_header('Content-Length', str(len(zip_data)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            self.wfile.write(zip_data)
            
            # Log the download
            debug_logger.log_action(
                f"User downloaded ZIP archive: {filename}",
                f"Files: {len(valid_paths)} files | Size: {len(zip_data)/1024/1024:.2f} MB",
                f"curl -X POST 'http://gcppftest01:9090/api/download-files-zip' -H 'Authorization: Bearer TOKEN' -d '{json.dumps({'files': valid_paths})}'"
            )
            
        except Exception as e:
            print(f"Error creating files ZIP: {e}")
            self.send_error(500, f"Error creating ZIP: {str(e)}")

    def format_bytes(self, size_bytes):
        """Format bytes into human readable format with multiple units"""
        if size_bytes == 0:
            return "0 bytes"
        elif size_bytes == 1:
            return "1 byte"
        elif size_bytes < 1024:
            return f"{size_bytes} bytes"
        elif size_bytes < 1024 * 1024:
            kb = size_bytes / 1024
            return f"{kb:.1f} KB ({size_bytes:,} bytes)"
        elif size_bytes < 1024 * 1024 * 1024:
            mb = size_bytes / (1024 * 1024)
            kb = size_bytes / 1024
            return f"{mb:.1f} MB ({kb:.0f} KB, {size_bytes:,} bytes)"
        else:
            gb = size_bytes / (1024 * 1024 * 1024)
            mb = size_bytes / (1024 * 1024)
            return f"{gb:.2f} GB ({mb:.0f} MB, {size_bytes:,} bytes)"
    
    def handle_file_operations(self, query):
        """Handle file operations requests (list, info, permissions)"""
        try:
            path = query.get('path', [''])[0]
            operation = query.get('operation', [''])[0]
            
            if not path or not operation:
                self.send_error(400, "Path and operation parameters required")
                return
            
            # Get absolute path
            if not os.path.isabs(path):
                path = os.path.abspath(path)
            
            if not os.path.exists(path):
                self.send_error(404, f"Path not found: {path}")
                return
            
            response = {}
            
            if operation == 'list':
                if os.path.isdir(path):
                    try:
                        items = []
                        for item in os.listdir(path):
                            item_path = os.path.join(path, item)
                            item_stat = os.stat(item_path)
                            
                            # Calculate directory size or use file size
                            if os.path.isdir(item_path):
                                # Calculate directory size recursively
                                total_size = 0
                                try:
                                    for dirpath, dirnames, filenames in os.walk(item_path):
                                        for filename in filenames:
                                            file_path = os.path.join(dirpath, filename)
                                            try:
                                                total_size += os.path.getsize(file_path)
                                            except (OSError, FileNotFoundError):
                                                continue
                                except (OSError, PermissionError):
                                    pass
                                size_display = self.format_bytes(total_size)
                            else:
                                size_display = self.format_bytes(item_stat.st_size)
                            
                            items.append({
                                'name': item,
                                'path': item_path,
                                'is_directory': os.path.isdir(item_path),
                                'size': size_display,
                                'modified': time.ctime(item_stat.st_mtime)
                            })
                        response = {
                            'path': path,
                            'operation': operation,
                            'items': sorted(items, key=lambda x: (not x['is_directory'], x['name']))
                        }
                    except PermissionError:
                        response = {'error': f"Permission denied accessing: {path}"}
                else:
                    response = {'error': f"Path is not a directory: {path}"}
            
            elif operation == 'info':
                try:
                    item_stat = os.stat(path)
                    response = {
                        'path': path,
                        'operation': operation,
                        'is_directory': os.path.isdir(path),
                        'is_file': os.path.isfile(path),
                        'size': item_stat.st_size,
                        'modified': time.ctime(item_stat.st_mtime),
                        'created': time.ctime(item_stat.st_ctime),
                        'permissions': oct(item_stat.st_mode)[-3:]
                    }
                except PermissionError:
                    response = {'error': f"Permission denied accessing: {path}"}
            
            elif operation == 'permissions':
                try:
                    item_stat = os.stat(path)
                    mode = item_stat.st_mode
                    response = {
                        'path': path,
                        'operation': operation,
                        'permissions': {
                            'octal': oct(mode)[-3:],
                            'readable': os.access(path, os.R_OK),
                            'writable': os.access(path, os.W_OK),
                            'executable': os.access(path, os.X_OK),
                            'owner_read': bool(mode & stat.S_IRUSR),
                            'owner_write': bool(mode & stat.S_IWUSR),
                            'owner_execute': bool(mode & stat.S_IXUSR),
                            'group_read': bool(mode & stat.S_IRGRP),
                            'group_write': bool(mode & stat.S_IWGRP),
                            'group_execute': bool(mode & stat.S_IXGRP),
                            'other_read': bool(mode & stat.S_IROTH),
                            'other_write': bool(mode & stat.S_IWOTH),
                            'other_execute': bool(mode & stat.S_IXOTH)
                        }
                    }
                except PermissionError:
                    response = {'error': f"Permission denied accessing: {path}"}
            
            else:
                response = {'error': f"Unknown operation: {operation}"}
            
            self.send_json_response(response)
            
        except Exception as e:
            print(f"File operations error: {e}")
            self.send_error(500, f"Error in file operations: {str(e)}")

    def handle_create_file(self):
        """Handle file creation"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
            
            file_path = data.get('path', '')
            file_content = data.get('content', '')
            use_sudo = data.get('use_sudo', False)
            sudo_username = data.get('sudo_username', '')
            sudo_password = data.get('sudo_password', '')
            
            if not file_path:
                self.send_error(400, "File path required")
                return
            
            # Get absolute path
            if not os.path.isabs(file_path):
                file_path = os.path.abspath(file_path)
            
            success = False
            error_msg = ""
            
            try:
                if use_sudo:
                    # Validate sudo credentials first
                    if not self.validate_sudo_credentials(sudo_username, sudo_password):
                        self.send_error(401, "Invalid sudo credentials")
                        return
                    
                    # Create file with sudo
                    import subprocess
                    # Create parent directories if needed
                    parent_dir = os.path.dirname(file_path)
                    if not os.path.exists(parent_dir):
                        cmd_mkdir = f'echo "{sudo_password}" | sudo -S mkdir -p "{parent_dir}"'
                        subprocess.run(cmd_mkdir, shell=True, check=True, capture_output=True)
                    
                    # Create file with content
                    cmd_create = f'echo "{sudo_password}" | sudo -S tee "{file_path}" > /dev/null'
                    process = subprocess.run(cmd_create, shell=True, input=file_content, 
                                           text=True, capture_output=True)
                    if process.returncode == 0:
                        success = True
                    else:
                        error_msg = process.stderr
                else:
                    # Create without sudo
                    parent_dir = os.path.dirname(file_path)
                    if not os.path.exists(parent_dir):
                        os.makedirs(parent_dir, exist_ok=True)
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(file_content)
                    success = True
                    
            except Exception as e:
                error_msg = str(e)
            
            response = {
                'success': success,
                'message': 'File created successfully' if success else f'Failed to create file: {error_msg}',
                'path': file_path
            }
            
            status_code = 200 if success else 500
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            print(f"Create file error: {e}")
            self.send_error(500, f"Error creating file: {str(e)}")

    def handle_create_folder(self):
        """Handle folder creation"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
            
            folder_path = data.get('path', '')
            use_sudo = data.get('use_sudo', False)
            sudo_username = data.get('sudo_username', '')
            sudo_password = data.get('sudo_password', '')
            
            if not folder_path:
                self.send_error(400, "Folder path required")
                return
            
            # Get absolute path
            if not os.path.isabs(folder_path):
                folder_path = os.path.abspath(folder_path)
            
            success = False
            error_msg = ""
            
            try:
                if use_sudo:
                    # Validate sudo credentials first
                    if not self.validate_sudo_credentials(sudo_username, sudo_password):
                        self.send_error(401, "Invalid sudo credentials")
                        return
                    
                    # Create folder with sudo
                    import subprocess
                    cmd = f'echo "{sudo_password}" | sudo -S mkdir -p "{folder_path}"'
                    process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    if process.returncode == 0:
                        success = True
                    else:
                        error_msg = process.stderr
                else:
                    # Create without sudo
                    os.makedirs(folder_path, exist_ok=True)
                    success = True
                    
            except Exception as e:
                error_msg = str(e)
            
            response = {
                'success': success,
                'message': 'Folder created successfully' if success else f'Failed to create folder: {error_msg}',
                'path': folder_path
            }
            
            status_code = 200 if success else 500
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            print(f"Create folder error: {e}")
            self.send_error(500, f"Error creating folder: {str(e)}")

    def handle_delete_item(self):
        """Handle file/folder deletion"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
            
            item_path = data.get('path', '')
            use_sudo = data.get('use_sudo', False)
            sudo_username = data.get('sudo_username', '')
            sudo_password = data.get('sudo_password', '')
            
            if not item_path:
                self.send_error(400, "Item path required")
                return
            
            # Get absolute path
            if not os.path.isabs(item_path):
                item_path = os.path.abspath(item_path)
            
            # Safety check - don't delete critical system paths
            critical_paths = ['/', '/bin', '/sbin', '/usr', '/etc', '/var', '/sys', '/proc', '/dev']
            if item_path in critical_paths or item_path.startswith('/bin/') or item_path.startswith('/sbin/'):
                self.send_error(403, "Cannot delete critical system paths")
                return
            
            if not os.path.exists(item_path):
                self.send_error(404, "Item does not exist")
                return
            
            success = False
            error_msg = ""
            
            try:
                if use_sudo:
                    # Validate sudo credentials first
                    if not self.validate_sudo_credentials(sudo_username, sudo_password):
                        self.send_error(401, "Invalid sudo credentials")
                        return
                    
                    # Delete with sudo
                    import subprocess
                    cmd = f'echo "{sudo_password}" | sudo -S rm -rf "{item_path}"'
                    process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    if process.returncode == 0:
                        success = True
                    else:
                        error_msg = process.stderr
                else:
                    # Delete without sudo
                    if os.path.isfile(item_path):
                        os.remove(item_path)
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                    success = True
                    
            except Exception as e:
                error_msg = str(e)
            
            response = {
                'success': success,
                'message': 'Item deleted successfully' if success else f'Failed to delete item: {error_msg}',
                'path': item_path
            }
            
            status_code = 200 if success else 500
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            print(f"Delete item error: {e}")
            self.send_error(500, f"Error deleting item: {str(e)}")

    def handle_sudo_auth(self):
        """Handle sudo authentication validation"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
            
            username = data.get('username', '')
            password = data.get('password', '')
            
            if not username or not password:
                self.send_error(400, "Username and password required")
                return
            
            is_valid = self.validate_sudo_credentials(username, password)
            
            response = {
                'valid': is_valid,
                'message': 'Sudo credentials valid' if is_valid else 'Invalid sudo credentials'
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            print(f"Sudo auth error: {e}")
            self.send_error(500, f"Error validating sudo credentials: {str(e)}")

    def validate_sudo_credentials(self, username, password):
        """Validate sudo credentials safely"""
        try:
            import subprocess
            # Test sudo access with a safe command
            cmd = f'echo "{password}" | sudo -S -u {username} echo "test" 2>/dev/null'
            process = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return process.returncode == 0
        except Exception as e:
            print(f"Sudo validation error: {e}")
            return False

    def handle_validate_existing_playlist(self):
        """Handle playlist validation - check if playlist file exists or list all playlists"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
            
            action = data.get('action', '')
            
            # Handle list all playlists action
            if action == 'list_all':
                self.handle_list_all_playlists()
                return
            
            playlist_name = data.get('playlist_name', '').strip()
            
            if not playlist_name:
                self.send_error(400, "Playlist name required")
                return
            
            # Sanitize the playlist name (same as frontend)
            sanitized_name = re.sub(r'[^a-zA-Z0-9\s\-_]', '', playlist_name).replace(' ', '_')
            
            if not sanitized_name:
                response_data = {
                    'exists': False,
                    'error': 'Invalid playlist name'
                }
                self.send_json_response(response_data)
                return
            
            # Check if playlist file exists
            playlist_filename = f"video_system_playlist_{sanitized_name}.txt"
            playlist_path = f"/home/gus/video-system/docs/video_system_saved_playlists/{playlist_filename}"
            
            file_exists = os.path.isfile(playlist_path)
            
            response_data = {
                'exists': file_exists,
                'playlist_name': playlist_name,
                'sanitized_name': sanitized_name,
                'filename': playlist_filename,
                'path': playlist_path if file_exists else None
            }
            
            # Log the validation check
            debug_logger.log_action(
                f"Playlist validation: {playlist_name}",
                f"File: {playlist_filename} | Exists: {file_exists} | Path: {playlist_path}",
                f"Validation result for playlist '{playlist_name}': {'EXISTS' if file_exists else 'NOT_EXISTS'}"
            )
            
            self.send_json_response(response_data)
            
        except Exception as e:
            logger.error(f"Error validating playlist: {e}")
            self.send_error(500, f"Error validating playlist: {str(e)}")

    def handle_list_all_playlists(self):
        """List all existing playlists"""
        try:
            playlist_dir = "/home/gus/video-system/docs/video_system_saved_playlists"
            
            if not os.path.exists(playlist_dir):
                response_data = {
                    'success': True,
                    'playlists': [],
                    'message': 'Playlist directory does not exist'
                }
                self.send_json_response(response_data)
                return
            
            playlists = []
            for filename in os.listdir(playlist_dir):
                if filename.startswith('video_system_playlist_') and filename.endswith('.txt'):
                    file_path = os.path.join(playlist_dir, filename)
                    if os.path.isfile(file_path):
                        playlists.append(filename)
            
            response_data = {
                'success': True,
                'playlists': sorted(playlists),
                'count': len(playlists)
            }
            
            # Log the playlist listing
            debug_logger.log_action(
                "List all playlists",
                f"Found {len(playlists)} playlists in {playlist_dir}",
                f"Playlist listing: {', '.join(playlists) if playlists else 'No playlists found'}"
            )
            
            self.send_json_response(response_data)
            
        except Exception as e:
            logger.error(f"Error listing playlists: {e}")
            self.send_error(500, f"Error listing playlists: {str(e)}")

    def handle_get_playlists_with_metadata(self):
        """Get all playlists with metadata for delete modal"""
        try:
            playlist_dir = "/home/gus/video-system/docs/video_system_saved_playlists"
            
            if not os.path.exists(playlist_dir):
                response_data = {
                    'success': True,
                    'playlists': [],
                    'message': 'No playlist directory found'
                }
                self.send_json_response(response_data)
                return
            
            playlists = []
            for filename in os.listdir(playlist_dir):
                if filename.startswith('video_system_playlist_') and filename.endswith('.txt'):
                    file_path = os.path.join(playlist_dir, filename)
                    if os.path.isfile(file_path):
                        # Extract playlist name from filename
                        playlist_name = filename.replace('video_system_playlist_', '').replace('.txt', '')
                        
                        # Get file stats
                        stat = os.stat(file_path)
                        created_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime))
                        file_size = stat.st_size
                        
                        # Count videos in playlist (count path entries after # Added or # Video lines)
                        video_count = 0
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                counting_videos = False
                                for line in f:
                                    line = line.strip()
                                    # Check if we're starting a video section
                                    if line.startswith('# Added') or line.startswith('# Video'):
                                        counting_videos = True
                                    # Check if we hit another comment that's not video-related
                                    elif line.startswith('#') and not line.startswith('# Added') and not line.startswith('# Video'):
                                        counting_videos = False
                                    # Count actual video paths (non-empty, non-comment lines)
                                    elif counting_videos and line and not line.startswith('#'):
                                        video_count += 1
                        except:
                            video_count = 0
                        
                        playlist_data = {
                            'name': playlist_name,
                            'filename': filename,
                            'video_count': video_count,
                            'created_date': created_date,
                            'file_size': file_size
                        }
                        playlists.append(playlist_data)
            
            # Sort playlists by name
            playlists.sort(key=lambda x: x['name'].lower())
            
            response_data = {
                'success': True,
                'playlists': playlists,
                'count': len(playlists),
                'message': f'Found {len(playlists)} playlists'
            }
            
            # Log the action
            debug_logger.log_action(
                "Get playlists with metadata",
                f"Found {len(playlists)} playlists in {playlist_dir}",
                f"Playlists: {', '.join([p['name'] for p in playlists]) if playlists else 'No playlists found'}"
            )
            
            self.send_json_response(response_data)
            
        except Exception as e:
            logger.error(f"Error getting playlists with metadata: {e}")
            self.send_error(500, f"Error getting playlists with metadata: {str(e)}")

    def handle_add_videos_to_playlist(self):
        """Handle adding videos to an existing playlist"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
            
            playlist_name = data.get('playlist_name', '').strip()
            videos = data.get('videos', [])
            addition_type = data.get('type', 'unknown')
            
            if not playlist_name:
                self.send_error(400, "Playlist name required")
                return
                
            if not videos or not isinstance(videos, list):
                self.send_error(400, "Videos list required")
                return
            
            # Sanitize the playlist name (same as frontend)
            sanitized_name = re.sub(r'[^a-zA-Z0-9\s\-_]', '', playlist_name).replace(' ', '_')
            
            # Construct playlist file path
            playlist_filename = f"video_system_playlist_{sanitized_name}.txt"
            playlist_path = f"/home/gus/video-system/docs/video_system_saved_playlists/{playlist_filename}"
            
            # Check if playlist exists
            if not os.path.isfile(playlist_path):
                self.send_error(404, f"Playlist '{playlist_name}' not found")
                return
            
            # Read existing playlist content
            try:
                with open(playlist_path, 'r', encoding='utf-8') as f:
                    existing_content = f.read()
            except Exception as e:
                self.send_error(500, f"Could not read playlist file: {str(e)}")
                return
            
            # Prepare video entries to add
            video_entries = []
            for video in videos:
                if isinstance(video, dict) and 'name' in video:
                    video_name = video['name']
                    video_path = video.get('path', '')
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Create entry with metadata based on addition type
                    if addition_type == 'individual':
                        entry = f"# Added: {timestamp} | Addition Type: Individual addition option\n"
                    elif addition_type == 'selected':
                        entry = f"# Added: {timestamp} | Addition Type: Selected option\n"
                    elif addition_type == 'all':
                        entry = f"# Added: {timestamp} | Addition Type: Added with all videos option\n"
                    else:
                        entry = f"# Added: {timestamp} | Addition Type: {addition_type}\n"
                    
                    entry += f"{video_name}\n"
                    if video_path:
                        entry += f"# Path: {video_path}\n"
                    entry += "\n"
                    
                    video_entries.append(entry)
            
            if not video_entries:
                self.send_error(400, "No valid videos to add")
                return
            
            # Append videos to playlist file
            try:
                with open(playlist_path, 'a', encoding='utf-8') as f:
                    f.write(f"# ========== Added {len(video_entries)} videos on {time.strftime('%Y-%m-%d %H:%M:%S')} ==========\n")
                    for entry in video_entries:
                        f.write(entry)
                    f.write(f"# ========== End of addition ==========\n\n")
                    
            except Exception as e:
                self.send_error(500, f"Could not write to playlist file: {str(e)}")
                return
            
            # Log the action
            debug_logger.log_action(
                f"Added videos to playlist: {playlist_name}",
                f"Videos: {len(videos)} | Type: {addition_type} | File: {playlist_filename}",
                f"Successfully added {len(videos)} videos to playlist '{playlist_name}'"
            )
            
            # Return success response
            response_data = {
                'success': True,
                'message': f'Successfully added {len(videos)} videos to playlist',
                'playlist_name': playlist_name,
                'videos_added': len(videos),
                'type': addition_type
            }
            
            self.send_json_response(response_data)
            
        except Exception as e:
            logger.error(f"Error adding videos to playlist: {e}")
            self.send_error(500, f"Error adding videos to playlist: {str(e)}")

    def handle_load_playlist_content(self):
        """Load playlist content for editing"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
            
            playlist_filename = data.get('filename', '').strip()
            
            if not playlist_filename:
                self.send_error(400, "Playlist filename required")
                return
            
            # Construct playlist path
            playlist_path = f"/home/gus/video-system/docs/video_system_saved_playlists/{playlist_filename}"
            
            if not os.path.isfile(playlist_path):
                response_data = {
                    'success': False,
                    'error': 'Playlist file not found',
                    'videos': []
                }
                self.send_json_response(response_data)
                return
            
            # Read and parse playlist file
            videos = []
            try:
                with open(playlist_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                for line in lines:
                    line = line.strip()
                    # Skip comments, empty lines, and separator lines
                    if not line or line.startswith('#') or line.startswith('='):
                        continue
                    
                    # Extract video information
                    # Lines should contain video paths/names
                    video_entry = {
                        'name': line,
                        'path': line
                    }
                    videos.append(video_entry)
                
            except Exception as e:
                logger.error(f"Error reading playlist file: {e}")
                response_data = {
                    'success': False,
                    'error': f'Error reading playlist file: {str(e)}',
                    'videos': []
                }
                self.send_json_response(response_data)
                return
            
            response_data = {
                'success': True,
                'videos': videos,
                'filename': playlist_filename,
                'video_count': len(videos)
            }
            
            # Log the load action
            debug_logger.log_action(
                f"Load playlist content: {playlist_filename}",
                f"Videos loaded: {len(videos)} | Path: {playlist_path}",
                f"Loaded {len(videos)} videos from playlist '{playlist_filename}'"
            )
            
            self.send_json_response(response_data)
            
        except Exception as e:
            logger.error(f"Error loading playlist content: {e}")
            self.send_error(500, f"Error loading playlist content: {str(e)}")

    def handle_save_playlist_order(self):
        """Save playlist with new video order and content"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
            
            playlist_filename = data.get('filename', '').strip()
            playlist_name = data.get('playlist_name', '').strip()
            videos = data.get('videos', [])
            
            if not playlist_filename:
                self.send_error(400, "Playlist filename required")
                return
            
            if not videos or not isinstance(videos, list):
                self.send_error(400, "Videos list required")
                return
            
            # Construct playlist path
            playlist_path = f"/home/gus/video-system/docs/video_system_saved_playlists/{playlist_filename}"
            
            try:
                # Create the new playlist content in the proper format
                playlist_content = []
                playlist_content.append(f"# ========== Playlist reordered on {time.strftime('%Y-%m-%d %H:%M:%S')} ==========")
                playlist_content.append(f"# Reordered playlist: {playlist_name}")
                playlist_content.append(f"# Total videos: {len(videos)}")
                playlist_content.append("")
                
                # Add each video in the new order using the existing format
                for i, video in enumerate(videos):
                    video_name = video.get('name', '')
                    video_path = video.get('path', video_name)
                    
                    if video_name:
                        # Use the same format as handle_add_videos_to_playlist
                        playlist_content.append(f"# Added: {time.strftime('%Y-%m-%d %H:%M:%S')} | Addition Type: Reordered video {i+1}")
                        playlist_content.append(video_path)
                        playlist_content.append("")
                
                playlist_content.append(f"# ========== End of reordering ==========")
                playlist_content.append("")
                
                # Write the updated playlist file
                with open(playlist_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(playlist_content))
                
                # Log the save action
                debug_logger.log_action(
                    f"Save playlist order: {playlist_name}",
                    f"Videos: {len(videos)} | File: {playlist_filename} | Path: {playlist_path}",
                    f"Successfully saved playlist '{playlist_name}' with {len(videos)} videos in new order"
                )
                
                response_data = {
                    'success': True,
                    'message': f'Successfully saved playlist with {len(videos)} videos',
                    'playlist_name': playlist_name,
                    'video_count': len(videos),
                    'filename': playlist_filename
                }
                
                self.send_json_response(response_data)
                
            except Exception as e:
                logger.error(f"Error writing playlist file: {e}")
                response_data = {
                    'success': False,
                    'error': f'Error writing playlist file: {str(e)}'
                }
                self.send_json_response(response_data)
                return
            
        except Exception as e:
            logger.error(f"Error saving playlist order: {e}")
            self.send_error(500, f"Error saving playlist order: {str(e)}")

    def handle_remove_all_videos_from_playlist(self):
        """Remove all videos from a playlist by clearing the playlist file"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error(400, "No data received")
                return
                
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            # Validate required parameters
            playlist_filename = data.get('playlist_filename')
            playlist_name = data.get('playlist_name')
            
            if not playlist_filename:
                self.send_error(400, "playlist_filename is required")
                return
                
            if not playlist_name:
                self.send_error(400, "playlist_name is required")  
                return
            
            # Construct playlist file path
            playlist_dir = '/home/gus/video-system/docs/video_system_saved_playlists'
            playlist_path = os.path.join(playlist_dir, playlist_filename)
            
            # Ensure playlist directory exists
            os.makedirs(playlist_dir, exist_ok=True)
            
            # Create empty playlist with just headers
            playlist_content = []
            playlist_content.append(f"# Video System Playlist: {playlist_name}")
            playlist_content.append(f"# Created/Updated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            playlist_content.append(f"# All videos removed: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            playlist_content.append("")  # Empty line for formatting
            
            # Write the empty playlist content to file
            with open(playlist_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(playlist_content))
            
            # Log the action
            debug_logger.log_action(f"Removed all videos from playlist: {playlist_name} (file: {playlist_filename})")
            
            # Send success response
            response_data = {
                "success": True,
                "message": f"Successfully removed all videos from playlist '{playlist_name}'",
                "playlist_name": playlist_name,
                "playlist_filename": playlist_filename,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            self.send_json_response(response_data)
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in remove all videos request: {e}")
            self.send_error(400, f"Invalid JSON: {str(e)}")
        except FileNotFoundError as e:
            logger.error(f"Playlist file not found: {e}")
            self.send_error(404, f"Playlist file not found: {str(e)}")
        except PermissionError as e:
            logger.error(f"Permission error removing all videos from playlist: {e}")
            self.send_error(500, f"Permission error: {str(e)}")
        except Exception as e:
            logger.error(f"Error removing all videos from playlist: {e}")
            self.send_error(500, f"Error removing all videos from playlist: {str(e)}")

    def handle_add_all_videos_to_playlist(self):
        """Add all available videos to a playlist"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error(400, "No data received")
                return
                
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            # Validate required parameters
            playlist_filename = data.get('playlist_filename')
            playlist_name = data.get('playlist_name')
            
            if not playlist_filename:
                self.send_error(400, "playlist_filename is required")
                return
                
            if not playlist_name:
                self.send_error(400, "playlist_name is required")  
                return
            
            # Get all videos from the video directory
            video_dir = '/home/gus/video-system/videos'
            if not os.path.exists(video_dir):
                self.send_error(404, f"Video directory not found: {video_dir}")
                return
            
            # Scan for all video files
            video_files = []
            supported_extensions = ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v']
            
            try:
                for root, dirs, files in os.walk(video_dir):
                    for file in files:
                        if any(file.lower().endswith(ext) for ext in supported_extensions):
                            full_path = os.path.join(root, file)
                            video_files.append(full_path)
            except Exception as e:
                logger.error(f"Error scanning video directory: {e}")
                self.send_error(500, f"Error scanning video directory: {str(e)}")
                return
            
            if not video_files:
                self.send_error(404, "No video files found in the video directory")
                return
            
            # Construct playlist file path
            playlist_dir = '/home/gus/video-system/docs/video_system_saved_playlists'
            playlist_path = os.path.join(playlist_dir, playlist_filename)
            
            # Ensure playlist directory exists
            os.makedirs(playlist_dir, exist_ok=True)
            
            # Check if playlist exists, if not create it
            if not os.path.exists(playlist_path):
                # Create new playlist with headers
                with open(playlist_path, 'w', encoding='utf-8') as f:
                    f.write(f"# Video System Playlist: {playlist_name}\n")
                    f.write(f"# Created: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Prepare video entries
            video_entries = []
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            
            for video_path in video_files:
                entry = f"# Added: {timestamp} | Addition Type: Added with all videos option\n"
                entry += f"{video_path}\n"
                entry += f"# Path: {video_path}\n"
                entry += "\n"
                video_entries.append(entry)
            
            # Append videos to playlist file
            with open(playlist_path, 'a', encoding='utf-8') as f:
                f.write(f"# ========== Added {len(video_entries)} videos on {timestamp} ==========\n")
                for entry in video_entries:
                    f.write(entry)
                f.write(f"# ========== End of addition ==========\n\n")
            
            # Log the action
            debug_logger.log_action(f"Added all videos to playlist: {playlist_name} (file: {playlist_filename}) - {len(video_files)} videos")
            
            # Send success response
            response_data = {
                "success": True,
                "message": f"Successfully added all {len(video_files)} videos to playlist '{playlist_name}'",
                "playlist_name": playlist_name,
                "playlist_filename": playlist_filename,
                "videos_added": len(video_files),
                "timestamp": timestamp
            }
            
            self.send_json_response(response_data)
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in add all videos request: {e}")
            self.send_error(400, f"Invalid JSON: {str(e)}")
        except FileNotFoundError as e:
            logger.error(f"File not found: {e}")
            self.send_error(404, f"File not found: {str(e)}")
        except PermissionError as e:
            logger.error(f"Permission error adding all videos to playlist: {e}")
            self.send_error(500, f"Permission error: {str(e)}")
        except Exception as e:
            logger.error(f"Error adding all videos to playlist: {e}")
            self.send_error(500, f"Error adding all videos to playlist: {str(e)}")

    def handle_add_single_video_to_playlist(self):
        """Add a single video to a playlist"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error(400, "No data received")
                return
                
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            # Validate required parameters
            playlist_filename = data.get('playlist_filename')
            playlist_name = data.get('playlist_name')
            video = data.get('video')
            
            if not playlist_filename:
                self.send_error(400, "playlist_filename is required")
                return
                
            if not playlist_name:
                self.send_error(400, "playlist_name is required")  
                return
                
            if not video or not isinstance(video, dict):
                self.send_error(400, "video object is required")
                return
                
            if not video.get('name') or not video.get('path'):
                self.send_error(400, "video must have name and path properties")
                return
            
            # Construct playlist file path
            playlist_dir = '/home/gus/video-system/docs/video_system_saved_playlists'
            playlist_path = os.path.join(playlist_dir, playlist_filename)
            
            # Ensure playlist directory exists
            os.makedirs(playlist_dir, exist_ok=True)
            
            # Check if playlist exists, if not create it
            if not os.path.exists(playlist_path):
                # Create new playlist with headers
                with open(playlist_path, 'w', encoding='utf-8') as f:
                    f.write(f"# Video System Playlist: {playlist_name}\n")
                    f.write(f"# Created: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Prepare video entry
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            video_name = video['name']
            video_path = video['path']
            
            entry = f"# ========== Added 1 video on {timestamp} ==========\n"
            entry += f"# Added: {timestamp} | Addition Type: Individual addition option\n"
            entry += f"{video_name}\n"
            entry += f"# Path: {video_path}\n"
            entry += "\n"
            entry += f"# ========== End of addition ==========\n\n"
            
            # Append video to playlist file
            with open(playlist_path, 'a', encoding='utf-8') as f:
                f.write(entry)
            
            # Log the action
            debug_logger.log_action(f"Added single video to playlist: {playlist_name} (file: {playlist_filename}) - {video_name}")
            
            # Send success response
            response_data = {
                "success": True,
                "message": f"Successfully added video to playlist '{playlist_name}'",
                "playlist_name": playlist_name,
                "playlist_filename": playlist_filename,
                "video_added": video_name,
                "timestamp": timestamp
            }
            
            self.send_json_response(response_data)
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in add single video request: {e}")
            self.send_error(400, f"Invalid JSON: {str(e)}")
        except FileNotFoundError as e:
            logger.error(f"File not found: {e}")
            self.send_error(404, f"File not found: {str(e)}")
        except PermissionError as e:
            logger.error(f"Permission error adding single video to playlist: {e}")
            self.send_error(500, f"Permission error: {str(e)}")
        except Exception as e:
            logger.error(f"Error adding single video to playlist: {e}")
            self.send_error(500, f"Error adding single video to playlist: {str(e)}")

    def handle_delete_single_playlist(self):
        """Delete a single playlist"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                error_response = {"success": False, "error": "bad_request", "message": "No data received"}
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(error_response).encode('utf-8'))
                return
                
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            # Get parameters - flexible handling
            playlist_filename = data.get('playlist_filename')
            playlist_name = data.get('playlist_name')
            
            # If we have playlist name but no filename, generate filename
            if playlist_name and not playlist_filename:
                # Sanitize the playlist name (same as frontend)
                sanitized_name = re.sub(r'[^a-zA-Z0-9\s\-_]', '', playlist_name).replace(' ', '_')
                playlist_filename = f"video_system_playlist_{sanitized_name}.txt"
            
            # If we have filename but no name, extract name from filename
            if playlist_filename and not playlist_name:
                playlist_name = playlist_filename.replace('video_system_playlist_', '').replace('.txt', '')
            
            if not playlist_filename or not playlist_name:
                error_response = {"success": False, "error": "bad_request", "message": "playlist_name or playlist_filename is required"}
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(error_response).encode('utf-8'))
                return
            
            # Construct playlist file path
            playlist_dir = '/home/gus/video-system/docs/video_system_saved_playlists'
            playlist_path = os.path.join(playlist_dir, playlist_filename)
            
            # If file doesn't exist with provided filename, try to find it by name
            if not os.path.exists(playlist_path):
                # Try to find the correct filename by searching directory
                if os.path.exists(playlist_dir):
                    for filename in os.listdir(playlist_dir):
                        if filename.startswith('video_system_playlist_') and filename.endswith('.txt'):
                            # Extract name from filename and compare
                            file_name = filename.replace('video_system_playlist_', '').replace('.txt', '')
                            if file_name == playlist_name:
                                playlist_filename = filename
                                playlist_path = os.path.join(playlist_dir, playlist_filename)
                                break
            
            # Check if playlist exists
            if not os.path.exists(playlist_path):
                error_response = {
                    "success": False,
                    "error": "not_found",
                    "message": f"Playlist not found: {playlist_name}",
                    "playlist_name": playlist_name,
                    "playlist_filename": playlist_filename
                }
                self.send_response(404)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(error_response).encode('utf-8'))
                return
            
            # Delete the playlist file
            os.remove(playlist_path)
            
            # Log the action
            debug_logger.log_action(f"Deleted single playlist: {playlist_name} (file: {playlist_filename})")
            
            # Send success response
            response_data = {
                "success": True,
                "message": f"Successfully deleted playlist '{playlist_name}'",
                "playlist_name": playlist_name,
                "playlist_filename": playlist_filename,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            self.send_json_response(response_data)
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in delete single playlist request: {e}")
            self.send_error(400, f"Invalid JSON: {str(e)}")
        except FileNotFoundError as e:
            logger.error(f"Playlist file not found: {e}")
            self.send_error(404, f"Playlist not found: {str(e)}")
        except PermissionError as e:
            logger.error(f"Permission error deleting playlist: {e}")
            self.send_error(500, f"Permission error: {str(e)}")
        except Exception as e:
            logger.error(f"Error deleting single playlist: {e}")
            self.send_error(500, f"Error deleting playlist: {str(e)}")

    def handle_delete_selected_playlists(self):
        """Delete multiple selected playlists"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error(400, "No data received")
                return
                
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            # Validate required parameters
            playlists = data.get('playlists')
            
            if not playlists or not isinstance(playlists, list):
                self.send_error(400, "playlists array is required")
                return
                
            if len(playlists) == 0:
                self.send_error(400, "At least one playlist must be specified")
                return
            
            # Construct playlist directory path
            playlist_dir = '/home/gus/video-system/docs/video_system_saved_playlists'
            
            deleted_playlists = []
            failed_playlists = []
            
            # Delete each playlist
            for playlist in playlists:
                try:
                    playlist_filename = playlist.get('playlist_filename')
                    playlist_name = playlist.get('playlist_name')
                    
                    # Handle flexible name/filename parameters
                    if playlist_name and not playlist_filename:
                        # Generate filename from name
                        sanitized_name = re.sub(r'[^a-zA-Z0-9\\s\\-_]', '', playlist_name).replace(' ', '_')
                        playlist_filename = f"video_system_playlist_{sanitized_name}.txt"
                    elif playlist_filename and not playlist_name:
                        # Extract name from filename
                        playlist_name = playlist_filename.replace('video_system_playlist_', '').replace('.txt', '')
                    
                    if not playlist_filename or not playlist_name:
                        failed_playlists.append({
                            'name': playlist_name or 'Unknown',
                            'error': 'Missing filename or name'
                        })
                        continue
                    
                    playlist_path = os.path.join(playlist_dir, playlist_filename)
                    
                    # If file doesn't exist with provided filename, try to find it by name
                    if not os.path.exists(playlist_path):
                        # Try to find the correct filename by searching directory
                        for filename in os.listdir(playlist_dir):
                            if filename.startswith('video_system_playlist_') and filename.endswith('.txt'):
                                # Extract name from filename and compare
                                file_name = filename.replace('video_system_playlist_', '').replace('.txt', '')
                                if file_name == playlist_name:
                                    playlist_filename = filename
                                    playlist_path = os.path.join(playlist_dir, playlist_filename)
                                    break
                    
                    if os.path.exists(playlist_path):
                        os.remove(playlist_path)
                        deleted_playlists.append(playlist_name)
                        debug_logger.log_action(f"Deleted playlist: {playlist_name} (file: {playlist_filename})")
                    else:
                        failed_playlists.append({
                            'name': playlist_name,
                            'error': 'File not found'
                        })
                        
                except Exception as e:
                    failed_playlists.append({
                        'name': playlist.get('playlist_name', 'Unknown'),
                        'error': str(e)
                    })
            
            # Send response
            response_data = {
                "success": True,
                "message": f"Processed {len(playlists)} playlist deletion requests",
                "deleted_count": len(deleted_playlists),
                "failed_count": len(failed_playlists),
                "deleted_playlists": deleted_playlists,
                "failed_playlists": failed_playlists,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            self.send_json_response(response_data)
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in delete selected playlists request: {e}")
            self.send_error(400, f"Invalid JSON: {str(e)}")
        except Exception as e:
            logger.error(f"Error deleting selected playlists: {e}")
            self.send_error(500, f"Error deleting selected playlists: {str(e)}")

    def handle_delete_all_playlists(self):
        """Delete all playlists"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error(400, "No data received")
                return
                
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            # Get confirmation flag
            confirm = data.get('confirm', False)
            
            if not confirm:
                self.send_error(400, "Confirmation required to delete all playlists")
                return
            
            # Construct playlist directory path
            playlist_dir = '/home/gus/video-system/docs/video_system_saved_playlists'
            
            if not os.path.exists(playlist_dir):
                # Send success response even if directory doesn't exist
                response_data = {
                    "success": True,
                    "message": "No playlists directory found - nothing to delete",
                    "deleted_count": 0,
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
                }
                self.send_json_response(response_data)
                return
            
            deleted_playlists = []
            failed_playlists = []
            
            # Get all playlist files
            try:
                playlist_files = [f for f in os.listdir(playlist_dir) if f.endswith('.txt')]
                
                # Delete each playlist file
                for filename in playlist_files:
                    try:
                        filepath = os.path.join(playlist_dir, filename)
                        os.remove(filepath)
                        deleted_playlists.append(filename)
                        debug_logger.log_action(f"Deleted playlist file: {filename}")
                    except Exception as e:
                        failed_playlists.append({
                            'filename': filename,
                            'error': str(e)
                        })
                
            except Exception as e:
                logger.error(f"Error listing playlist directory: {e}")
                self.send_error(500, f"Error accessing playlist directory: {str(e)}")
                return
            
            # Send response
            response_data = {
                "success": True,
                "message": f"Deleted all playlists - {len(deleted_playlists)} removed, {len(failed_playlists)} failed",
                "deleted_count": len(deleted_playlists),
                "failed_count": len(failed_playlists),
                "deleted_playlists": deleted_playlists,
                "failed_playlists": failed_playlists,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            self.send_json_response(response_data)
            
            # Log major action
            debug_logger.log_action(f"DELETED ALL PLAYLISTS - Count: {len(deleted_playlists)}")
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in delete all playlists request: {e}")
            self.send_error(400, f"Invalid JSON: {str(e)}")
        except Exception as e:
            logger.error(f"Error deleting all playlists: {e}")
            self.send_error(500, f"Error deleting all playlists: {str(e)}")

    def handle_open_playlist_content(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            playlist_name = data.get('playlist_name')
            playlist_filename = data.get('playlist_filename')
            
            if not playlist_name:
                self.send_error(400, "Playlist name is required")
                return
                
            # Use filename if provided, otherwise construct from name
            if playlist_filename:
                filename = playlist_filename
            else:
                filename = f"video_system_playlist_{playlist_name}.txt"
            
            playlist_dir = '/home/gus/video-system/docs/video_system_saved_playlists'
            playlist_file = os.path.join(playlist_dir, filename)
            
            if not os.path.exists(playlist_file):
                self.send_error(404, "Playlist not found")
                return
            
            # Parse playlist file - same format as edit playlist section
            video_paths = []
            with open(playlist_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
                for line in lines:
                    line = line.strip()
                    # Skip comments, empty lines, and separator lines
                    if not line or line.startswith('#') or line.startswith('='):
                        continue
                    # Add the video path
                    video_paths.append(line)
            
            # Get video metadata for each path
            videos_data = []
            for video_path in video_paths:
                try:
                    # If path is not absolute, assume it's in the videos directory
                    if not os.path.isabs(video_path):
                        full_video_path = os.path.join('/home/gus/video-system/videos', video_path)
                    else:
                        full_video_path = video_path
                    
                    if os.path.exists(full_video_path):
                        stat_info = os.stat(full_video_path)
                        file_size = stat_info.st_size
                        
                        # Convert size to readable format
                        size_str = ""
                        if file_size >= 1024 * 1024 * 1024:
                            size_str = f"{file_size / (1024 * 1024 * 1024):.1f} GB"
                        else:
                            size_str = f"{file_size / (1024 * 1024):.1f} MB"
                        
                        videos_data.append({
                            'name': os.path.basename(full_video_path),
                            'path': full_video_path,
                            'size': size_str,
                            'exists': True
                        })
                    else:
                        # Still try with original path if full path doesn't exist
                        if os.path.exists(video_path):
                            stat_info = os.stat(video_path)
                            file_size = stat_info.st_size
                            
                            # Convert size to readable format
                            size_str = ""
                            if file_size >= 1024 * 1024 * 1024:
                                size_str = f"{file_size / (1024 * 1024 * 1024):.1f} GB"
                            else:
                                size_str = f"{file_size / (1024 * 1024):.1f} MB"
                            
                            videos_data.append({
                                'name': os.path.basename(video_path),
                                'path': video_path,
                                'size': size_str,
                                'exists': True
                            })
                        else:
                            videos_data.append({
                                'name': os.path.basename(video_path),
                                'path': video_path,
                                'size': 'N/A',
                                'exists': False
                            })
                except Exception as e:
                    logger.error(f"Error processing video {video_path}: {e}")
                    videos_data.append({
                        'name': os.path.basename(video_path),
                        'path': video_path,
                        'size': 'Error',
                        'exists': False
                    })
            
            response_data = {
                'playlist_name': playlist_name,
                'videos': videos_data,
                'total_count': len(videos_data)
            }
            
            response = json.dumps(response_data, indent=2)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response.encode())
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in open playlist content request: {e}")
            self.send_error(400, f"Invalid JSON: {str(e)}")
        except Exception as e:
            logger.error(f"Error opening playlist content: {e}")
            self.send_error(500, f"Error opening playlist content: {str(e)}")

    def handle_refresh_playlist_modal_metadata(self):
        """Handle refresh playlist metadata requests"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(post_data)
            
            playlist_name = data.get('playlist_name')
            if not playlist_name:
                self.send_error(400, "Missing playlist_name")
                return
            
            logger.info(f"Refreshing metadata for playlist: {playlist_name}")
            
            # Construct playlist file path
            playlist_file = f"/home/gus/video-system/docs/video_system_saved_playlists/video_system_playlist_{playlist_name}.txt"
            
            if not os.path.exists(playlist_file):
                response_data = {
                    'success': False,
                    'message': f'Playlist file not found: {playlist_name}'
                }
                response = json.dumps(response_data)
                self.send_response(404)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response.encode())
                return
            
            # Read the playlist file and update metadata for existing videos
            updated_lines = []
            video_count = 0
            errors = []
            
            try:
                with open(playlist_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                for line in lines:
                    line = line.rstrip('\n\r')
                    
                    # Keep comment lines as-is
                    if line.startswith('#') or not line.strip():
                        updated_lines.append(line)
                        continue
                    
                    # This is a video path line
                    video_path = line.strip()
                    
                    try:
                        # Check if file exists and get updated metadata
                        if os.path.exists(video_path):
                            stat_info = os.stat(video_path)
                            file_size = stat_info.st_size
                            
                            # Format file size
                            if file_size >= 1024 * 1024 * 1024:
                                size_str = f"{file_size / (1024 * 1024 * 1024):.1f} GB"
                            elif file_size >= 1024 * 1024:
                                size_str = f"{file_size / (1024 * 1024):.1f} MB"
                            else:
                                size_str = f"{file_size / 1024:.1f} KB"
                            
                            # Add metadata comment after the video path
                            updated_lines.append(video_path)
                            updated_lines.append(f"# Size: {size_str} | Modified: {time.ctime(stat_info.st_mtime)}")
                            video_count += 1
                            
                        else:
                            # File doesn't exist, mark as missing
                            updated_lines.append(video_path)
                            updated_lines.append("# Status: FILE NOT FOUND")
                            errors.append(f"File not found: {video_path}")
                            
                    except Exception as e:
                        updated_lines.append(video_path)
                        updated_lines.append(f"# Error: {str(e)}")
                        errors.append(f"Error processing {video_path}: {str(e)}")
                
                # Write the updated playlist file
                with open(playlist_file, 'w', encoding='utf-8') as f:
                    for line in updated_lines:
                        f.write(line + '\n')
                
                logger.info(f"Successfully refreshed metadata for {video_count} videos in playlist '{playlist_name}'")
                
                response_data = {
                    'success': True,
                    'message': f'Successfully refreshed metadata for {video_count} videos',
                    'video_count': video_count,
                    'errors': errors
                }
                
            except Exception as e:
                logger.error(f"Error processing playlist file {playlist_file}: {e}")
                response_data = {
                    'success': False,
                    'message': f'Error processing playlist file: {str(e)}'
                }
            
            # Send response
            response = json.dumps(response_data)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response.encode())
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in refresh playlist metadata request: {e}")
            self.send_error(400, f"Invalid JSON: {str(e)}")
        except Exception as e:
            logger.error(f"Error refreshing playlist metadata: {e}")
            self.send_error(500, f"Error refreshing playlist metadata: {str(e)}")

    def handle_check_youtube_dl(self):
        """Check if youtube-dl is installed on the server"""
        try:
            # Check if yt-dlp is installed by running --version
            result = subprocess.run(['/home/gus/.local/bin/yt-dlp', '--version'], 
                                    capture_output=True, text=True, timeout=10)
            
            installed = result.returncode == 0
            version = result.stdout.strip() if installed else None
            
            response_data = {
                'installed': installed,
                'version': version,
                'success': True
            }
            
            if not installed:
                response_data['message'] = 'youtube-dl is not installed or not in PATH'
            
            response = json.dumps(response_data)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response.encode())
            
        except subprocess.TimeoutExpired:
            self.send_json_response({
                'installed': False,
                'success': False,
                'error': 'youtube-dl command timeout'
            }, 500)
        except FileNotFoundError:
            self.send_json_response({
                'installed': False,
                'success': False,
                'error': 'youtube-dl not found in PATH'
            }, 200)
        except Exception as e:
            logger.error(f"Error checking youtube-dl: {e}")
            self.send_json_response({
                'installed': False,
                'success': False,
                'error': str(e)
            }, 500)

    def handle_welcome_video(self):
        """Serve the welcome video file for authenticated users"""
        try:
            logger.info("🎬 Welcome video request received")
            logger.info(f"Client: {self.client_address[0]}")
            logger.info(f"Headers: {dict(self.headers)}")
            
            video_path = "/home/gus/video-system/videos/video_system_futuristic_welcome_animation_enhanced_presentation.webm"
            logger.info(f"Video path: {video_path}")
            
            # Check if video file exists
            if not os.path.exists(video_path):
                logger.error(f"❌ Video file not found: {video_path}")
                self.send_error(404, "Welcome video not found")
                return
            
            logger.info("✅ Video file exists")
                
            # Get file info
            file_size = os.path.getsize(video_path)
            logger.info(f"📊 Video file size: {file_size} bytes")
            
            # Handle range requests for video streaming
            range_header = self.headers.get('Range')
            logger.info(f"📋 Range header: {range_header}")
            
            if range_header:
                # Parse range header
                range_match = re.match(r'bytes=(\d+)-(\d*)', range_header)
                if range_match:
                    start = int(range_match.group(1))
                    end = int(range_match.group(2)) if range_match.group(2) else file_size - 1
                    logger.info(f"📦 Range request: bytes {start}-{end}")
                    
                    # Send partial content response
                    logger.info("📤 Sending 206 Partial Content")
                    self.send_response(206)
                    self.send_header('Content-Type', 'video/webm')
                    self.send_header('Content-Range', f'bytes {start}-{end}/{file_size}')
                    self.send_header('Content-Length', str(end - start + 1))
                    self.send_header('Accept-Ranges', 'bytes')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    
                    # Send the requested chunk
                    with open(video_path, 'rb') as f:
                        f.seek(start)
                        chunk_size = 8192
                        remaining = end - start + 1
                        while remaining > 0:
                            to_read = min(chunk_size, remaining)
                            data = f.read(to_read)
                            if not data:
                                break
                            self.wfile.write(data)
                            remaining -= len(data)
                else:
                    self.send_error(416, "Range Not Satisfiable")
            else:
                # Send full file
                logger.info("📤 Sending 200 OK - Full file")
                self.send_response(200)
                self.send_header('Content-Type', 'video/webm')
                self.send_header('Content-Length', str(file_size))
                self.send_header('Accept-Ranges', 'bytes')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Cache-Control', 'public, max-age=3600')
                self.end_headers()
                
                # Send the file in chunks
                with open(video_path, 'rb') as f:
                    chunk_size = 8192
                    while True:
                        data = f.read(chunk_size)
                        if not data:
                            break
                        self.wfile.write(data)
                        
        except Exception as e:
            logger.error(f"❌ Error serving welcome video: {e}")
            logger.error(f"Exception type: {type(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            self.send_error(500, f"Error serving video: {str(e)}")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

def main():
    # Print startup header with timestamp
    import datetime
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] --------------------------------------------------------------------")
    print(f"[{timestamp}] === Server Starting ===")
    print(f"[{timestamp}] 🔐 Starting Authenticated API Server on port {PORT}")
    
    try:
        with ThreadedTCPServer(("0.0.0.0", PORT), AuthenticatedAPIHandler) as httpd:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] 🔒 Secure API Server running at http://0.0.0.0:{PORT}")
            # Also log to debug log
            debug_logger.log_action("SERVER STARTED", f"Port: {PORT} |  Timestamp: {timestamp}")
            debug_logger.log_action("Authentication server initialized", f"Listening on: http://0.0.0.0:{PORT}")

            print(f"[{timestamp}] 🎬 Login required for access")
            print(f"[{timestamp}] ⏹️  Press Ctrl+C to stop the server")
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print("\n🛑 Authenticated API Server stopped")
    except Exception as e:
        print(f"❌ Server error: {e}")

if __name__ == "__main__":
    main()
# Override the default exception handler for the server
import socketserver

def custom_handle_error(self, request, client_address):
    """Custom error handler that suppresses broken pipe errors"""
    import sys, traceback
    exc_type, exc_value, exc_traceback = sys.exc_info()
    
    if isinstance(exc_value, (BrokenPipeError, ConnectionResetError)):
        print(f"Client {client_address[0]} disconnected unexpectedly")
    else:
        print(f"Exception in request from {client_address[0]}:{client_address[1]}")
        print(''.join(traceback.format_exception(exc_type, exc_value, exc_traceback)))

# Monkey patch the error handler
socketserver.BaseRequestHandler.handle_error = custom_handle_error
