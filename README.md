# Program developed by Gustavo Wydler Azuaga - 2025-09-25

# 🎬 Video Library & File Management System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Status: Active](https://img.shields.io/badge/status-active-success.svg)]()

A comprehensive, secure video streaming and file management system with advanced playlist management, authentication, terminal access, and API testing capabilities.

![Video System Dashboard](https://img.shields.io/badge/interface-web--based-brightgreen)

## 🚀 Quick Start

### Directory Structure
```
/home/$USER/video-system/
├── videos/         # Video files (MP4, WebM, AVI, MOV, MKV, FLV)
├── docs/          # Web interface files
├── scripts/       # Python API server
└── logs/          # System and debug logs
```

### Installation & Launch
```bash
# Start the API server
cd /home/$USER/video-system/scripts && python3 auth_api_server.py &

# Access the web interface
# Navigate to: http://your-server:9090
```

## 🔐 Authentication

### Access Linux system and edit file: 

```~/.crds```

**Credentials File:** `~/.crds`  
**Format:** `username:password`

```bash
# Change credentials
nano ~/.crds
# Format: newuser:newpassword
# No restart required
```

**Security Features:**
- Session token management
- Encrypted password storage
- Protected API endpoints
- Secure authentication flow

## 🌟 Core Features

### 🎬 Advanced Video Player
- **HTML5 Video Player** with full controls (play/pause, restart, mute, fullscreen)
- **Comprehensive Speed Control** (0.05x to 20x speeds)
  - Speed categories: Ultra Slow, Super Slow, Very Slow, Slow, Normal, Fast
  - Custom speed input with precise control (0.01x to 20x range)
- **Loop Toggle** functionality
- **Real-time Play Status** with animated indicators
- **Welcome Video Modal** with authentication

### 🎵 Playlist Management
- **Create, Edit, Delete** custom playlists
- **Add Videos to Playlists** (individual or bulk selection)
- **Play All Functionality** (first-to-last, last-to-first)
- **Sequential Playlist Playback** with Next/Previous navigation
- **Playlist Metadata Refresh** and management
- **Drag-and-Drop** playlist reordering
- **Save/Undo** playlist operations

### 🔍 Video Search & Organization
- **Advanced Video Search Modal** with real-time filtering
- **Text-based Search** with Enter key support
- **Drag-and-Drop** search result reordering
- **Video Selection System** (individual/bulk operations)
- **Select All/Deselect All** functionality
- **Video Metadata Display** and thumbnail generation
- **Hover-to-Preview** video thumbnails

### 📁 File Explorer & Management
- **Data Navigator** with breadcrumb navigation
- **Quick Access Shortcuts** (Home, Random Files, Videos)
- **Multi-file Selection** with checkboxes
- **File Operations:** create, delete, rename files and folders
- **Color-coded File Types** (directories, videos, images)
- **Directory Tree Browsing**

### ⬇️ Download Operations
- **Individual File Downloads**
- **Bulk Download** selected files
- **Download All Files** functionality
- **ZIP Archive Creation** and download
- **Download Progress Tracking** with status indicators

### ⬆️ Upload System
- **Video Uploads** with format validation (MP4, WebM, AVI, MOV, MKV, FLV)
- **General File Uploads** (all file types) to any directory
- **Dual Drag-and-Drop Interfaces**
- **Upload Progress Tracking** with detailed modals
- **File Preview** before upload
- **Upload Confirmation** and cancellation options

### 💾 Storage Management
- **Real-time Storage Status** displays across all sections
- **Visual Storage Usage Bars** with color indicators
- **Disk Quota Reserve Configuration** and management
- **Upload Limit Calculations** with automatic updates
- **Available Space Monitoring** and alerts
- **Storage Refresh** functionality

### 💻 Terminal Access
- **Shell-in-a-Box Integration** (opens on port 4200)
- **Full Linux Terminal Access** in browser
- **Terminal Opens** in dedicated new tab
- **Secure Authenticated** terminal sessions

### 📡 API Testing Module
- **API Console Interface** (opens on port 9090)
- **Interactive API Call Testing**
- **Pre-configured Curl Commands** library
- **Authentication Testing** and endpoint validation
- **Copy-paste Ready** curl commands for external use

### 🖥️ System Specifications
- **Linux System Specifications** modal
- **Hardware Information Display**
- **Terminal-style System Monitoring**
- **Real-time System Status** information

### 🔍 Logging & Debugging
- **Debug Logs Viewer Modal** with download capability
- **Scroll Navigation** (Top/Bottom/Middle)
- **Real-time Log Monitoring** and updates
- **Comprehensive Action Logging** and request tracking
- **Error Handling** with detailed status messages

## 🎵 Playlist System Guide

### Creating Playlists
1. Click **"🔍 Manage and play videos"** to open video search modal
2. Search and select videos using checkboxes
3. Click **"Create New Playlist"** button
4. Enter playlist name and save

### Managing Playlists
- **Edit Playlist:** Modify existing playlist contents
- **Delete Playlist:** Remove playlists permanently
- **Show All Playlists:** View all created playlists
- **Add to Playlist:** Add selected videos to existing playlists

### Playlist Playback
- **Play All (First to Last):** Sequential playback from beginning
- **Play All (Last to First):** Reverse sequential playback
- **Next/Previous:** Manual navigation between playlist videos
- **Auto-progression:** Automatic advancement to next video

### Playlist Operations
- **Drag & Drop:** Reorder videos within playlists
- **Bulk Add:** Add all search results to playlist
- **Selective Add:** Add only checked videos to playlist
- **Metadata Refresh:** Update playlist video information
- **Save Changes:** Persist playlist modifications
- **Undo:** Revert last playlist operation

## 🚀 System Management

### Start Services
```bash
cd /home/$USER/video-system/scripts && python3 auth_api_server.py &
```

### Stop Services
```bash
pkill -f auth_api_server.py
```

### Check Status
```bash
ps aux | grep auth_api_server
```

### View Logs
```bash
tail -f /home/$USER/video-system/logs/debug.log
# Or use the UI debug log viewer
```

## 🔧 Configuration

### Disk Quota Management
- Access via **"💽 Disk quota reserve limit"** buttons
- Set reserved disk space to prevent system crashes
- Automatic upload limit calculations
- Persistent configuration across reboots
- Located: `/home/$USER/video-system/docs/reserved_value.txt`

### File Permissions
```bash
sudo chown -R $USER:$USER /home/$USER/video-system/
chmod +x /home/$USER/video-system/scripts/*.py
```

### Firewall Configuration
```bash
sudo ufw allow 9090/tcp
sudo ufw allow 4200/tcp
```

## 🎯 Feature Quick Access Guide

### 🎬 Video Playback & Playlists
- **SEARCH VIDEOS:** Click "🔍 Manage and play videos" to open advanced search modal
- **SPEED CONTROL:** Use the detailed speed grid (0.05x to 20x) in video player
- **PLAYLISTS:** Create/manage playlists with "Create New Playlist" button
- **PLAY ALL:** Use "Play All" buttons for sequential playlist playback
- **LOOP/CONTROLS:** Toggle loop, mute, fullscreen directly in video player

### 📁 File & System Management
- **DATA NAVIGATOR:** Click "📊 Data Navigator" for file system browsing
- **QUICK ACCESS:** Use Home/Random Files/Videos shortcuts in file browser
- **DOWNLOADS:** Select files and use bulk download operations
- **TERMINAL:** Click "💻 Terminal" for Shell-in-a-Box web terminal access
- **SYSTEM SPECS:** Click system info buttons for hardware details

### ⬆️⬇️ Upload & Download
- **VIDEO UPLOAD:** Click "🎬 Upload Videos" (MP4, WebM, AVI, MOV, MKV, FLV only)
- **GENERAL UPLOAD:** Click "📁 General Upload" (all file types accepted)
- **DRAG & DROP:** Use drag-and-drop on both upload interfaces
- **BULK DOWNLOADS:** Select multiple files and download as ZIP archive

### 🔧 Advanced Tools
- **API TESTING:** Click "📡 API Calls" for API console (opens port 9090)
- **DEBUG LOGS:** Click "🔍 View Debug Logs" for system log monitoring
- **STORAGE QUOTAS:** Click "💽 Disk quota reserve limit" for storage management
- **REFRESH DATA:** Use refresh buttons to update video metadata and storage info

### 🎮 User Interface Navigation
- **TOGGLE MODES:** Use the 7 main toggle buttons (Video Catalog, Data Navigator, etc.)
- **SEARCH & FILTER:** Real-time search with Enter key in video search modal
- **BULK OPERATIONS:** Use Select All/Deselect All for multi-file operations
- **DRAG & DROP:** Reorder search results and playlist items by dragging

## 🐛 Troubleshooting

### Common Issues

#### Authentication Failed
- Check `~/.crds` file format
- Verify credentials
- Clear browser cache

#### Videos Not Loading
- Check file permissions
- Verify video formats (MP4, WebM, AVI, MOV, MKV, FLV)
- Check `/home/$USER/video-system/videos/` directory

#### Server Connection Issues
- Verify services are running
- Check firewall settings: `sudo ufw status`
- Check logs: `tail -f /home/$USER/video-system/logs/debug.log`

#### Upload Failures
- Check disk space
- Verify upload directory permissions
- Check storage quota settings

#### Terminal Not Working
- Verify authentication
- Check server logs
- Ensure websocket connection

#### API Calls Failing
- Check authentication headers
- Verify endpoint URLs
- Use API testing module for debugging

#### Playlist Issues
- Refresh playlist metadata if videos not loading
- Check video file permissions and paths
- Use "Show All Playlists" to verify playlist exists
- Clear browser cache if playlist operations fail

#### Welcome Video Not Playing
- Ensure authentication token is valid
- Check video file exists in `~/video-system/videos/`
- Verify API server is running on port 9090
- Check browser console for authentication errors

#### Search/Filter Not Working
- Refresh video metadata using refresh button
- Clear search terms and try again
- Check if videos exist in `~/video-system/videos/`
- Verify file permissions on video directory

#### Speed Control Issues
- Use custom speed input for precise control
- Reset to 1.0x (normal) speed if experiencing issues
- Check browser compatibility for HTML5 video

### Debug Log Access
- Use **"🔍 View Debug Logs"** button in UI
- Or check: `/home/$USER/video-system/logs/debug.log`
- Real-time monitoring available in web interface
- Download logs using download button in debug modal

## 🌐 Network Configuration

### Default Ports
- **Main API Server:** Port 9090
- **Terminal Access:** Port 4200

### Access URLs
- **Main Interface:** `http://your-server:9090`
- **API Endpoint:** `http://your-server:9090/api`
- **Terminal:** `http://your-server:4200`

## 📞 Support

All features are accessible through the main dashboard interface.
- Check debug logs for detailed error information
- Use terminal access for direct system troubleshooting
- System Path: `/home/$USER/video-system/`

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔄 Remote System Transfer

The system includes remote transfer capabilities that allow you to copy the entire video system to another server via SCP with automatic configuration updates.

### Transfer Process
1. **Transfer video-system-default** to remote system
2. **Create working copy** as video-system 
3. **Replace IP addresses** (gcppftest01 → actual remote IP)
4. **Update file paths** for remote user's home directory
5. **Configure authentication** with proper Bearer token loading
6. **Restart API server** with updated configuration

The welcome video modal will load correctly with sound after successful authentication on remote systems.

---

**🎬 Enjoy your professional video management system!** 🚀
