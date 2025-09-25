import os
import datetime

class DebugLogger:
    def __init__(self):
        self.log_dir = "/home/gus/video-system/logs"
        self.debug_log_file = f"{self.log_dir}/debug.log"
        os.makedirs(self.log_dir, exist_ok=True)
        
    def log_action(self, action, details=None, curl_command=None):
        """Log user action with timestamp and single separator at end only"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        separator = "-" * 46
        
        try:
            with open(self.debug_log_file, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {action}\n")
                if details:
                    f.write(f"[{timestamp}] {details}\n")
                if curl_command:
                    f.write(f"[{timestamp}] {curl_command}\n")
                f.write(f"[{timestamp}] {separator}\n")
                f.flush()
        except Exception as e:
            print(f"Debug logging error: {e}")

# Global debug logger instance
debug_logger = DebugLogger()
