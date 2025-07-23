#!/usr/bin/env python3
"""
Update mailer configuration with Railway URL
"""

import json
import sys
import os

def update_railway_config(railway_url):
    """Update mailer config with Railway URL"""
    config_path = "/Users/home/Desktop/redteam/config/mailer_config.json"
    
    if not os.path.exists(config_path):
        print(f"❌ Config file not found: {config_path}")
        return False
    
    try:
        # Load current config
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        # Update tracking configuration
        config["email_settings"]["tracking"] = {
            "enable_railway_tracking": True,
            "railway_base_url": railway_url,
            "enable_email_tracking": False,
            "pixel_enabled": False,
            "click_tracking_enabled": False
        }
        
        # Save updated config
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        
        print(f"✅ Updated mailer config with Railway URL: {railway_url}")
        return True
        
    except Exception as e:
        print(f"❌ Error updating config: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 update_railway_config.py <railway_url>")
        print("Example: python3 update_railway_config.py https://my-project.up.railway.app")
        sys.exit(1)
    
    railway_url = sys.argv[1].rstrip('/')
    
    if not railway_url.startswith('https://'):
        print("❌ Railway URL must start with https://")
        sys.exit(1)
    
    success = update_railway_config(railway_url)
    sys.exit(0 if success else 1)
