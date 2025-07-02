"""
Configuration settings for the Discord Data Collection Bot
"""

import os
from datetime import time

class BotConfig:
    """Bot configuration constants"""
    
    # Bot settings
    COMMAND_PREFIX = os.getenv('BOT_PREFIX', '!')
    
    # Data collection settings
    AUTO_COLLECT_DATA = os.getenv('AUTO_COLLECT_DATA', 'true').lower() == 'true'
    COLLECTION_INTERVAL_HOURS = int(os.getenv('COLLECTION_INTERVAL_HOURS', '24'))
    LOG_MESSAGE_ACTIVITY = os.getenv('LOG_MESSAGE_ACTIVITY', 'false').lower() == 'true'
    
    # Rate limiting settings
    MESSAGE_SCRAPE_DELAY = float(os.getenv('MESSAGE_SCRAPE_DELAY', '0.1'))  # Seconds between message requests
    API_RATE_LIMIT_DELAY = float(os.getenv('API_RATE_LIMIT_DELAY', '1.0'))  # Seconds between API calls
    
    # Data export settings
    DEFAULT_MESSAGE_LIMIT = int(os.getenv('DEFAULT_MESSAGE_LIMIT', '1000'))
    MAX_MESSAGE_LIMIT = int(os.getenv('MAX_MESSAGE_LIMIT', '10000'))
    
    # File paths
    DATA_DIR = os.getenv('DATA_DIR', 'data')
    EXPORTS_DIR = os.path.join(DATA_DIR, 'exports')
    LOGS_DIR = os.path.join(DATA_DIR, 'logs')
    
    # Privacy settings
    COLLECT_USER_IDS = os.getenv('COLLECT_USER_IDS', 'true').lower() == 'true'
    COLLECT_MESSAGE_CONTENT = os.getenv('COLLECT_MESSAGE_CONTENT', 'false').lower() == 'true'
    ANONYMIZE_USERS = os.getenv('ANONYMIZE_USERS', 'false').lower() == 'true'
    
    # Required permissions for the bot
    REQUIRED_PERMISSIONS = [
        'read_messages',
        'read_message_history',
        'send_messages',
        'embed_links',
        'attach_files'
    ]
    
    @classmethod
    def ensure_directories(cls):
        """Ensure required directories exist"""
        import os
        os.makedirs(cls.DATA_DIR, exist_ok=True)
        os.makedirs(cls.EXPORTS_DIR, exist_ok=True)
        os.makedirs(cls.LOGS_DIR, exist_ok=True)

# Ensure directories exist on import
BotConfig.ensure_directories()
