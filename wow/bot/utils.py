"""
Utility functions for the Discord Data Collection Bot
"""

import os
import re
import discord
from datetime import datetime
from typing import Union

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to be safe for file system
    
    Args:
        filename: The filename to sanitize
        
    Returns:
        Sanitized filename
    """
    # Remove or replace invalid characters
    invalid_chars = r'[<>:"/\\|?*]'
    sanitized = re.sub(invalid_chars, '_', filename)
    
    # Remove multiple consecutive underscores
    sanitized = re.sub(r'_{2,}', '_', sanitized)
    
    # Trim and limit length
    sanitized = sanitized.strip('._')[:200]
    
    return sanitized

def format_file_size(filepath: str) -> int:
    """
    Get file size in bytes
    
    Args:
        filepath: Path to the file
        
    Returns:
        File size in bytes
    """
    try:
        return os.path.getsize(filepath)
    except OSError:
        return 0

def format_bytes(bytes_count: int) -> str:
    """
    Format bytes into human-readable format
    
    Args:
        bytes_count: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} PB"

def create_embed(title: str, description: str, color: discord.Color) -> discord.Embed:
    """
    Create a standardized Discord embed
    
    Args:
        title: Embed title
        description: Embed description
        color: Embed color
        
    Returns:
        Discord Embed object
    """
    embed = discord.Embed(
        title=title,
        description=description,
        color=color,
        timestamp=datetime.now()
    )
    
    return embed

def check_permissions(channel: discord.TextChannel, bot_member: discord.Member) -> dict:
    """
    Check bot permissions in a channel
    
    Args:
        channel: Discord text channel
        bot_member: Bot's member object
        
    Returns:
        Dictionary of permission checks
    """
    permissions = channel.permissions_for(bot_member)
    
    return {
        'read_messages': permissions.read_messages,
        'send_messages': permissions.send_messages,
        'read_message_history': permissions.read_message_history,
        'embed_links': permissions.embed_links,
        'attach_files': permissions.attach_files,
        'manage_messages': permissions.manage_messages
    }

def format_duration(seconds: int) -> str:
    """
    Format seconds into human-readable duration
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string
    """
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds}s"
    else:
        hours = seconds // 3600
        remaining_minutes = (seconds % 3600) // 60
        return f"{hours}h {remaining_minutes}m"

def truncate_text(text: str, max_length: int = 100) -> str:
    """
    Truncate text to specified length with ellipsis
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        
    Returns:
        Truncated text
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."

def is_valid_discord_id(discord_id: Union[str, int]) -> bool:
    """
    Check if a Discord ID is valid (snowflake format)
    
    Args:
        discord_id: Discord ID to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        discord_id = int(discord_id)
        # Discord snowflakes are typically 17-19 digits long
        return 100000000000000000 <= discord_id <= 999999999999999999
    except (ValueError, TypeError):
        return False

def extract_channel_id(channel_mention: str) -> int:
    """
    Extract channel ID from mention or return as int
    
    Args:
        channel_mention: Channel mention or ID string
        
    Returns:
        Channel ID as integer
    """
    # Remove <# and > from channel mention
    channel_id = channel_mention.strip('<#>')
    
    try:
        return int(channel_id)
    except ValueError:
        raise ValueError(f"Invalid channel ID or mention: {channel_mention}")

def get_member_activity_status(member: discord.Member) -> dict:
    """
    Get detailed activity status for a member
    
    Args:
        member: Discord member object
        
    Returns:
        Dictionary with activity information
    """
    activity_info = {
        'status': str(member.status),
        'is_on_mobile': member.is_on_mobile(),
        'activities': []
    }
    
    for activity in member.activities:
        activity_data = {
            'type': str(activity.type),
            'name': activity.name
        }
        
        # Add specific details based on activity type
        if isinstance(activity, discord.Game):
            activity_data['details'] = getattr(activity, 'details', None)
            activity_data['state'] = getattr(activity, 'state', None)
        elif isinstance(activity, discord.Streaming):
            activity_data['url'] = activity.url
            activity_data['platform'] = activity.platform
        elif isinstance(activity, discord.Spotify):
            activity_data['artist'] = activity.artist
            activity_data['title'] = activity.title
            activity_data['album'] = activity.album
        
        activity_info['activities'].append(activity_data)
    
    return activity_info

def create_progress_bar(current: int, total: int, length: int = 20) -> str:
    """
    Create a text progress bar
    
    Args:
        current: Current progress
        total: Total progress
        length: Length of progress bar
        
    Returns:
        Progress bar string
    """
    if total == 0:
        return "[" + "─" * length + "] 0%"
    
    progress = current / total
    filled_length = int(length * progress)
    bar = "█" * filled_length + "─" * (length - filled_length)
    percentage = round(progress * 100, 1)
    
    return f"[{bar}] {percentage}%"

def validate_export_format(format_type: str) -> bool:
    """
    Validate export format type
    
    Args:
        format_type: Format type to validate
        
    Returns:
        True if valid, False otherwise
    """
    valid_formats = ['csv', 'json', 'txt']
    return format_type.lower() in valid_formats
