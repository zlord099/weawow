"""
Web scraping functionality for username searches across platforms
"""

import asyncio
import aiohttp
import re
import logging
from typing import Dict, List, Optional
from urllib.parse import quote_plus
import trafilatura

logger = logging.getLogger(__name__)

class UsernameSearcher:
    """Search for usernames across various platforms using web scraping"""
    
    def __init__(self):
        self.session = None
        self.search_platforms = {
            'roblox': {
                'search_url': 'https://www.roblox.com/search/users?keyword={}',
                'profile_pattern': r'roblox\.com/users/(\d+)/profile',
                'username_pattern': r'<h2[^>]*>([^<]+)</h2>',
                'display_name': 'Roblox'
            },
            'github': {
                'search_url': 'https://github.com/search?q={}&type=users',
                'profile_pattern': r'github\.com/([^/\s"]+)',
                'username_pattern': r'<span[^>]*class="[^"]*username[^"]*"[^>]*>([^<]+)</span>',
                'display_name': 'GitHub'
            },
            'twitter': {
                'search_url': 'https://twitter.com/search?q={}&src=typed_query&f=user',
                'profile_pattern': r'twitter\.com/([^/\s"]+)',
                'username_pattern': r'@([a-zA-Z0-9_]+)',
                'display_name': 'Twitter/X'
            }
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def search_username(self, username: str, platforms: List[str] = None) -> Dict[str, List[Dict]]:
        """
        Search for a username across specified platforms
        
        Args:
            username: Username to search for
            platforms: List of platforms to search (default: all)
            
        Returns:
            Dictionary with platform names as keys and search results as values
        """
        if platforms is None:
            platforms = list(self.search_platforms.keys())
        
        results = {}
        
        for platform in platforms:
            if platform not in self.search_platforms:
                logger.warning(f"Unknown platform: {platform}")
                continue
            
            try:
                platform_results = await self._search_platform(username, platform)
                results[platform] = platform_results
                logger.info(f"Found {len(platform_results)} results for {username} on {platform}")
                
                # Add delay between requests to be respectful
                await asyncio.sleep(2)
                
            except Exception as e:
                logger.error(f"Error searching {platform} for {username}: {e}")
                results[platform] = []
        
        return results
    
    async def _search_platform(self, username: str, platform: str) -> List[Dict]:
        """Search for username on a specific platform"""
        platform_config = self.search_platforms[platform]
        search_url = platform_config['search_url'].format(quote_plus(username))
        
        try:
            async with self.session.get(search_url) as response:
                if response.status != 200:
                    logger.warning(f"HTTP {response.status} for {platform} search")
                    return []
                
                html_content = await response.text()
                
                # Use trafilatura to extract clean text content
                extracted_text = trafilatura.extract(html_content)
                
                if not extracted_text:
                    logger.warning(f"No text extracted from {platform} search")
                    return []
                
                # Extract potential matches
                matches = self._extract_usernames_from_text(extracted_text, username, platform_config)
                
                return matches
                
        except Exception as e:
            logger.error(f"Error fetching {platform} search: {e}")
            return []
    
    def _extract_usernames_from_text(self, text: str, search_username: str, config: Dict) -> List[Dict]:
        """Extract username matches from text content"""
        matches = []
        
        # Look for exact username matches
        if search_username.lower() in text.lower():
            # Try to extract profile information
            profile_matches = re.findall(config.get('profile_pattern', ''), text, re.IGNORECASE)
            username_matches = re.findall(config.get('username_pattern', search_username), text, re.IGNORECASE)
            
            # Combine results
            for i, profile in enumerate(profile_matches[:5]):  # Limit to first 5 matches
                match_data = {
                    'username': username_matches[i] if i < len(username_matches) else search_username,
                    'profile_id': profile,
                    'platform': config['display_name'],
                    'confidence': 'high' if search_username.lower() == (username_matches[i] if i < len(username_matches) else search_username).lower() else 'medium'
                }
                matches.append(match_data)
        
        return matches
    
    async def get_detailed_profile_info(self, username: str, platform: str = 'roblox') -> Optional[Dict]:
        """Get detailed profile information for a specific username and platform"""
        if platform == 'roblox':
            return await self._get_roblox_profile_details(username)
        
        return None
    
    async def _get_roblox_profile_details(self, username: str) -> Optional[Dict]:
        """Get detailed Roblox profile information"""
        try:
            # First, search for the user to get their ID
            search_url = f"https://www.roblox.com/search/users?keyword={quote_plus(username)}"
            
            async with self.session.get(search_url) as response:
                if response.status != 200:
                    return None
                
                content = await response.text()
                
                # Extract user ID from search results
                user_id_match = re.search(r'/users/(\d+)/profile', content)
                if not user_id_match:
                    return None
                
                user_id = user_id_match.group(1)
                
                # Get profile page
                profile_url = f"https://www.roblox.com/users/{user_id}/profile"
                async with self.session.get(profile_url) as profile_response:
                    if profile_response.status != 200:
                        return None
                    
                    profile_content = await profile_response.text()
                    extracted_text = trafilatura.extract(profile_content)
                    
                    if not extracted_text:
                        return None
                    
                    # Extract profile information
                    profile_info = {
                        'username': username,
                        'user_id': user_id,
                        'profile_url': profile_url,
                        'platform': 'Roblox',
                        'extracted_text': extracted_text[:500] + "..." if len(extracted_text) > 500 else extracted_text
                    }
                    
                    # Try to extract specific information
                    join_date_match = re.search(r'Join Date[:\s]*([^\n]+)', extracted_text, re.IGNORECASE)
                    if join_date_match:
                        profile_info['join_date'] = join_date_match.group(1).strip()
                    
                    return profile_info
                    
        except Exception as e:
            logger.error(f"Error getting Roblox profile for {username}: {e}")
            return None

class UsernameValidator:
    """Validate and analyze usernames"""
    
    @staticmethod
    def is_valid_username(username: str) -> bool:
        """Check if username appears to be valid"""
        if not username or len(username) < 2:
            return False
        
        # Check for common invalid patterns
        invalid_patterns = [
            r'^https?://',  # URLs
            r'^<[^>]+>$',   # HTML tags
            r'^\d+$',       # Pure numbers
            r'^[^a-zA-Z0-9_.-]+$',  # No alphanumeric characters
        ]
        
        for pattern in invalid_patterns:
            if re.match(pattern, username, re.IGNORECASE):
                return False
        
        return True
    
    @staticmethod
    def extract_potential_usernames(text: str) -> List[str]:
        """Extract potential usernames from text"""
        usernames = []
        
        # Common username patterns
        patterns = [
            r'@([a-zA-Z0-9_.-]+)',  # @username format
            r'(?:^|\s)([a-zA-Z0-9_.-]{3,20})(?:\s|$)',  # Standalone usernames
            r'(?:username|user|name)[:\s]*([a-zA-Z0-9_.-]+)',  # Username: value
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                if UsernameValidator.is_valid_username(match):
                    usernames.append(match)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_usernames = []
        for username in usernames:
            if username.lower() not in seen:
                seen.add(username.lower())
                unique_usernames.append(username)
        
        return unique_usernames[:10]  # Limit to first 10 unique usernames