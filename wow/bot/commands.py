"""
Command definitions for the Discord Data Collection Bot
"""

import discord
from discord.ext import commands
import asyncio
from datetime import datetime
import logging

from .utils import format_file_size, create_embed, check_permissions, create_progress_bar
from .data_collector import DataExporter, CredentialExtractor, RobloxValidator
from .web_scraper import UsernameSearcher, UsernameValidator
from .config import BotConfig

logger = logging.getLogger(__name__)

async def setup_commands(bot):
    """Setup all command groups"""
    await bot.add_cog(DataCommands(bot))
    await bot.add_cog(ServerCommands(bot))
    await bot.add_cog(AdminCommands(bot))

class DataCommands(commands.Cog):
    """Commands for data collection and export"""

    def __init__(self, bot):
        self.bot = bot
        self.exporter = DataExporter()
        self.credential_extractor = CredentialExtractor()
        self.roblox_validator = RobloxValidator()

    @commands.command(name='scrape_messages', aliases=['scrape', 'messages'])
    @commands.has_permissions(manage_messages=True)
    @commands.cooldown(1, 30, commands.BucketType.guild)
    async def scrape_messages(self, ctx, channel: discord.TextChannel = None, limit: int = None):
        """
        Scrape messages from a channel

        Usage: !scrape_messages #channel 1000
        """
        if not channel:
            channel = ctx.channel

        if not limit:
            limit = None  # No limit - scrape ALL messages
        elif limit > 100000:
            await ctx.send("❌ Message limit cannot exceed 100,000 for performance reasons.")
            return

        # Check bot permissions
        if not channel.permissions_for(ctx.guild.me).read_message_history:
            await ctx.send(f"❌ I don't have permission to read message history in {channel.mention}")
            return

        # Send initial message
        limit_text = f"{limit:,} messages" if limit else "ALL messages"
        embed = create_embed(
            "📊 Message Scraping Started",
            f"Scraping {limit_text} from {channel.mention}...",
            discord.Color.blue()
        )
        status_msg = await ctx.send(embed=embed)

        try:
            # Collect messages with progress updates (starting from most recent)
            messages_data = []
            scraped_count = 0

            async for message in channel.history(limit=limit, oldest_first=False):
                try:
                    message_info = await self._extract_message_data(message)
                    messages_data.append(message_info)
                    scraped_count += 1

                    # Update progress every 100 messages
                    if scraped_count % 100 == 0:
                        embed = create_embed(
                            "📊 Scraping in Progress",
                            f"Scraped {scraped_count:,} messages from {channel.mention}...",
                            discord.Color.blue()
                        )
                        await status_msg.edit(embed=embed)

                    # Rate limiting
                    await asyncio.sleep(0.1)

                except Exception as e:
                    logger.warning(f"Failed to process message {message.id}: {e}")
                    continue

            if not messages_data:
                embed = create_embed(
                    "❌ No Messages Found",
                    f"No messages could be scraped from {channel.mention}",
                    discord.Color.red()
                )
                await status_msg.edit(embed=embed)
                return

            # Export data
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename_base = f"messages_{channel.name}_{timestamp}"

            # Export to both CSV and JSON
            csv_file = await self.exporter.export_messages_csv(messages_data, filename_base)
            json_file = await self.exporter.export_messages_json(messages_data, filename_base)

            # Send results
            embed = create_embed(
                "✅ Message Scraping Complete",
                f"Successfully scraped {len(messages_data):,} messages from {channel.mention}",
                discord.Color.green()
            )
            embed.add_field(name="Files Created", value=f"• {csv_file}\n• {json_file}", inline=False)
            embed.add_field(name="Date Range", 
                           value=f"From: {messages_data[-1]['timestamp'][:10]}\nTo: {messages_data[0]['timestamp'][:10]}", 
                           inline=True)

            await status_msg.edit(embed=embed)

            # Send files if they're small enough
            try:
                csv_size = format_file_size(csv_file)
                json_size = format_file_size(json_file)

                files_to_send = []
                if csv_size < 8 * 1024 * 1024:  # 8MB Discord limit
                    files_to_send.append(discord.File(csv_file))
                if json_size < 8 * 1024 * 1024:
                    files_to_send.append(discord.File(json_file))

                if files_to_send:
                    await ctx.send("📁 Data files:", files=files_to_send)

            except Exception as e:
                logger.warning(f"Could not send files: {e}")

        except discord.Forbidden:
            embed = create_embed(
                "❌ Permission Denied",
                f"I don't have permission to read messages in {channel.mention}",
                discord.Color.red()
            )
            await status_msg.edit(embed=embed)

        except Exception as e:
            logger.error(f"Error scraping messages: {e}")
            embed = create_embed(
                "❌ Scraping Failed",
                f"An error occurred while scraping messages: {str(e)}",
                discord.Color.red()
            )
            await status_msg.edit(embed=embed)

    async def _extract_message_data(self, message):
        """Extract data from a Discord message"""
        return {
            'id': message.id,
            'author': str(message.author),
            'author_id': message.author.id,
            'author_display_name': message.author.display_name,
            'content': message.content if message.content else '',
            'timestamp': message.created_at.isoformat(),
            'edited_at': message.edited_at.isoformat() if message.edited_at else None,
            'channel': message.channel.name,
            'channel_id': message.channel.id,
            'message_type': str(message.type),
            'attachments': [{'filename': att.filename, 'url': att.url, 'size': att.size} for att in message.attachments],
            'embeds_count': len(message.embeds),
            'reactions': [{'emoji': str(r.emoji), 'count': r.count} for r in message.reactions],
            'reply_to': message.reference.message_id if message.reference else None,
            'thread_id': message.thread.id if hasattr(message, 'thread') and message.thread else None
        }

    @commands.command(name='scrape_credentials', aliases=['creds', 'passwords'])
    @commands.has_permissions(manage_messages=True)
    @commands.cooldown(1, 30, commands.BucketType.guild)
    async def scrape_credentials(self, ctx, channel: discord.TextChannel = None, limit: int = None):
        """
        Extract usernames and passwords from messages

        Usage: !scrape_credentials #hits 1000
        """
        if not channel:
            channel = ctx.channel

        if not limit:
            limit = None  # No limit - scrape ALL messages
        elif limit > 100000:
            await ctx.send("❌ Message limit cannot exceed 100,000 for performance reasons.")
            return

        # Check bot permissions
        if not channel.permissions_for(ctx.guild.me).read_message_history:
            await ctx.send(f"❌ I don't have permission to read message history in {channel.mention}")
            return

        # Send initial message
        limit_text = f"up to {limit:,} messages" if limit else "ALL messages"
        embed = create_embed(
            "🔐 Credential Extraction Started",
            f"Extracting credentials from {limit_text} in {channel.mention}...",
            discord.Color.blue()
        )
        status_msg = await ctx.send(embed=embed)

        try:
            credentials_data = []
            scraped_count = 0
            found_credentials = 0

            async for message in channel.history(limit=limit, oldest_first=False):
                try:
                    scraped_count += 1

                    # Extract credentials from message content and embeds
                    extracted_creds = await self.credential_extractor.extract_from_message(message)

                    if extracted_creds:
                        credentials_data.extend(extracted_creds)
                        found_credentials += len(extracted_creds)

                    # Update progress every 100 messages
                    if scraped_count % 100 == 0:
                        embed = create_embed(
                            "🔐 Extraction in Progress",
                            f"Processed {scraped_count:,} messages, found {found_credentials} credentials from {channel.mention}...",
                            discord.Color.blue()
                        )
                        await status_msg.edit(embed=embed)

                    # Rate limiting
                    await asyncio.sleep(0.1)

                except Exception as e:
                    logger.warning(f"Failed to process message {message.id}: {e}")
                    continue

            if not credentials_data:
                embed = create_embed(
                    "❌ No Credentials Found",
                    f"No username/password pairs found in {channel.mention}",
                    discord.Color.red()
                )
                await status_msg.edit(embed=embed)
                return

            # Export credential data
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename_base = f"credentials_{channel.name}_{timestamp}"

            # Export to both CSV and JSON (full and simplified versions)
            csv_file = await self.exporter.export_credentials_csv(credentials_data, filename_base)
            json_file = await self.exporter.export_credentials_json(credentials_data, filename_base)
            simple_csv_file = await self.exporter.export_credentials_simple_csv(credentials_data, filename_base)
            simple_json_file = await self.exporter.export_credentials_simple_json(credentials_data, filename_base)

            # Send results
            embed = create_embed(
                "✅ Credential Extraction Complete",
                f"Successfully extracted {len(credentials_data):,} credential pairs from {channel.mention}",
                discord.Color.green()
            )
            embed.add_field(name="Full Export Files", value=f"• {csv_file}\n• {json_file}", inline=False)
            embed.add_field(name="Simple Export Files", value=f"• {simple_csv_file}\n• {simple_json_file}", inline=False)
            embed.add_field(name="Statistics", 
                           value=f"Messages Processed: {scraped_count:,}\nCredentials Found: {found_credentials}", 
                           inline=True)

            await status_msg.edit(embed=embed)

            # Send files if they're small enough
            try:
                csv_size = format_file_size(csv_file)
                json_size = format_file_size(json_file)
                simple_csv_size = format_file_size(simple_csv_file)
                simple_json_size = format_file_size(simple_json_file)

                files_to_send = []
                if csv_size < 8 * 1024 * 1024:  # 8MB Discord limit
                    files_to_send.append(discord.File(csv_file))
                if json_size < 8 * 1024 * 1024:
                    files_to_send.append(discord.File(json_file))
                if simple_csv_size < 8 * 1024 * 1024:
                    files_to_send.append(discord.File(simple_csv_file))
                if simple_json_size < 8 * 1024 * 1024:
                    files_to_send.append(discord.File(simple_json_file))

                if files_to_send:
                    await ctx.send("📁 Credential files:", files=files_to_send)

            except Exception as e:
                logger.warning(f"Could not send files: {e}")

        except discord.Forbidden:
            embed = create_embed(
                "❌ Permission Denied",
                f"I don't have permission to read messages in {channel.mention}",
                discord.Color.red()
            )
            await status_msg.edit(embed=embed)

        except Exception as e:
            logger.error(f"Error extracting credentials: {e}")
            embed = create_embed(
                "❌ Extraction Failed",
                f"An error occurred while extracting credentials: {str(e)}",
                discord.Color.red()
            )
            await status_msg.edit(embed=embed)

    @commands.command(name='scrape_all_credentials', aliases=['scrape_all', 'complete_scrape'])
    @commands.has_permissions(manage_messages=True)
    @commands.cooldown(1, 300, commands.BucketType.guild)  # 5 minute cooldown for intensive operation
    async def scrape_all_credentials(self, ctx, channel: discord.TextChannel = None):
        """
        Scrape EVERY SINGLE message from a channel for credentials (no limits)

        Usage: !scrape_all_credentials #hits
        """
        if not channel:
            channel = ctx.channel

        # Check bot permissions
        if not channel.permissions_for(ctx.guild.me).read_message_history:
            await ctx.send(f"❌ I don't have permission to read message history in {channel.mention}")
            return

        # Send initial warning message
        warning_embed = create_embed(
            "⚠️ Comprehensive Credential Scraping",
            f"This will scrape **EVERY SINGLE MESSAGE** in {channel.mention} with no limits.\n"
            "This may take a very long time for large channels.\n\n"
            "React with ✅ to continue or ❌ to cancel.",
            discord.Color.orange()
        )
        warning_msg = await ctx.send(embed=warning_embed)
        await warning_msg.add_reaction("✅")
        await warning_msg.add_reaction("❌")

        def check(reaction, user):
            return user == ctx.author and str(reaction.emoji) in ["✅", "❌"] and reaction.message.id == warning_msg.id

        try:
            reaction, user = await self.bot.wait_for('reaction_add', timeout=60.0, check=check)

            if str(reaction.emoji) == "❌":
                await warning_msg.edit(embed=create_embed("❌ Cancelled", "Comprehensive scraping cancelled.", discord.Color.red()))
                return

        except asyncio.TimeoutError:
            await warning_msg.edit(embed=create_embed("⏰ Timeout", "Comprehensive scraping cancelled due to timeout.", discord.Color.red()))
            return

        # Start comprehensive scraping
        embed = create_embed(
            "🔐 Comprehensive Credential Extraction Started",
            f"Extracting credentials from ALL messages in {channel.mention}...\n"
            "⚠️ This process has no message limit and may take a long time.",
            discord.Color.blue()
        )
        status_msg = await warning_msg.edit(embed=embed)

        try:
            credentials_data = []
            scraped_count = 0
            found_credentials = 0

            # Scrape with NO LIMIT, starting from most recent messages
            async for message in channel.history(limit=None, oldest_first=False):
                try:
                    scraped_count += 1

                    # Extract credentials from message content and embeds
                    extracted_creds = await self.credential_extractor.extract_from_message(message)

                    if extracted_creds:
                        credentials_data.extend(extracted_creds)
                        found_credentials += len(extracted_creds)

                    # Update progress every 500 messages for comprehensive scraping
                    if scraped_count % 500 == 0:
                        embed = create_embed(
                            "🔐 Comprehensive Extraction in Progress",
                            f"Processed {scraped_count:,} messages, found {found_credentials} credentials from {channel.mention}...\n"
                            f"Still processing... (No limit)",
                            discord.Color.blue()
                        )
                        await status_msg.edit(embed=embed)

                    # Smaller rate limiting for comprehensive scraping
                    await asyncio.sleep(0.05)

                except Exception as e:
                    logger.warning(f"Failed to process message {message.id}: {e}")
                    continue

            # Final results
            if not credentials_data:
                embed = create_embed(
                    "❌ No Credentials Found",
                    f"No username/password pairs found in {channel.mention} after processing {scraped_count:,} messages",
                    discord.Color.red()
                )
                await status_msg.edit(embed=embed)
                return

            # Export credential data
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename_base = f"credentials_complete_{channel.name}_{timestamp}"

            # Export to both CSV and JSON (full and simplified versions)
            csv_file = await self.exporter.export_credentials_csv(credentials_data, filename_base)
            json_file = await self.exporter.export_credentials_json(credentials_data, filename_base)
            simple_csv_file = await self.exporter.export_credentials_simple_csv(credentials_data, filename_base)
            simple_json_file = await self.exporter.export_credentials_simple_json(credentials_data, filename_base)

            # Send results
            embed = create_embed(
                "✅ Comprehensive Credential Extraction Complete",
                f"Successfully extracted {len(credentials_data):,} credential pairs from {channel.mention}",
                discord.Color.green()
            )
            embed.add_field(name="Full Export Files", value=f"• {csv_file}\n• {json_file}", inline=False)
            embed.add_field(name="Simple Export Files", value=f"• {simple_csv_file}\n• {simple_json_file}", inline=False)
            embed.add_field(name="Final Statistics", 
                           value=f"Total Messages Processed: {scraped_count:,}\nCredentials Found: {found_credentials}\nChannel: {channel.mention}", 
                           inline=True)

            await status_msg.edit(embed=embed)

            # Send files if they're small enough
            try:
                csv_size = format_file_size(csv_file)
                json_size = format_file_size(json_file)
                simple_csv_size = format_file_size(simple_csv_file)
                simple_json_size = format_file_size(simple_json_file)

                files_to_send = []
                if csv_size < 8 * 1024 * 1024:  # 8MB Discord limit
                    files_to_send.append(discord.File(csv_file))
                if json_size < 8 * 1024 * 1024:
                    files_to_send.append(discord.File(json_file))
                if simple_csv_size < 8 * 1024 * 1024:
                    files_to_send.append(discord.File(simple_csv_file))
                if simple_json_size < 8 * 1024 * 1024:
                    files_to_send.append(discord.File(simple_json_file))

                if files_to_send:
                    await ctx.send("📁 Complete credential files:", files=files_to_send)

            except Exception as e:
                logger.warning(f"Could not send files: {e}")

        except discord.Forbidden:
            embed = create_embed(
                "❌ Permission Denied",
                f"I don't have permission to read messages in {channel.mention}",
                discord.Color.red()
            )
            await status_msg.edit(embed=embed)

        except Exception as e:
            logger.error(f"Error in comprehensive credential extraction: {e}")
            embed = create_embed(
                "❌ Extraction Failed",
                f"An error occurred during comprehensive extraction: {str(e)}",
                discord.Color.red()
            )
            await status_msg.edit(embed=embed)

    @commands.command(name='search_username', aliases=['search', 'find_user'])
    @commands.has_permissions(manage_messages=True)  
    @commands.cooldown(1, 60, commands.BucketType.user)
    async def search_username(self, ctx, username: str, platforms: str = "roblox"):
        """
        Search for a username across various platforms

        Usage: !search_username Visor_XB roblox,github
        """
        if not username:
            await ctx.send("❌ Please provide a username to search for.")
            return

        # Validate username
        if not UsernameValidator.is_valid_username(username):
            await ctx.send(f"❌ '{username}' doesn't appear to be a valid username.")
            return

        # Parse platforms
        platform_list = [p.strip().lower() for p in platforms.split(',')]
        valid_platforms = ['roblox', 'github', 'twitter']

        # Filter valid platforms
        search_platforms = [p for p in platform_list if p in valid_platforms]
        if not search_platforms:
            search_platforms = ['roblox']  # Default to Roblox

        # Send initial message
        embed = create_embed(
            "🔍 Username Search Started",
            f"Searching for '{username}' on {', '.join(search_platforms)}...",
            discord.Color.blue()
        )
        status_msg = await ctx.send(embed=embed)

        try:
            async with UsernameSearcher() as searcher:
                results = await searcher.search_username(username, search_platforms)

                if not any(results.values()):
                    embed = create_embed(
                        "🔍 Search Complete",
                        f"No results found for '{username}' on the searched platforms.",
                        discord.Color.orange()
                    )
                    await status_msg.edit(embed=embed)
                    return

                # Format results
                result_text = f"**Search Results for '{username}':**\n\n"
                total_matches = 0

                for platform, matches in results.items():
                    if matches:
                        result_text += f"**{platform.title()}** ({len(matches)} matches):\n"
                        for match in matches[:3]:  # Show first 3 matches per platform
                            result_text += f"• {match.get('username', username)} - {match.get('confidence', 'unknown')} confidence\n"
                            if match.get('profile_id'):
                                result_text += f"  Profile: {match['profile_id']}\n"
                        result_text += "\n"
                        total_matches += len(matches)

                embed = create_embed(
                    "🔍 Search Results",
                    result_text[:2000],  # Discord embed description limit
                    discord.Color.green()
                )
                embed.set_footer(text=f"Total matches found: {total_matches}")
                await status_msg.edit(embed=embed)

        except Exception as e:
            logger.error(f"Error searching for username {username}: {e}")
            embed = create_embed(
                "❌ Search Failed",
                f"An error occurred while searching for '{username}': {str(e)}",
                discord.Color.red()
            )
            await status_msg.edit(embed=embed)

    @commands.command(name='extract_usernames', aliases=['find_usernames'])
    @commands.has_permissions(manage_messages=True)
    @commands.cooldown(1, 30, commands.BucketType.guild)
    async def extract_usernames(self, ctx, channel: discord.TextChannel = None, limit: int = 100):
        """
        Extract potential usernames from messages and search for them

        Usage: !extract_usernames #channel 500
        """
        if not channel:
            channel = ctx.channel

        embed = create_embed(
            "🔍 Username Extraction Started",
            f"Scanning messages in {channel.mention} for usernames...",
            discord.Color.blue()
        )
        status_msg = await ctx.send(embed=embed)

        try:
            found_usernames = set()

            async for message in channel.history(limit=limit):
                # Extract usernames from message content
                if message.content:
                    usernames = UsernameValidator.extract_potential_usernames(message.content)
                    found_usernames.update(usernames)

                # Extract from embeds
                for embed in message.embeds:
                    embed_text = ""
                    if embed.description:
                        embed_text += embed.description + "\n"
                    for field in embed.fields:
                        embed_text += f"{field.name}: {field.value}\n"

                    if embed_text:
                        usernames = UsernameValidator.extract_potential_usernames(embed_text)
                        found_usernames.update(usernames)

            if not found_usernames:
                embed = create_embed(
                    "🔍 Extraction Complete",
                    "No potential usernames found in the scanned messages.",
                    discord.Color.orange()
                )
                await status_msg.edit(embed=embed)
                return

            # Limit to first 10 usernames for display
            username_list = list(found_usernames)[:10]
            result_text = f"**Found {len(found_usernames)} potential usernames:**\n\n"

            for username in username_list:
                result_text += f"• {username}\n"

            if len(found_usernames) > 10:
                result_text += f"\n... and {len(found_usernames) - 10} more"

            result_text += f"\n\nUse `!search_username <username>` to search for specific usernames."

            embed = create_embed(
                "🔍 Username Extraction Complete",
                result_text,
                discord.Color.green()
            )
            await status_msg.edit(embed=embed)

        except Exception as e:
            logger.error(f"Error extracting usernames: {e}")
            embed = create_embed(
                "❌ Extraction Failed",
                f"An error occurred while extracting usernames: {str(e)}",
                discord.Color.red()
            )
            await status_msg.edit(embed=embed)

    @commands.command(name='scrape_token2', aliases=['token2', 'discord_tokens'])
    @commands.has_permissions(manage_messages=True)
    @commands.cooldown(1, 30, commands.BucketType.guild)
    async def scrape_token2(self, ctx, channel: discord.TextChannel = None, limit: int = None):
        """
        Extract Discord token2 authentication data from messages
        
        Usage: !scrape_token2 #channel 1000
        """
        if not channel:
            channel = ctx.channel
        
        if not limit:
            limit = BotConfig.DEFAULT_MESSAGE_LIMIT
        elif limit > BotConfig.MAX_MESSAGE_LIMIT:
            await ctx.send(f"❌ Message limit cannot exceed {BotConfig.MAX_MESSAGE_LIMIT:,}")
            return
        
        # Check bot permissions
        if not channel.permissions_for(ctx.guild.me).read_message_history:
            await ctx.send(f"❌ I don't have permission to read message history in {channel.mention}")
            return
        
        # Send initial message
        embed = create_embed(
            "🔐 Token2 Extraction Started",
            f"Scanning {limit:,} messages in {channel.mention} for Discord authentication tokens...",
            discord.Color.orange()
        )
        status_msg = await ctx.send(embed=embed)
        
        try:
            # Initialize credential extractor
            extractor = CredentialExtractor()
            
            # Collect messages and extract token2 data
            token2_data = []
            scraped_count = 0
            
            async for message in channel.history(limit=limit, oldest_first=False):
                scraped_count += 1
                
                # Extract token2 data from message
                extracted_data = await extractor.extract_from_message(message)
                
                # Filter for token2 data only
                for data in extracted_data:
                    if data.get('type') == 'discord_token2' or data.get('token2_full_token'):
                        token2_data.append(data)
                
                # Update progress every 100 messages
                if scraped_count % 100 == 0:
                    progress = create_progress_bar(scraped_count, limit)
                    embed = create_embed(
                        "🔐 Token2 Extraction in Progress",
                        f"Processing messages... {progress}\n\n"
                        f"**Progress:** {scraped_count:,}/{limit:,} messages\n"
                        f"**Tokens Found:** {len(token2_data):,}\n"
                        f"**Channel:** {channel.mention}",
                        discord.Color.orange()
                    )
                    await status_msg.edit(embed=embed)
                
                # Rate limiting
                await asyncio.sleep(BotConfig.MESSAGE_SCRAPE_DELAY)
            
            # Check if we found any token2 data
            if not token2_data:
                embed = create_embed(
                    "❌ No Discord Tokens Found",
                    f"No Discord token2 authentication data found in {channel.mention} after processing {scraped_count:,} messages",
                    discord.Color.red()
                )
                await status_msg.edit(embed=embed)
                return
            
            # Export token2 data
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename_base = f"token2_{channel.name}_{timestamp}"
            
            # Export to both CSV and JSON (full and simplified versions)
            csv_file = await self.exporter.export_credentials_csv(token2_data, filename_base)
            json_file = await self.exporter.export_credentials_json(token2_data, filename_base)
            simple_csv_file = await self.exporter.export_credentials_simple_csv(token2_data, filename_base)
            simple_json_file = await self.exporter.export_credentials_simple_json(token2_data, filename_base)
            
            # Send results
            embed = create_embed(
                "✅ Token2 Extraction Complete",
                f"Successfully extracted {len(token2_data):,} Discord token2 entries from {channel.mention}",
                discord.Color.green()
            )
            embed.add_field(name="Full Export Files", value=f"• {csv_file}\n• {json_file}", inline=False)
            embed.add_field(name="Simple Export Files", value=f"• {simple_csv_file}\n• {simple_json_file}", inline=False)
            embed.add_field(name="Statistics", 
                           value=f"Messages Processed: {scraped_count:,}\nTokens Found: {len(token2_data):,}\nChannel: {channel.mention}", 
                           inline=True)
            
            await status_msg.edit(embed=embed)
            
            # Send files if they're small enough
            try:
                csv_size = format_file_size(csv_file)
                json_size = format_file_size(json_file)
                simple_csv_size = format_file_size(simple_csv_file)
                simple_json_size = format_file_size(simple_json_file)
                
                files_to_send = []
                if csv_size < 8 * 1024 * 1024:  # 8MB Discord limit
                    files_to_send.append(discord.File(csv_file))
                if json_size < 8 * 1024 * 1024:
                    files_to_send.append(discord.File(json_file))
                if simple_csv_size < 8 * 1024 * 1024:
                    files_to_send.append(discord.File(simple_csv_file))
                if simple_json_size < 8 * 1024 * 1024:
                    files_to_send.append(discord.File(simple_json_file))
                
                if files_to_send:
                    await ctx.send("📁 Token2 data files:", files=files_to_send)
                
            except Exception as e:
                logger.warning(f"Could not send files: {e}")
        
        except discord.Forbidden:
            embed = create_embed(
                "❌ Permission Denied",
                f"I don't have permission to read messages in {channel.mention}",
                discord.Color.red()
            )
            await status_msg.edit(embed=embed)
        
        except Exception as e:
            logger.error(f"Error extracting token2 data: {e}")
            embed = create_embed(
                "❌ Extraction Failed",
                f"An error occurred while extracting token2 data: {str(e)}",
                discord.Color.red()
            )
            await status_msg.edit(embed=embed)

    @commands.command(name='validate_caeaahab', aliases=['validate_roblox', 'check_roblox'])
    @commands.has_permissions(read_message_history=True)
    @commands.cooldown(1, 30, commands.BucketType.user)
    async def validate_caeaahab(self, ctx, channel: discord.TextChannel = None, limit: int = None):
        """
        Validate CAEaAhAB tokens using Roblox API

        Usage: !validate_caeaahab #channel 1000
        """
        # Use current channel if none specified
        if channel is None:
            channel = ctx.channel
        
        # Use default limit if none specified
        if limit is None:
            limit = BotConfig.DEFAULT_MESSAGE_LIMIT
        
        # Ensure limit doesn't exceed maximum
        if limit > BotConfig.MAX_MESSAGE_LIMIT:
            limit = BotConfig.MAX_MESSAGE_LIMIT
        
        # Check permissions
        permissions = check_permissions(channel, ctx.guild.me)
        if not permissions['read_message_history']:
            embed = create_embed(
                "❌ Missing Permissions",
                f"I need **Read Message History** permission in {channel.mention}",
                discord.Color.red()
            )
            await ctx.send(embed=embed)
            return
        
        # Send initial message
        embed = create_embed(
            "🔍 CAEaAhAB Token Validation Started",
            f"Scanning {limit:,} messages in {channel.mention} for CAEaAhAB tokens and validating them...",
            discord.Color.orange()
        )
        status_msg = await ctx.send(embed=embed)
        
        try:
            # Initialize credential extractor
            extractor = CredentialExtractor()
            
            # Collect messages and extract credentials
            all_credentials = []
            scraped_count = 0
            
            async for message in channel.history(limit=limit, oldest_first=False):
                scraped_count += 1
                
                # Extract credentials from message
                extracted_data = await extractor.extract_from_message(message)
                all_credentials.extend(extracted_data)
                
                # Update progress every 100 messages
                if scraped_count % 100 == 0:
                    progress_bar = create_progress_bar(scraped_count, limit)
                    embed = create_embed(
                        "🔍 CAEaAhAB Token Validation In Progress",
                        f"Scanned {scraped_count:,}/{limit:,} messages\n{progress_bar}",
                        discord.Color.orange()
                    )
                    try:
                        await status_msg.edit(embed=embed)
                    except:
                        pass
                
                # Small delay to respect rate limits
                await asyncio.sleep(BotConfig.MESSAGE_SCRAPE_DELAY)
            
            # Filter for credentials with CAEaAhAB tokens
            caeaahab_credentials = [
                cred for cred in all_credentials 
                if cred.get('caeaahab_token', '').startswith('CAEaAhAB')
            ]
            
            if not caeaahab_credentials:
                embed = create_embed(
                    "📊 No CAEaAhAB Tokens Found",
                    f"Scanned {scraped_count:,} messages but found no CAEaAhAB tokens to validate.",
                    discord.Color.blue()
                )
                await status_msg.edit(embed=embed)
                return
            
            # Update status for validation phase
            embed = create_embed(
                "🔍 Validating CAEaAhAB Tokens",
                f"Found {len(caeaahab_credentials)} CAEaAhAB tokens. Now validating with Roblox API...",
                discord.Color.orange()
            )
            await status_msg.edit(embed=embed)
            
            # Validate the tokens
            validated_credentials = await self.roblox_validator.validate_credentials_with_cookies(caeaahab_credentials)
            
            # Count validation results
            valid_count = sum(1 for cred in validated_credentials if cred.get('roblox_valid', False))
            invalid_count = len(validated_credentials) - valid_count
            
            # Export the validated data
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename_base = f"caeaahab_validation_{channel.name}_{timestamp}"
            
            csv_file = await self.exporter.export_credentials_csv(validated_credentials, filename_base)
            json_file = await self.exporter.export_credentials_json(validated_credentials, filename_base)
            simple_csv_file = await self.exporter.export_credentials_simple_csv(validated_credentials, filename_base)
            simple_json_file = await self.exporter.export_credentials_simple_json(validated_credentials, filename_base)
            
            # Create summary embed
            embed = create_embed(
                "✅ CAEaAhAB Token Validation Complete",
                f"**Validation Results:**\n"
                f"• Total CAEaAhAB tokens found: {len(validated_credentials)}\n"
                f"• ✅ Valid tokens: {valid_count}\n"
                f"• ❌ Invalid/expired tokens: {invalid_count}\n"
                f"• Messages scanned: {scraped_count:,}\n\n"
                f"**Files exported:**\n"
                f"• Full data (CSV): `{csv_file}`\n"
                f"• Full data (JSON): `{json_file}`\n"
                f"• Simple data (CSV): `{simple_csv_file}`\n"
                f"• Simple data (JSON): `{simple_json_file}`",
                discord.Color.green()
            )
            await status_msg.edit(embed=embed)
            
            # Try to send files if they're not too large
            try:
                csv_size = format_file_size(csv_file)
                json_size = format_file_size(json_file)
                simple_csv_size = format_file_size(simple_csv_file)
                simple_json_size = format_file_size(simple_json_file)
                
                files_to_send = []
                if csv_size < 8 * 1024 * 1024:  # 8MB Discord limit
                    files_to_send.append(discord.File(csv_file))
                if json_size < 8 * 1024 * 1024:
                    files_to_send.append(discord.File(json_file))
                if simple_csv_size < 8 * 1024 * 1024:
                    files_to_send.append(discord.File(simple_csv_file))
                if simple_json_size < 8 * 1024 * 1024:
                    files_to_send.append(discord.File(simple_json_file))
                
                if files_to_send:
                    await ctx.send("📁 CAEaAhAB validation files:", files=files_to_send)
                
            except Exception as e:
                logger.warning(f"Could not send files: {e}")
        
        except discord.Forbidden:
            embed = create_embed(
                "❌ Permission Denied",
                f"I don't have permission to read messages in {channel.mention}",
                discord.Color.red()
            )
            await status_msg.edit(embed=embed)
        
        except Exception as e:
            logger.error(f"Error validating CAEaAhAB tokens: {e}")
            embed = create_embed(
                "❌ Validation Failed",
                f"An error occurred while validating CAEaAhAB tokens: {str(e)}",
                discord.Color.red()
            )
            await status_msg.edit(embed=embed)

    @commands.command(name='export_members', aliases=['members'])
    @commands.has_permissions(manage_guild=True)
    @commands.cooldown(1, 60, commands.BucketType.guild)
    async def export_members(self, ctx):
        """Export server member data"""
        embed = create_embed(
            "👥 Exporting Member Data",
            "Collecting member information...",
            discord.Color.blue()
        )
        status_msg = await ctx.send(embed=embed)

        try:
            members_data = []

            for member in ctx.guild.members:
                member_info = {
                    'id': member.id,
                    'username': member.name,
                    'display_name': member.display_name,
                    'discriminator': member.discriminator,
                    'joined_at': member.joined_at.isoformat() if member.joined_at else None,
                    'created_at': member.created_at.isoformat(),
                    'roles': [role.name for role in member.roles if role.name != '@everyone'],
                    'top_role': member.top_role.name,
                    'status': str(member.status),
                    'is_bot': member.bot,
                    'avatar_url': str(member.avatar.url) if member.avatar else None,
                    'premium_since': member.premium_since.isoformat() if member.premium_since else None
                }
                members_data.append(member_info)

            # Export data
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename_base = f"members_{ctx.guild.name}_{timestamp}"

            csv_file = await self.exporter.export_members_csv(members_data, filename_base)
            json_file = await self.exporter.export_members_json(members_data, filename_base)

            embed = create_embed(
                "✅ Member Export Complete",
                f"Exported data for {len(members_data):,} members",
                discord.Color.green()
            )
            embed.add_field(name="Files Created", value=f"• {csv_file}\n• {json_file}", inline=False)

            await status_msg.edit(embed=embed)

        except Exception as e:
            logger.error(f"Error exporting members: {e}")
            embed = create_embed(
                "❌ Export Failed",
                f"Failed to export member data: {str(e)}",
                discord.Color.red()
            )
            await status_msg.edit(embed=embed)

class ServerCommands(commands.Cog):
    """Commands for server information and statistics"""

    def __init__(self, bot):
        self.bot = bot
        self.exporter = DataExporter()

    @commands.command(name='server_stats', aliases=['stats', 'info'])
    @commands.cooldown(1, 30, commands.BucketType.guild)
    async def server_stats(self, ctx):
        """Display comprehensive server statistics"""
        guild = ctx.guild

        # Calculate statistics
        text_channels = len(guild.text_channels)
        voice_channels = len(guild.voice_channels)
        categories = len(guild.categories)

        online_members = len([m for m in guild.members if m.status != discord.Status.offline])
        bot_count = len([m for m in guild.members if m.bot])
        human_count = guild.member_count - bot_count

        # Create embed
        embed = create_embed(
            f"📊 {guild.name} Statistics",
            f"Comprehensive server information",
            discord.Color.blue()
        )

        if guild.icon:
            embed.set_thumbnail(url=guild.icon.url)

        # Basic info
        embed.add_field(
            name="🏠 Basic Information",
            value=f"**Owner:** {guild.owner.mention}\n"
                  f"**Created:** {guild.created_at.strftime('%B %d, %Y')}\n"
                  f"**Server ID:** {guild.id}",
            inline=False
        )

        # Member statistics
        embed.add_field(
            name="👥 Members",
            value=f"**Total:** {guild.member_count:,}\n"
                  f"**Humans:** {human_count:,}\n"
                  f"**Bots:** {bot_count:,}\n"
                  f"**Online:** {online_members:,}",
            inline=True
        )

        # Channel statistics
        embed.add_field(
            name="📝 Channels",
            value=f"**Text:** {text_channels}\n"
                  f"**Voice:** {voice_channels}\n"
                  f"**Categories:** {categories}\n"
                  f"**Total:** {text_channels + voice_channels}",
            inline=True
        )

        # Server features
        embed.add_field(
            name="✨ Features",
            value=f"**Roles:** {len(guild.roles)}\n"
                  f"**Emojis:** {len(guild.emojis)}\n"
                  f"**Boost Level:** {guild.premium_tier}\n"
                  f"**Boosts:** {guild.premium_subscription_count or 0}",
            inline=True
        )

        await ctx.send(embed=embed)

    @commands.command(name='export_stats', aliases=['save_stats'])
    @commands.has_permissions(manage_guild=True)
    @commands.cooldown(1, 60, commands.BucketType.guild)
    async def export_server_stats(self, ctx):
        """Export detailed server statistics to file"""
        guild = ctx.guild

        embed = create_embed(
            "📊 Exporting Server Statistics",
            "Collecting detailed server information...",
            discord.Color.blue()
        )
        status_msg = await ctx.send(embed=embed)

        try:
            stats = {
                'server_name': guild.name,
                'server_id': guild.id,
                'owner': str(guild.owner),
                'owner_id': guild.owner.id,
                'created_at': guild.created_at.isoformat(),
                'member_count': guild.member_count,
                'channels': {
                    'text_channels': len(guild.text_channels),
                    'voice_channels': len(guild.voice_channels),
                    'categories': len(guild.categories),
                    'stage_channels': len(guild.stage_channels),
                    'forum_channels': len([c for c in guild.channels if isinstance(c, discord.ForumChannel)])
                },
                'roles': len(guild.roles),
                'emojis': len(guild.emojis),
                'stickers': len(guild.stickers),
                'boost_level': guild.premium_tier,
                'boost_count': guild.premium_subscription_count or 0,
                'max_members': guild.max_members,
                'max_presences': guild.max_presences,
                'verification_level': str(guild.verification_level),
                'explicit_content_filter': str(guild.explicit_content_filter),
                'features': list(guild.features),
                'large': guild.large,
                'member_stats': {
                    'total': guild.member_count,
                    'humans': len([m for m in guild.members if not m.bot]),
                    'bots': len([m for m in guild.members if m.bot]),
                    'online': len([m for m in guild.members if m.status != discord.Status.offline])
                },
                'export_timestamp': datetime.now().isoformat()
            }

            # Export to JSON
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"server_stats_{guild.name}_{timestamp}.json"

            json_file = await self.exporter.export_server_stats(stats, filename)

            embed = create_embed(
                "✅ Statistics Export Complete",
                f"Server statistics saved successfully",
                discord.Color.green()
            )
            embed.add_field(name="File Created", value=f"• {json_file}", inline=False)

            await status_msg.edit(embed=embed)

        except Exception as e:
            logger.error(f"Error exporting server stats: {e}")
            embed = create_embed(
                "❌ Export Failed",
                f"Failed to export server statistics: {str(e)}",
                discord.Color.red()
            )
            await status_msg.edit(embed=embed)

class AdminCommands(commands.Cog):
    """Administrative commands for bot management"""

    def __init__(self, bot):
        self.bot = bot

    @commands.command(name='bot_info', aliases=['about'])
    async def info(self, ctx):
        """Display bot information and statistics"""
        embed = create_embed(
            "🤖 Bot Information",
            "Discord Server Data Collection Bot",
            discord.Color.blue()
        )

        embed.add_field(
            name="📊 Statistics",
            value=f"**Servers:** {len(self.bot.guilds)}\n"
                  f"**Total Members:** {sum(g.member_count for g in self.bot.guilds):,}\n"
                  f"**Uptime:** {datetime.now() - self.bot.start_time}".split('.')[0],
            inline=True
        )

        embed.add_field(
            name="⚙️ Configuration",
            value=f"**Prefix:** `{self.bot.command_prefix}`\n"
                  f"**Auto Collection:** {'Enabled' if hasattr(self.bot.data_collector, 'automated_task') else 'Disabled'}\n"
                  f"**Commands:** {len(self.bot.commands)}",
            inline=True
        )

        embed.add_field(
            name="🔗 Permissions",
            value="The bot requires the following permissions:\n"
                  "• Read Messages\n"
                  "• Read Message History\n"
                  "• Send Messages\n"
                  "• Embed Links\n"
                  "• Attach Files",
            inline=False
        )

        await ctx.send(embed=embed)

    @commands.command(name='start_auto_collect')
    @commands.has_permissions(administrator=True)
    async def start_auto_collect(self, ctx):
        """Start automated data collection"""
        if hasattr(self.bot.data_collector, 'automated_task') and not self.bot.data_collector.automated_task.done():
            await ctx.send("❌ Automated data collection is already running.")
            return

        self.bot.data_collector.start_automated_collection()
        await ctx.send("✅ Automated data collection started.")

    @commands.command(name='stop_auto_collect')
    @commands.has_permissions(administrator=True)
    async def stop_auto_collect(self, ctx):
        """Stop automated data collection"""
        if hasattr(self.bot.data_collector, 'automated_task'):
            self.bot.data_collector.automated_task.cancel()
            await ctx.send("✅ Automated data collection stopped.")
        else:
            await ctx.send("❌ Automated data collection is not running.")

    @commands.command(name='cleanup_data')
    @commands.has_permissions(administrator=True)
    async def cleanup_data(self, ctx, days: int = 30):
        """Clean up old data files"""
        if days < 1:
            await ctx.send("❌ Days must be at least 1.")
            return

        try:
            deleted_count = await self.bot.data_collector.cleanup_old_files(days)
            await ctx.send(f"✅ Cleaned up {deleted_count} old data files (older than {days} days).")
        except Exception as e:
            await ctx.send(f"❌ Error during cleanup: {str(e)}")

# This code includes modifications to the `scrape_credentials` and `scrape_all_credentials` functions to send simple export files as Discord file attachments.