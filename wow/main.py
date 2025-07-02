#!/usr/bin/env python3
"""
Discord Data Collection Bot
A comprehensive Discord bot for server data collection and analysis
"""

import os
import asyncio
import logging
from datetime import datetime
import discord
from discord.ext import commands

from bot.config import BotConfig
from bot.commands import setup_commands
from bot.data_collector import DataCollector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DataScrapingBot(commands.Bot):
    """Main Discord bot class for data collection"""
    
    def __init__(self):
        # Configure required intents for data collection
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        intents.guilds = True
        intents.presences = True
        
        super().__init__(
            command_prefix=BotConfig.COMMAND_PREFIX,
            intents=intents,
            description="Discord Server Data Collection Bot"
        )
        
        self.data_collector = DataCollector(self)
        self.start_time = datetime.now()
        
    async def setup_hook(self):
        """Initialize bot components"""
        try:
            # Setup command groups
            await setup_commands(self)
            
            # Start automated data collection
            if BotConfig.AUTO_COLLECT_DATA:
                self.data_collector.start_automated_collection()
                logger.info("Automated data collection started")
            
            logger.info("Bot setup completed successfully")
            
        except Exception as e:
            logger.error(f"Error during bot setup: {e}")
            raise
    
    async def on_ready(self):
        """Event fired when bot is ready"""
        logger.info(f'{self.user} has connected to Discord!')
        logger.info(f'Bot is in {len(self.guilds)} guilds')
        
        # Set presence
        activity = discord.Activity(
            type=discord.ActivityType.watching,
            name=f"{len(self.guilds)} servers | {BotConfig.COMMAND_PREFIX}help"
        )
        await self.change_presence(activity=activity)
        
        # Log guild information
        for guild in self.guilds:
            logger.info(f"Connected to guild: {guild.name} (ID: {guild.id})")
    
    async def on_guild_join(self, guild):
        """Event fired when bot joins a new guild"""
        logger.info(f"Joined new guild: {guild.name} (ID: {guild.id})")
        
        # Update presence
        activity = discord.Activity(
            type=discord.ActivityType.watching,
            name=f"{len(self.guilds)} servers | {BotConfig.COMMAND_PREFIX}help"
        )
        await self.change_presence(activity=activity)
    
    async def on_guild_remove(self, guild):
        """Event fired when bot leaves a guild"""
        logger.info(f"Left guild: {guild.name} (ID: {guild.id})")
        
        # Update presence
        activity = discord.Activity(
            type=discord.ActivityType.watching,
            name=f"{len(self.guilds)} servers | {BotConfig.COMMAND_PREFIX}help"
        )
        await self.change_presence(activity=activity)
    
    async def on_command_error(self, ctx, error):
        """Global error handler for commands"""
        if isinstance(error, commands.CommandNotFound):
            return  # Ignore command not found errors
        
        elif isinstance(error, commands.MissingPermissions):
            await ctx.send("❌ You don't have the required permissions to use this command.")
        
        elif isinstance(error, commands.BotMissingPermissions):
            await ctx.send("❌ I don't have the required permissions to execute this command.")
        
        elif isinstance(error, commands.CommandOnCooldown):
            await ctx.send(f"⏰ Command is on cooldown. Try again in {error.retry_after:.2f} seconds.")
        
        elif isinstance(error, commands.MissingRequiredArgument):
            await ctx.send(f"❌ Missing required argument: {error.param}")
        
        else:
            logger.error(f"Unhandled command error: {error}", exc_info=True)
            await ctx.send("❌ An unexpected error occurred while processing the command.")
    
    async def on_message(self, message):
        """Event fired for every message"""
        # Ignore bot messages
        if message.author.bot:
            return
        
        # Log message activity if enabled
        if BotConfig.LOG_MESSAGE_ACTIVITY:
            await self.data_collector.log_message_activity(message)
        
        # Process commands
        await self.process_commands(message)
    
    async def close(self):
        """Cleanup when bot shuts down"""
        logger.info("Bot is shutting down...")
        
        # Stop automated data collection
        if hasattr(self.data_collector, 'automated_task') and self.data_collector.automated_task:
            self.data_collector.automated_task.cancel()
        
        await super().close()

def main():
    """Main entry point"""
    # Check for bot token
    token = os.getenv('DISCORD_BOT_TOKEN')
    if not token:
        logger.error("DISCORD_BOT_TOKEN environment variable not found!")
        logger.error("Please set your Discord bot token in the environment variables.")
        return
    
    # Create and run bot
    bot = DataScrapingBot()
    
    try:
        # Run the bot
        bot.run(token)
    except discord.LoginFailure:
        logger.error("Invalid bot token provided!")
    except Exception as e:
        logger.error(f"Failed to start bot: {e}")

if __name__ == "__main__":
    main()
