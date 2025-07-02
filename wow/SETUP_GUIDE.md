# Discord Bot Setup Guide

Your Discord data collection bot is ready! Follow these steps to get it running:

## Step 1: Enable Privileged Intents

Your bot needs special permissions called "privileged intents" to access member data and message content.

1. Go to https://discord.com/developers/applications
2. Select your bot application
3. Click on "Bot" in the left sidebar
4. Scroll down to "Privileged Gateway Intents"
5. Enable these three options:
   - ✅ **Presence Intent** - To see who's online
   - ✅ **Server Members Intent** - To access member information  
   - ✅ **Message Content Intent** - To read message content

6. Click "Save Changes"

## Step 2: Invite Bot to Your Server

1. Still in the Discord Developer Portal, click "OAuth2" → "URL Generator"
2. Under "Scopes" check: ✅ **bot**
3. Under "Bot Permissions" check:
   - ✅ Read Messages
   - ✅ Read Message History
   - ✅ Send Messages
   - ✅ Embed Links
   - ✅ Attach Files
   - ✅ Manage Messages (for admin commands)

4. Copy the generated URL and open it in your browser
5. Select your server and click "Authorize"

## Step 3: Test Your Bot

Once the bot joins your server, try these commands:

- `!bot_info` - Check if the bot is working
- `!server_stats` - View server statistics
- `!scrape_messages #channel-name 100` - Scrape 100 messages from a channel
- `!export_members` - Export member data (requires Manage Server permission)

## Available Commands

### Data Collection
- `!scrape_messages #channel [limit]` - Scrape messages from a channel
- `!export_members` - Export all member data to files
- `!server_stats` - Show comprehensive server statistics
- `!export_stats` - Save server statistics to file

### Bot Management  
- `!bot_info` - Display bot information and status
- `!start_auto_collect` - Start automated data collection
- `!stop_auto_collect` - Stop automated data collection
- `!cleanup_data [days]` - Clean up old data files

## Privacy Settings

The bot respects privacy. You can configure what data it collects by setting these environment variables:

- `COLLECT_USER_IDS=true/false` - Whether to save user IDs
- `COLLECT_MESSAGE_CONTENT=true/false` - Whether to save message text
- `ANONYMIZE_USERS=true/false` - Whether to anonymize usernames
- `AUTO_COLLECT_DATA=true/false` - Whether to run daily automated collection

## Troubleshooting

**Bot appears offline:** Make sure privileged intents are enabled in Step 1

**Permission errors:** Ensure the bot has the right permissions in your server

**Rate limit warnings:** The bot includes built-in rate limiting, but heavy usage may trigger Discord's limits

**Missing data:** Some features require specific permissions - check that the bot can read message history and access member information

Your bot will save all exported data to the `data/exports/` folder as both CSV and JSON files.