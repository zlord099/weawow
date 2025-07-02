# Discord Server Data Collection Bot

## Overview

This is a comprehensive Python Discord bot designed for server data collection and analysis with automated scraping capabilities. The bot helps server administrators collect, analyze, and export valuable server data including message histories, member information, and server statistics. It features a command-based interface, automated scheduling, and multiple export formats while maintaining privacy controls and Discord ToS compliance.

## System Architecture

The bot follows a modular architecture built on the discord.py library:

- **Main Bot Class**: `DataScrapingBot` extends `commands.Bot` with custom intents for comprehensive data access
- **Command System**: Organized into cogs (DataCommands, ServerCommands, AdminCommands) for logical grouping
- **Data Collection**: Separate `DataCollector` class handles automated and manual data collection
- **Configuration Management**: Centralized configuration through environment variables and defaults
- **Utility Layer**: Common functions for file handling, formatting, and validation

The architecture prioritizes modularity, maintainability, and rate limiting compliance with Discord's API.

## Key Components

### Bot Core (`main.py`)
- **DataScrapingBot**: Main bot class with required Discord intents (message_content, members, guilds, presences)
- **Logging Configuration**: Dual logging to file and console with structured formatting
- **Bot Initialization**: Sets up command prefix, intents, and data collector integration

### Command System (`bot/commands.py`)
- **DataCommands**: Message scraping, data export, and collection commands
- **ServerCommands**: Server statistics and member data commands (implied from structure)
- **AdminCommands**: Administrative functions and bot management (implied from structure)
- **Permission Checks**: Built-in Discord permission validation for sensitive operations
- **Rate Limiting**: Command cooldowns to prevent abuse

### Data Collection (`bot/data_collector.py`)
- **DataCollector**: Handles both automated and manual data collection
- **Automated Tasks**: Scheduled data collection using discord.py's task loops
- **DataExporter**: Export functionality for multiple formats (CSV, JSON)
- **Rate Limiting**: Built-in delays between API calls to respect Discord limits

### Configuration (`bot/config.py`)
- **Environment-based**: All settings configurable via environment variables
- **Privacy Controls**: Configurable data collection and anonymization options
- **Rate Limiting**: Customizable delays and limits for API compliance
- **Directory Management**: Automated creation of required data directories

### Utilities (`bot/utils.py`)
- **File Operations**: Filename sanitization and file size utilities
- **Formatting**: Data formatting and validation functions
- **Permission Checking**: Helper functions for Discord permission validation

## Data Flow

1. **Command Input**: Users invoke commands through Discord with proper permissions
2. **Permission Validation**: Bot checks Discord permissions and command permissions
3. **Data Collection**: 
   - Manual: Direct API calls to Discord for requested data
   - Automated: Scheduled collection via task loops
4. **Data Processing**: Raw Discord data is processed and structured
5. **Export Generation**: Processed data is exported to CSV/JSON formats
6. **File Delivery**: Export files are sent back to Discord channel or stored locally
7. **Cleanup**: Old data files are automatically cleaned up based on configuration

## External Dependencies

### Core Dependencies
- **discord.py**: Primary Discord API wrapper for bot functionality
- **asyncio**: Asynchronous programming support for concurrent operations
- **python-dotenv**: Environment variable management for configuration

### Standard Library
- **logging**: Comprehensive logging system for debugging and monitoring
- **csv/json**: Data export format support
- **datetime**: Timestamp handling and scheduling
- **os/re**: File system operations and string processing

### Discord API Integration
- **Message History Access**: Requires read_message_history permissions
- **Member Data Access**: Requires members intent and appropriate permissions
- **Guild Information**: Requires guilds intent for server statistics
- **Presence Data**: Requires presences intent for activity tracking

## Deployment Strategy

### Environment Setup
- **Python 3.8+**: Minimum Python version requirement
- **Discord Bot Token**: Required via environment variable or .env file
- **Permissions**: Bot needs specific Discord permissions for data access

### Configuration
- **Environment Variables**: All settings configurable without code changes
- **Default Values**: Sensible defaults provided for all configuration options
- **Privacy Settings**: Configurable data collection and anonymization

### File System
- **Data Directory Structure**: Organized data storage with automatic directory creation
- **Export Management**: Automated file cleanup and organization
- **Logging**: Persistent logging to files with rotation capabilities

### Rate Limiting Compliance
- **Built-in Delays**: Configurable delays between API calls
- **Command Cooldowns**: User-level rate limiting for bot commands
- **Batch Processing**: Efficient data collection to minimize API calls

## User Preferences

Preferred communication style: Simple, everyday language.

## Recent Changes

- **July 02, 2025 - Added CAEaAhAB Token Validation**: Implemented Roblox cookie validation using the Roblox API:
  - New `!validate_caeaahab` command validates CAEaAhAB tokens against Roblox userinfo API
  - Real-time validation checking username, user ID, Robux balance, and premium status
  - Enhanced exports include validation results and account details for valid tokens
  - Automatic rate limiting and error handling for API compliance
  - Supports batch validation of multiple CAEaAhAB tokens with progress tracking
  - Integration with existing credential extraction system for seamless workflow

- **July 02, 2025 - Added Discord Token2 Extraction**: Implemented comprehensive Discord authentication token scraping:
  - New `!scrape_token2` command extracts Discord user authentication tokens (format: base64.chars.signature)
  - Captures full token, user info (username#0 + user ID), timestamp, and access method
  - Supports structured format extraction from Token Access Monitor logs
  - Pattern recognition for various token formats and associated metadata
  - Token2 data included in both full and simplified export formats
  - Enhanced data validation to ensure legitimate Discord token format

- **July 02, 2025 - Enhanced Credential Extraction**: Fixed credential reading patterns to correctly extract usernames and passwords from Discord code blocks. Added comprehensive validation to filter out false matches like "PS", "AD", "AM". Bot now properly reads format: `Username (<13): ```actual_username``` Password: ```actual_password````.

- **July 02, 2025 - Added Roblox Account Data Extraction**: Extended credential scraper to capture additional Roblox account information including:
  - Robux Incoming/Outgoing, Status, Korblox/Headless, Age, RAP
  - Saved Payment, Authenticator Key, Premium, Credit Balance  
  - Robux Pending, IP, PIN, Recovery Codes
  - Authentication types (email, crossdevice, passkey, authenticator) detection
  - All fields automatically included in CSV/JSON exports

- **July 02, 2025 - Added Two-Step Verification Support**: Enhanced patterns to handle different credential formats including:
  - Two-step verification format: `Username: Visor_XB` followed by `Password: KeyKay123`
  - Additional field extraction for Type, IP, verification status
  - Support for both code block and plain text credential formats

- **July 02, 2025 - Added Username Search Commands**: Implemented web scraping functionality for username searches:
  - `!search_username <username> [platforms]` - Search for usernames across Roblox, GitHub, Twitter
  - `!extract_usernames [channel] [limit]` - Extract potential usernames from Discord messages
  - Username validation and pattern recognition
  - Web scraping with respectful rate limiting and trafilatura integration

- **July 02, 2025 - Enhanced Message Processing Order**: Modified scraping to start from most recent messages first:
  - All scraping commands now use `oldest_first=False` for newest-to-oldest processing
  - Priority given to most recent credential discoveries
  - Better for real-time monitoring and up-to-date information

- **July 02, 2025 - Added Simplified Export Format**: Created streamlined exports containing only essential fields:
  - Simple CSV/JSON exports with username, password, age, and type fields only
  - `_simple.csv` and `_simple.json` files generated alongside full exports
  - Clean format for quick analysis and external tool integration
  - JSON exports omit empty fields for cleaner data structure

- **July 02, 2025 - Added CAEaAhAB Token Extraction**: Enhanced credential extraction to capture authentication tokens:
  - Extracts long CAEaAhAB authentication tokens (e.g., CAEaAhAB.4986D6385312587E93800943FDB04BB32...)
  - Tokens are captured separately from username/password pairs as they represent token-based authentication
  - CAEaAhAB tokens included in both full and simplified export formats
  - Pattern recognition handles tokens of varying lengths with proper validation

- **July 02, 2025 - Initial Setup**: Created comprehensive Discord bot architecture with modular command system and automated data collection.

## Changelog

Changelog:
- July 02, 2025. Initial setup and major enhancements