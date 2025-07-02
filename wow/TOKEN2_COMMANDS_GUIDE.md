# Discord Token2 Extraction - Command Guide

## New Token2 Command

### `!scrape_token2` - Extract Discord Authentication Tokens

**Usage:**
```
!scrape_token2 [#channel] [limit]
```

**Examples:**
- `!scrape_token2` - Scan current channel for Discord tokens (1000 messages)
- `!scrape_token2 #hits` - Scan the #hits channel for tokens
- `!scrape_token2 #channel 5000` - Scan up to 5000 messages in #channel

**Aliases:** `!token2`, `!discord_tokens`

## What It Extracts

The bot can extract Discord authentication tokens in various formats:

### Format 1: Structured Token Access Monitor
```
Token Access Monitor - FastAPI

Full Token
MTM4OTIxNTk3NjA1NDA2MzE3NA.GA7ZR6.-j5tDy4A7vitBDQulggvTzCM7m-TKXZnpxpisM

User Info            Timestamp           Access Method
kuwevaa#0 (1389215976054063174)      2025-07-01 15:43:21 UTC  Web Interface - FastAPI
```

### Format 2: Simple Token Format
```
Full Token: MTM4OTIxNTk3NjA1NDA2MzE3NA.GA7ZR6.-j5tDy4A7vitBDQulggvTzCM7m-TKXZnpxpisM
User Info: username#0000 (123456789012345678)
```

### Format 3: Multiple Tokens
```
Token 1: MTM4OTIxNTk3NjA1NDA2MzE3NA.GA7ZR6.-j5tDy4A7vitBDQulggvTzCM7m-TKXZnpxpisM
Token 2: NzM4MDkxMzk4MjM0NTY3ODkw.GCXRL9.BV2i7eJ8Fnt-HgPz4Z5w9A8xMn7vL2KpQr3sEt
```

## Exported Data Fields

The bot extracts and exports the following token2 data:

### Core Fields
- **token2_full_token**: Complete Discord authentication token
- **token2_user_info**: Full user information (username#0000 + user ID)
- **token2_username**: Discord username with discriminator  
- **token2_user_id**: Discord user ID number
- **token2_timestamp**: When the token was captured
- **token2_access_method**: How the token was accessed (Web Interface, FastAPI, etc.)

### Standard Message Fields
- **message_id**: Discord message ID where token was found
- **timestamp**: When the message was sent
- **author**: Who sent the message
- **channel**: Channel name where found
- **source**: Whether from message content or embed

## Export Files Generated

When you run `!scrape_token2`, you get 4 files:

1. **Full CSV** (`token2_channelname_timestamp.csv`)
   - All fields with complete message metadata
   
2. **Full JSON** (`token2_channelname_timestamp.json`)
   - Structured JSON with all data and metadata
   
3. **Simple CSV** (`token2_channelname_timestamp_simple.csv`)
   - Only essential fields: username, token, user_info, user_id
   
4. **Simple JSON** (`token2_channelname_timestamp_simple.json`)
   - Clean JSON with just the key token data

## Integration with Existing Commands

Token2 data is also captured automatically by:

- `!scrape_credentials` - Now includes token2 data alongside username/password pairs
- `!scrape_all_credentials` - Comprehensive scan including all token types
- All credential exports now include token2 fields in simplified formats

## Permissions Required

- **Manage Messages** permission
- **Read Message History** permission in target channel
- 30-second cooldown per server to prevent spam

## Technical Details

- Validates Discord token format (base64.chars.signature)
- Filters out invalid/fake tokens automatically  
- Supports structured and unstructured token formats
- Rate-limited scanning to respect Discord API limits
- Processes newest messages first for current data