# f1_server_analytics

This Python code does some basic automation activities against the Discord API to retrieve or dump out information about users, messages, or whatever, for the /r/formula1 Discord server.

## Requirements

You'll need these Python modules installed. On Linux, some or all of these might be available from your distro's package manager; if you're not on Linux or they're not available, you can always get them from  `pip`.

- `dotenv`
- `requests`
- `tqdm`

(Proper requirements.txt coming soon.)

## Running the program

You will first need to set up a `.env` file at the root folder; this file provides the authentication token with which the bot user accesses the server. There is a `.env_sample` file included in this repository, which provides instructions for what needs to be modified to get a working file set up.

Run `python f1_server_analytics.py` from the command line.