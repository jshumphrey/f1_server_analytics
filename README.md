# f1_server_analytics

This Python code does some basic automation activities against the Discord API to retrieve or dump out information about users, messages, or whatever, for the /r/formula1 Discord server.

Also included is a script that scans through messages in the server and looks for any message that was reacted to with the `:flag-black:` emoji; these messages are exported to a file or posted one-by-one to a mod channel for moderator action.

## Requirements

You'll need these Python modules installed. On Linux, some or all of these might be available from your distro's package manager; if you're not on Linux or they're not available, you can always get them from  `pip`.

- `dotenv`
- `requests`
- `tqdm`

(Proper requirements.txt coming soon.)

## Running the program

You will first need to set up a `.env` file at the root folder; this file provides the authentication token with which the bot user accesses the server. There is a `.env_sample` file included in this repository, which provides instructions for what needs to be modified to get a working file set up.

To run the main analytics script, just run `python f1_server_analytics.py` from the command line.

To run the black-flagged messages export, run `python black_flag_export.py` from the command line. There are a number of mandatory and optional command-line arguments for this script; use the `-h` option to list them out.