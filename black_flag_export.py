#! /usr/bin/env python
'''This is a script that can be run on a scheduler to generate an export of
messages in certain channels that were reacted to with the :flag-black-1: emoji.'''

import f1_server_analytics as f1sa
import argparse, csv, datetime, logging, re
from tqdm import tqdm

BLACK_FLAG_EMOJI_NAME = "flag_black"
BLACK_FLAG_EMOJI_ID = "299650191835922432"

CHANNELS_TO_SEARCH = [f1sa.F1_GENERAL_CHANNEL_ID]
REPORTED_MESSAGE_CHANNELS = [
    f1sa.BLACK_FLAG_QUEUE_CHANNEL_ID,
    f1sa.MODERATION_QUEUE_CHANNEL_ID,
    f1sa.MOD_QUEUE_ARCHIVE_CHANNEL_ID,
]

NUM_FLAGGERS_LIMIT = 3 # Maximum number of flagging users to list out. The rest will be under "and # others"

logging.basicConfig()
logger = logging.getLogger("black_flag_export")

def get_arguments():
    '''This handles the parsing of various arguments to the script.'''
    parser = argparse.ArgumentParser(description = "Run the Black Flag export.")
    parser.add_argument("export_method", choices = ["channel", "file"])
    parser.add_argument("--seconds", action = "store")
    parser.add_argument("--minutes", action = "store")
    parser.add_argument("--hours", action = "store")
    parser.add_argument("--days", action = "store")
    parser.add_argument("--weeks", action = "store")
    parser.add_argument("-q", "--quiet", action = "store_true")
    parser.add_argument("--no-progress", action = "store_true")
    parser.add_argument("--verbose", action = "store_true")
    return parser.parse_args()

def calculate_total_time(arguments):
    '''This parses the arguments provided to the script to calculate the requisite time delta.'''
    time_args = {
        arg_name: int(arg_value)
        for arg_name, arg_value in vars(arguments).items()
        if arg_name in ["weeks", "days", "hours", "minutes", "seconds"]
        and arg_value is not None
    }
    if not time_args:
        raise ValueError("At least one of '--weeks', '--days', '--hours', '--minutes', or '--seconds' is required.")

    return datetime.timedelta(**time_args)

def get_flagged_messages(connection, channel_ids, after_dt, progress_bar = True):
    '''This sweeps through the channel_ids provided and returns a list of messages that were black-flagged.'''
    # First, get a list of all message IDs that have already been reported. We don't want to return these.
    reported_message_ids = get_reported_message_ids(
        connection = connection,
        channel_ids = REPORTED_MESSAGE_CHANNELS,
        after_dt = after_dt - datetime.timedelta(minutes = 5), # Allow some extra time when looking for reports.
        progress_bar = progress_bar
    )
    logger.debug(f"Found that message IDs {', '.join(reported_message_ids)} have already been reported since {after_dt - datetime.timedelta(minutes = 5)!s}")

    # Next, sweep each of the provided channels for any messages that got black-flagged.
    flagged_messages = []
    for channel_id in channel_ids:
        flagged_messages += [
            message for message in connection.get_reacted_messages(
                channel_id = channel_id,
                emoji_text = BLACK_FLAG_EMOJI_NAME,
                after_dt = after_dt,
                progress_bar = progress_bar
            )
            if message["id"] not in reported_message_ids # Exclude messages that have already been reported.
            and message["author"]["id"] not in f1sa.MOD_USER_IDS # Exclude messages sent by mods.
        ]

    # Finally, retrieve some extra information for the flagged messages, to find out _who_ flagged them.
    for message in tqdm(flagged_messages, desc = "Processing flagged messages", disable = not progress_bar):
        message["flaggers"] = connection.get_reaction_users(
            channel_id = message["channel_id"],
            message_id = message["id"],
            emoji_name = BLACK_FLAG_EMOJI_NAME,
            emoji_id = BLACK_FLAG_EMOJI_ID,
            progress_bar = False # Don't set this based on the "no_progress" arg - it's ALWAYS too noisy in this use-case.
        )
        logger.debug(f"Found new black-flagged message ID {message['id']}, sent by {message['author']['username']}#{message['author']['discriminator']}")

    return flagged_messages

def get_reported_message_ids(connection, channel_ids, after_dt, progress_bar = True):
    '''This returns a list of Message IDs that have already been reported - either by this script, or by
    the Formula One bot. We can use this to avoid exporting messages that have already been reported.'''
    all_messages = []
    for channel_id in tqdm(channel_ids, desc = "Scanning channels for reported messages", disable = not progress_bar):
        all_messages += connection.get_channel_messages(
            channel_id = channel_id,
            after_dt = after_dt,
            progress_bar = False # This is ALWAYS too noisy in this use-case.
        )

    return [
        match for message in all_messages
        if "embeds" in message # Don't trigger on a normal message
        and message["embeds"] # Really, don't trigger on a normal message, even if it has an embed
        and "footer" in message["embeds"][0] # Seriously, actually, only trigger on the messages for reports
        and (match := re.search(r'Message ID: ([0-9]+)', message["embeds"][0]["footer"]["text"]).group(1))
    ]

def export_flagged_messages(flagged_messages):
    '''This exports all of the retrieved messages with information about the message and who reacted to it.'''
    with open("black_flag_messages.csv", "w") as outfile:
        writer = csv.writer(outfile, delimiter = ",", quotechar = '"')
        writer.writerow([
            "Message Channel",
            "Message Timestamp (UTC)",
            "Message Link",
            "Message Author Name",
            "Message Author ID",
            "Message Text",
            "Flagging User Name",
            "Flagging User ID",
        ])

        for message in flagged_messages:
            writer.writerow([
                "f1-general",
                message["timestamp"][:19].replace("T", " "),
                f"https://discord.com/channels/{f1sa.F1_GUILD_ID}/{f1sa.F1_GENERAL_CHANNEL_ID}/{message['id']}",
                f"{message['author']['username']}#{message['author']['discriminator']}",
                message["author"]["id"],
                message["content"],
                f"{message['flagger']['username']}#{message['flagger']['discriminator']}",
                message["flagger"]["id"],
            ])

        logger.debug(f"Wrote {len(flagged_messages)!s} records to black_flag_messages.csv")

def post_flagged_messages(connection, flagged_messages, progress_bar = True):
    '''This posts a message in #black-flag-queue for each of the flagged messages.'''
    for message in tqdm(flagged_messages, desc = "Sending flagged messages to #black-flag-queue", disable = not progress_bar):
        flagging_users = ", ".join([f"{user['username']}#{user['discriminator']}" for user in message["flaggers"][:NUM_FLAGGERS_LIMIT]])
        flagging_users += '' if len(message['flaggers']) <= NUM_FLAGGERS_LIMIT else f", and {str(len(message['flaggers']) - NUM_FLAGGERS_LIMIT)} others"

        message_dict = {
            "content": "",
            "embeds": [{
                "type": "rich",
                "author": {
                    "name": f"{message['author']['username']}#{message['author']['discriminator']}",
                    "icon_url": f"https://cdn.discordapp.com/avatars/{message['author']['id']}/{message['author']['avatar']}.webp"
                },
                "description": (
                    f"Sent a message in <#{message['channel_id']}> that was black-flagged. "
                    f"[Jump to message](https://discord.com/channels/{f1sa.F1_GUILD_ID}/{message['channel_id']}/{message['id']})\n\n"
                    f"**Message:** {message['content']}\n\n"
                    f"**Black-flagged by:** {flagging_users}"
                ),
                "footer": {"text": f"User ID: {message['author']['id']} - Message ID: {message['id']}"}
            }],
        }
        connection.send_message(channel_id = f1sa.BLACK_FLAG_QUEUE_CHANNEL_ID, message_dict = message_dict)
        logger.debug(f"Successfully sent a Discord message for message ID {message['id']}")

def main():
    '''Handle top-level functionality.'''
    args = get_arguments()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.WARNING)

    total_time = calculate_total_time(args)

    with f1sa.Connection(f1sa.TOKEN) as connection:
        flagged_messages = get_flagged_messages(
            connection = connection,
            channel_ids = CHANNELS_TO_SEARCH,
            after_dt = datetime.datetime.now() - total_time,
            progress_bar = not args.no_progress
        )

        if flagged_messages:
            if args.export_method == "file":
                export_flagged_messages(flagged_messages)
            else:
                post_flagged_messages(connection, flagged_messages, progress_bar = not args.no_progress)
        else:
            logger.info("No messages were black-flagged in the specified time window.")

if __name__ == "__main__":
    main()
