#! /usr/bin/env python
'''This is a script that can be run on a scheduler to generate an export of
messages in certain channels that were reacted to with the :flag-black-1: emoji.'''

import f1_server_analytics as f1sa
import argparse, csv, datetime, logging
from tqdm import tqdm

BLACK_FLAG_EMOJI_ID = "299650191835922432"

CHANNELS_TO_SEARCH = [f1sa.F1_GENERAL_CHANNEL_ID, f1sa.BLACK_FLAG_CHANNEL_ID]

logger = logging.getLogger("f1discord")

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
    return parser.parse_args()

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

def post_flagged_messages(connection, flagged_messages, progress_bar = True):
    '''This posts a message in #black-flag-queue for each of the flagged messages.'''
    for message in tqdm(flagged_messages, desc = "Sending flagged messages to #black-flag-queue", disable = not progress_bar):
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
                    f"**Black-flagged by:** {message['flagger']['username']}#{message['flagger']['discriminator']}"
                ),
                "footer": {"text": f"User ID: {message['author']['id']} - Message ID: {message['id']}"}
            }],
        }
        connection.send_message(channel_id = f1sa.BLACK_FLAG_CHANNEL_ID, message_dict = message_dict)

def main():
    '''Handle top-level functionality.'''
    args = get_arguments()
    time_args = {
        arg_name: int(arg_value)
        for arg_name, arg_value in vars(args).items()
        if arg_name in ["weeks", "days", "hours", "minutes", "seconds"]
        and arg_value is not None
    }
    if not time_args:
        raise ValueError("At least one of '--weeks', '--days', '--hours', '--minutes', or '--seconds' is required.")
    total_time = datetime.timedelta(**time_args)

    with f1sa.Connection(f1sa.TOKEN) as c:
        flagged_messages = []
        for channel_id in CHANNELS_TO_SEARCH:
            flagged_messages += c.get_reacted_messages(
                channel_id = channel_id,
                emoji_text = "flag_black",
                after_dt = datetime.datetime.now() - total_time,
                progress_bar = not args.quiet
            )

        if not flagged_messages:
            if not args.quiet:
                print("No messages were black-flagged in the specified time window.")
            return # Exit out.

        for message in tqdm(flagged_messages, desc = "Processing flagged messages", disable = args.quiet):
            reacted_users = c.get_reaction_users(
                channel_id = message["channel_id"],
                message_id = message["id"],
                emoji_name = "flag_black",
                emoji_id = BLACK_FLAG_EMOJI_ID,
                progress_bar = False
            )
            message["flagger"] = reacted_users[0]

        if args.export_method == "file":
            export_flagged_messages(flagged_messages)
        else:
            post_flagged_messages(c, flagged_messages, progress_bar = not args.quiet)

if __name__ == "__main__":
    main()
