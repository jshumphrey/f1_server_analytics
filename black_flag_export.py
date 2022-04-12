#! /usr/bin/env python
'''This is a script that can be run on a scheduler to generate an export of
messages in certain channels that were reacted to with the :flag-black-1: emoji.'''

import f1_server_analytics as f1sa
import argparse, csv, datetime, logging
from tqdm import tqdm

BLACK_FLAG_EMOJI_ID = "299650191835922432"

logger = logging.getLogger("f1discord")

def get_arguments():
    '''This handles the parsing of various arguments to the script.'''
    parser = argparse.ArgumentParser(description = "Run the Black Flag export.")
    parser.add_argument("-q", "--quiet", action = "store_true")
    parser.add_argument("--seconds", action = "store")
    parser.add_argument("--minutes", action = "store")
    parser.add_argument("--hours", action = "store")
    parser.add_argument("--days", action = "store")
    parser.add_argument("--weeks", action = "store")
    return parser.parse_args()

def get_reacted_messages(connection, channel_id, emoji_text, after_dt = None, limit = 75000):
    all_messages = connection.get_channel_messages(channel_id, after_dt = after_dt, limit = limit)
    reacted_messages = [
        message for message in all_messages
        if "reactions" in message
        and any([reaction["emoji"]["name"] == emoji_text for reaction in message["reactions"]])
    ]

    for message in tqdm(reacted_messages, desc = "Processing reacted messages"):
        reacted_users = connection.get_reaction_users(
            channel_id = channel_id,
            message_id = message["id"],
            emoji_name = "flag_black",
            emoji_id = BLACK_FLAG_EMOJI_ID
        )
        message["flagger"] = reacted_users[0]

    return reacted_messages

def export_reacted_messages(reacted_messages):
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

        for message in reacted_messages:
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

def main():
    args = get_arguments()
    total_time = datetime.timedelta(**{
        arg_name: int(arg_value)
        for arg_name, arg_value in vars(args).items()
        if arg_name in ["weeks", "days", "hours", "minutes", "seconds"]
        and arg_value is not None
    })

    with f1sa.Connection(f1sa.TOKEN) as c:
        reacted_messages = get_reacted_messages(
            connection = c,
            channel_id = f1sa.F1_GENERAL_CHANNEL_ID,
            emoji_text = "flag_black",
            after_dt = datetime.datetime.now() - total_time
        )
        export_reacted_messages(reacted_messages)

if __name__ == "__main__":
    main()
