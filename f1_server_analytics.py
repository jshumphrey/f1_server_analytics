#! /usr/bin/env python
'''This is a standalone script to dump out information about the F1 Discord server and its users.'''

import csv, datetime, dotenv, logging, os, requests, time # pylint: disable = unused-import
from tqdm import tqdm # pylint: disable = unused-import

# Configure the logger so that we have a logger object to use.
logging.basicConfig(level = logging.INFO)
logger = logging.getLogger("f1discord")

dotenv.load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")

DISCORD_EPOCH = 1420070400000

URL_BASE = "https://discord.com/api/v9"
BASE_SLEEP_DELAY = 1.0 # This is the number of seconds to sleep between requests.
MAX_FAILURES = 5

SHADOW_USER_ID = "480338490639384576"
F1_GUILD_ID = "177387572505346048"
ANNOUNCEMENTS_CHANNEL_ID = "361137849736626177"
LOGS_CHANNEL_ID = "273927887034515457"
F1_LOGS_CHANNEL_ID = "447397947261452288"

MOD_APPLICATION_MESSAGE_ID = "935642010419879957"

class Connection:
    '''This class wraps a requests Session, wraps the process of making a request via the
    Discord API (handling rate limits, etc.), and includes a number of methods that
    wrap some common individual requests.'''
    def __init__(self, token):
        self.session = requests.Session()
        self.session.headers = {
            "Authorization": "Bot " + token.strip(),
            "Content-Type": "application/json",
            "X-Ratelimit-Precision": "millisecond"
        }

        self.last_call = time.time()
        self.test_token()

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        '''This automatically closes the connection once the with/as is released.'''
        self.session.close()

    def test_token(self):
        '''This "tests" the token by trying to make a very simple request (requesting
        information about our own user). If this request fails, we know that the token
        is not valid, and the user needs to fix this before trying again.'''
        try:
            self.get_self()
            logging.info("Successfully retrieved data using the provided token!")
        except requests.HTTPError as ex:
            raise EnvironmentError("The token provided is not valid - Discord authentication failed!") from ex

    def bucket_sleep(self):
        '''This sleeps the script for the appropriate amount of time to avoid issues
        with the Discord rate limiter. Discord's rate limits are not actually static,
        so we might still hit the limiter (which is handled separately), but by baking
        in a basic delay between requests, we get a more stable average request time.'''
        time_since_last_call = round(time.time() - self.last_call, 4)
        time_to_sleep = max(BASE_SLEEP_DELAY - time_since_last_call, 0)
        if time_to_sleep > 0:
            logging.debug(f"It's only been {time_since_last_call!s} seconds since the last call, sleeping for {time_to_sleep!s}s")
            time.sleep(time_to_sleep)
        else:
            logging.debug(f"It's been {time_since_last_call!s} seconds since the last call, no need to sleep")

    def request_json(self, request_type, suburl, **kwargs):
        '''This wraps the process of making a request to a given URL, handling errors,
        and sleeping for the appropriate amount of time to avoid rate limits.
        If/when we receive a valid response, its JSON is returned.'''
        failures = 0
        while True:
            self.bucket_sleep()
            try:
                response = self.session.request(request_type, URL_BASE + suburl, **kwargs)
                response.raise_for_status() # Potential exit from the function - crash out due to a bad request
                return response.json() # Potential exit from the function - return the JSON of a valid response

            except requests.HTTPError as ex:
                if ex.response.status_code == 429:
                    time_to_sleep = ex.response.json()["retry_after"]
                    logging.info(f"Hit the Discord rate limiter; sleeping for {time_to_sleep!s} seconds")
                    time.sleep(time_to_sleep)
                else:
                    raise ex

            except (requests.ConnectionError, requests.Timeout) as ex:
                failures += 1
                logging.debug(f"Encountered a {type(ex)} when {request_type}ing {suburl}; {failures!s} failures so far")
                if failures >= MAX_FAILURES:
                    logging.debug(f"Encountered too many ConnectionErrors or Timeouts when {request_type}ing {suburl}; crashing out")
                    raise # Potential exit from the function - crash out due to too many ConnectionErrors or Timeouts

            finally:
                self.last_call = time.time()

    def get_self(self):
        '''This returns the JSON for the User associated to the current Connection.'''
        return self.request_json("GET", "/users/@me")

    def get_guild(self, guild_id):
        '''This returns the JSON for the Guild with the provided Guild ID.'''
        return self.request_json("GET", f"/guilds/{guild_id}")

    def get_roles(self, guild_id):
        '''This returns the JSON of the Roles for the Guild with the provided Guild ID.'''
        return self.request_json("GET", f"/guilds/{guild_id}/roles")

    def get_channel(self, channel_id):
        '''This returns the JSON for the Channel with the provided Channel ID.'''
        return self.request_json("GET", f"/channels/{channel_id}")

    def get_channel_messages(self, channel_id, before = None, after = None, limit = 15000):
        '''This yields the JSON of messages sent in the channel with the provided Channel ID,
        up to the number of messages in the "limit" argument.

        If the "before" or "after" arguments are provided (or both), only the messages before
        or after (or between) the provided Message ID(s) will be retrieved. If neither argument
        is provided, the most recent messages sent in the channel will be retrieved.'''
        messages = []
        channel = self.get_channel(channel_id)

        if after and before and after > before:
            raise ValueError("'after' cannot be greater than 'before'")

        direction_param = "after" if after else "before"
        default_message_id = after or before or generate_fake_message_id(datetime.datetime.now()) # Equivalent to SQL COALESCE()

        with tqdm(desc = f"Retrieving messages in #{channel['name']}", total = limit) as pbar:
            while True:
                response_messages = self.request_json(
                    request_type = "GET",
                    suburl = f"/channels/{channel_id}/messages",
                    params = {"limit": 100, direction_param: messages[-1]["id"] if messages else default_message_id}
                )
                if not response_messages:
                    return messages # We're completely out of messages; return the list

                response_messages.sort(key = lambda m: m["id"], reverse = direction_param == "before")
                for message in response_messages:
                    if after and before and message["id"] > before:
                        return messages # We've hit the end of our search range; return the list

                    messages.append(message)
                    pbar.update()

                    if len(messages) >= limit:
                        return messages # We've hit our limit of messages to pull; return the list

    def get_message(self, channel_id, message_id):
        '''This returns the JSON for the Message with the provided Message ID.'''
        return self.request_json("GET", f"/channels/{channel_id}/messages/{message_id}")

    def get_reaction_users(self, channel_id, message_id, emoji_name, emoji_id):
        '''This returns a list of User JSONs that reacted to the given message.
        Discord requires that we paginate through the users since we have a limit
        of 100 reacting users at a time, so we need to provide a User ID to pull
        the next 100 users after, hundred by hundred.'''
        users = []
        message = self.get_message(channel_id, message_id)
        num_users = [emoji for emoji in message["reactions"] if emoji["emoji"]["id"] == emoji_id][0]["count"]

        with tqdm(desc = "Retrieving reaction users", total = num_users) as pbar:
            while True:
                response_users = self.request_json(
                    request_type = "GET",
                    suburl = f"/channels/{channel_id}/messages/{message_id}/reactions/{emoji_name}:{emoji_id}",
                    params = {"limit": 100} | ({"after": users[-1]["id"]} if users else {})
                )
                if response_users:
                    users += response_users
                    pbar.update(len(response_users))
                else:
                    return users

    def get_guild_member(self, guild_id, user_id):
        '''This takes in a User ID and returns the full Guild Member data
        for that user, including their join date, roles, etc.
        This returns None if the member is no longer part of the Guild.'''
        try:
            return self.request_json("GET", f"/guilds/{guild_id}/members/{user_id}")
        except requests.HTTPError as ex:
            if ex.response.status_code == 404:
                return None
            else:
                raise ex

def generate_fake_message_id(dt):
    '''This translates a Python datetime.datetime object into a FAKE Discord Message ID.
    This Message ID is one that would have been sent at the datetime provided.

    Discord Message IDs are 64-bit integers. When you translate them into binary,
    the first 42 bits are the number of milliseconds since 2015-01-01T00:00:00.
    The remaining 22 bits are internal stuff that you don't care about.

    What this means is that if you have a datetime, you can generate a Message ID
    for a _fake_ message that was sent at that time. To do this, get the number
    of milliseconds since the Discord Epoch (just get the Unix time and subtract
    the DE), then left-shift it by 22 bits. This left-shift fills the last 22 bits
    with zeroes, which are the bits you don't care about. Converting this back to
    an integer gives you a Discord Message ID.

    Again, this Message ID is _not_ the ID of any _real_ message, but you _can_ use it
    as a point of reference to be able to jump to a point in time of a channel's message history.'''
    return str(int((dt.timestamp() * 1000) - DISCORD_EPOCH) << 22)

def export_reaction_users(connection, channel_id, message_id, emoji_text):
    '''This exports a CSV of data about users that reacted to a particular message
    with a particular emoji. Users that are no longer in the server are ignored.'''
    guild = connection.get_guild(F1_GUILD_ID)
    guild_roles = connection.get_roles(F1_GUILD_ID)
    message = connection.get_message(channel_id, message_id)
    emoji = [emoji for emoji in message["reactions"] if emoji["emoji"]["name"] == emoji_text][0]["emoji"]
    users = connection.get_reaction_users(channel_id, message_id, emoji["name"], emoji["id"])

    with open("reacted_users.csv", "w") as outfile:
        writer = csv.writer(outfile, delimiter = ',', quotechar = '"')
        writer.writerow(["User ID", "User Name", "Display Name", "Join Date", "Highest FX Role", "Has NoXP?", "Is Banished?"])

        for user in tqdm(users, desc = "Retrieving member data for users"):
            member = connection.get_guild_member(guild["id"], user["id"])
            if member:
                member_roles = [gr["name"] for gr in guild_roles if gr["id"] in member["roles"]]
                writer.writerow([
                    member["user"]["id"],
                    member["user"]["username"] + "#" + member["user"]["discriminator"],
                    member["nick"] if member["nick"] else member["user"]["username"],
                    member["joined_at"][:10],
                    min([role for role in member_roles if role in ["F1", "F2", "F3", "F4", "Fan"]]),
                    any([role == "NoXP" for role in member_roles]),
                    any([role.upper().startswith("BANISHED") for role in member_roles])
                ])

def get_joins_leaves(connection, since_datetime):
    '''This is a subroutine that gets all of the messages sent by Shadow
    in the #logs channel when users join or leave the server.'''
    messages = connection.get_channel_messages(
        LOGS_CHANNEL_ID,
        after = generate_fake_message_id(since_datetime)
    )
    return [
        message for message in messages
        if message["author"]["id"] == SHADOW_USER_ID
        and "Message Edit" not in message["embeds"][0]["fields"][0]["value"]
        and "Message Deletion" not in message["embeds"][0]["fields"][0]["value"]
    ]

def export_bouncing_users(connection, since_datetime):
    '''This exports a CSV of data about users that "bounced" from the server:
    users that join and then quickly leave the server.'''
    joins_leaves = get_joins_leaves(connection, since_datetime)

    user_events = {} # {user_id: {"join_datetime": YYYY-MM-DD HH:MM:SS, "leave_datetime": YYYY-MM-DD HH:MM:SS}}
    for message in joins_leaves:
        user_id = message["embeds"][0]["footer"]["text"].replace("User ID: ", "")
        event_type = "joined_at" if message["embeds"][0]["fields"][0]["value"] == "Joined the server" else "left_at"
        user_events[user_id][event_type] = message["timestamp"][:19].replace("T" " ")

    breakpoint()

def main():
    '''Execute top-level functionality.'''
    with Connection(TOKEN) as c:
        #export_reaction_users(c, ANNOUNCEMENTS_CHANNEL_ID, MOD_APPLICATION_MESSAGE_ID, "Bonk")
        export_bouncing_users(c, datetime.datetime.today() - datetime.timedelta(weeks = 2))

main()