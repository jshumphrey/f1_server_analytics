#! /usr/bin/env python
'''This is a standalone script to dump out information about the F1 Discord server and its users.'''

import csv, datetime, dotenv, itertools, logging, os, re, requests, time # pylint: disable = unused-import
from tqdm import tqdm

# Configure the logger so that we have a logger object to use.
logging.basicConfig(level = logging.INFO)
logger = logging.getLogger("f1discord")

dotenv.load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")

DISCORD_EPOCH = 1420070400000

URL_BASE = "https://discord.com/api/v9"
BASE_SLEEP_DELAY = 0.5 # This is the number of seconds to sleep between requests.
MAX_FAILURES = 5

F1_GUILD_ID = "177387572505346048"

FAN_ROLE_ID = "328635502792278017"
MOD_ROLE_IDS = ["177408413381165056", "177408501268611073", "293845938764644352", "738665034359767060"]

ANNOUNCEMENTS_CHANNEL_ID = "361137849736626177"
F1_GENERAL_CHANNEL_ID = "876046265111167016"
F1_DISCUSSION_CHANNEL_ID = "432208507073331201"
F1_GRANDSTAND_CHANNEL_ID = "825702140118564905"
PADDOCK_CLUB_CHANNEL_ID = "314949863911587840"
OFFTRACK_CHANNEL_ID = "242392969213247500"
SANDBOX_CHANNEL_ID = "242392574193565711"
LOGS_CHANNEL_ID = "273927887034515457"
F1_LOGS_CHANNEL_ID = "447397947261452288"

SHADOW_USER_ID = "480338490639384576"
FORMULA_ONE_USER_ID = "424900962449358848"
LUX_USER_ID = "145582654857805825"

MOD_APPLICATION_MESSAGE_ID = "935642010419879957"

MEMBER_UPDATE_ACTION_TYPE = 24
MEMBER_ROLE_UPDATE_ACTION_TYPE = 25

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
        self.sleep_delay = BASE_SLEEP_DELAY
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
            logger.info("Successfully retrieved data using the provided token!")
        except requests.HTTPError as ex:
            raise EnvironmentError("The token provided is not valid - Discord authentication failed!") from ex

    def bucket_sleep(self):
        '''This sleeps the script for the appropriate amount of time to avoid issues
        with the Discord rate limiter. Discord's rate limits are not actually static,
        so we might still hit the limiter (which is handled separately), but by baking
        in a basic delay between requests, we get a more stable average request time.'''
        time_since_last_call = round(time.time() - self.last_call, 4)
        time_to_sleep = max(self.sleep_delay - time_since_last_call, 0)
        if time_to_sleep > 0:
            logger.debug(f"It's only been {time_since_last_call!s} seconds since the last call, sleeping for {time_to_sleep!s}s")
            time.sleep(time_to_sleep)
        else:
            logger.debug(f"It's been {time_since_last_call!s} seconds since the last call, no need to sleep")

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
                    logger.debug(f"Hit the Discord rate limiter; sleeping for {time_to_sleep!s} seconds")
                    self.sleep_delay += 0.05 # If we hit the rate limiter, back off the request speed bit by bit.
                    time.sleep(time_to_sleep)
                else:
                    raise ex

            except (requests.ConnectionError, requests.Timeout) as ex:
                failures += 1
                logger.debug(f"Encountered a {type(ex)} when {request_type}ing {suburl}; {failures!s} failures so far")
                if failures >= MAX_FAILURES:
                    logger.debug(f"Encountered too many ConnectionErrors or Timeouts when {request_type}ing {suburl}; crashing out")
                    raise # Potential exit from the function - crash out due to too many ConnectionErrors or Timeouts

            finally:
                self.last_call = time.time()

    def get_self(self):
        '''This returns the JSON for the User associated to the current Connection.'''
        return self.request_json("GET", "/users/@me")

    def get_guild(self, guild_id):
        '''This returns the JSON for the Guild with the provided Guild ID.'''
        return self.request_json("GET", f"/guilds/{guild_id}")

    def get_guild_preview(self, guild_id):
        '''This returns the JSON for the Guild Preview with the provided Guild ID.'''
        return self.request_json("GET", f"/guilds/{guild_id}/preview")

    def get_roles(self, guild_id):
        '''This returns the JSON of the Roles for the Guild with the provided Guild ID.'''
        return self.request_json("GET", f"/guilds/{guild_id}/roles")

    def get_all_emoji(self, guild_id):
        '''This returns the JSON of all of the emoji for the Guild with the provided Guild ID.'''
        return self.get_guild(guild_id)["emojis"]

    def get_channel(self, channel_id):
        '''This returns the JSON for the Channel with the provided Channel ID.'''
        return self.request_json("GET", f"/channels/{channel_id}")

    def get_channel_messages(self, channel_id, after_dt = None, before_dt = None, limit = 15000):
        '''This returns the JSON of messages sent in the channel with the provided Channel ID,
        up to the number of messages in the "limit" argument.

        If the "before" or "after" arguments are provided (or both), only the messages before
        or after (or between) the provided datetimes will be retrieved. If neither argument
        is provided, the most recent messages sent in the channel will be retrieved.'''
        messages = []
        channel = self.get_channel(channel_id)

        if after_dt and before_dt and after_dt > before_dt:
            raise ValueError("'after_dt' cannot be greater than 'before_dt'")

        after_id = generate_snowflake(after_dt) if after_dt else None
        before_id = generate_snowflake(before_dt) if before_dt else None
        default_message_id = after_id or before_id or generate_snowflake(datetime.datetime.now()) # Equivalent to COALESCE() in SQL
        direction_param = "after" if after_id else "before"

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
                    if after_id and before_id and message["id"] > before_id:
                        return messages # We've hit the end of our search range; return the list

                    messages.append(message)
                    pbar.update()

                    if limit and len(messages) >= limit:
                        return messages # We've hit our limit of messages to pull; return the list

    def get_message(self, channel_id, message_id):
        '''This returns the JSON for the Message with the provided Message ID.'''
        return self.request_json("GET", f"/channels/{channel_id}/messages/{message_id}")

    def get_audit_log_entries(self, user_id = None, action_type = None, after_dt = None, before_dt = None, limit = 15000):
        '''This returns the JSON of audit log entries created by the user with the provided User ID,
        (or by all users, if no user ID is provided), of the provided action type (or all action types,
        if no action type is provided), up to the number of entries in the "limit" argument.

        If the "before" or "after" arguments are provided (or both), only the log entries before
        or after (or in between) the provided datetimes will be retrieved. If neither argument
        is provided, the most recent log entries will be retrieved.'''
        entries = []

        if after_dt and before_dt and after_dt > before_dt:
            raise ValueError("'after_dt' cannot be greater than 'before_dt'")

        # Note that this is a bit different than get_channel_messages.
        # The audit log doesn't let you specify an "after" value, so we have to do it ourselves.
        after_id = generate_snowflake(after_dt) if after_dt else None
        before_id = generate_snowflake(before_dt) if before_dt else None
        default_entry_id = before_id or generate_snowflake(datetime.datetime.now()) # Equivalent to COALESCE() in SQL

        base_params = (
            {"limit": 100}
            | ({"user_id": user_id} if user_id else {})
            | ({"action_type": action_type} if action_type else {})
        )

        with tqdm(desc = "Retrieving audit log entries", total = limit) as pbar:
            while True:
                response_entries = self.request_json(
                    request_type = "GET",
                    suburl = f"/guilds/{F1_GUILD_ID}/audit-logs",
                    params = base_params | {"before": entries[-1]["id"] if entries else default_entry_id}
                )["audit_log_entries"]
                if not response_entries:
                    return entries # We're completely out of entries; return the list

                response_entries.sort(key = lambda e: e["id"], reverse = True)
                for entry in response_entries:
                    if after_id and entry["id"] < after_id:
                        return entries # We've hit the end of our search range; return the list

                    entries.append(entry)
                    pbar.update()

                    if len(entries) >= limit:
                        return entries # We've hit our limit of entries to pull; return the list

    def get_reaction_users(self, channel_id, message_id, emoji_name, emoji_id):
        '''This returns a list of User JSONs that reacted to the given message.
        Discord requires that we paginate through the users since we have a limit
        of 100 reacting users at a time, so we need to provide a User ID to pull
        the next 100 users after, hundred by hundred.'''
        users = []
        message = self.get_message(channel_id, message_id)
        num_users = [
            reaction for reaction in message["reactions"]
            if reaction["emoji"]["id"] == emoji_id
        ][0]["count"]

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

    def get_user(self, user_id):
        '''This returns the JSON for the user with the provided User ID.'''
        return self.request_json("GET", f"/users/{user_id}")

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

    def get_all_guild_members(self, guild_id):
        '''This returns a list with the JSON of all members of the guild with the provided Guild ID.'''
        members = []
        num_members = self.get_guild_preview(guild_id)["approximate_member_count"]

        with tqdm(desc = "Retrieving all guild members", total = num_members) as pbar:
            while True:
                response_members = self.request_json(
                    request_type = "GET",
                    suburl = f"/guilds/{guild_id}/members",
                    params = {"limit": 1000} | ({"after": members[-1]["user"]["id"]} if members else {})
                )
                if not response_members:
                    return members # We're completely out of members; return the list

                response_members.sort(key = lambda m: m["user"]["id"])
                members += response_members
                pbar.update(len(response_members))

def generate_snowflake(dt):
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

def generate_datetime(snowflake):
    '''This parses the creation datetime from a Discord [whatever] ID.
    This essentially does the reverse of generate_snowflake().'''
    return datetime.datetime.fromtimestamp(((int(snowflake) >> 22) + DISCORD_EPOCH) / 1000, tz = datetime.timezone.utc)

def export_reaction_users(connection, channel_id, message_id, emoji_text):
    '''This exports a CSV of data about users that reacted to a particular message
    with a particular emoji. Users that are no longer in the server are ignored.'''
    guild_roles = connection.get_roles(F1_GUILD_ID)
    message = connection.get_message(channel_id, message_id)
    emoji = [emoji for emoji in message["reactions"] if emoji["emoji"]["name"] == emoji_text][0]["emoji"]
    users = connection.get_reaction_users(channel_id, message_id, emoji["name"], emoji["id"])
    members = {member["user"]["id"]: member for member in connection.get_all_guild_members(F1_GUILD_ID)}

    with open("reacted_users.csv", "w") as outfile:
        writer = csv.writer(outfile, delimiter = ',', quotechar = '"')
        writer.writerow(["User ID", "User Name", "Display Name", "Join Date", "Highest FX Role", "Has NoXP?", "Is Banished?"])

        for user in tqdm(users, desc = "Retrieving member data for users"):
            if user in members:
                member = members[user["id"]]
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

def get_joins_leaves(connection, after_dt = None, before_dt = None):
    '''This is a subroutine that gets all of the messages sent by Shadow in the #logs
    channel when users join or leave the server. This returns a tuple containing two dicts
    of {user_id: join/leave message} - one dict for joins, one for leaves.'''
    messages = connection.get_channel_messages(LOGS_CHANNEL_ID, after_dt = after_dt, before_dt = before_dt)
    joins = {
        message["embeds"][0]["footer"]["text"].replace("User ID: ", ""): message
        for message in messages
        if message["author"]["id"] == SHADOW_USER_ID
        and message["embeds"][0]["fields"][0]["value"] == "Joined the server"
    }
    leaves = {
        message["embeds"][0]["footer"]["text"].replace("User ID: ", ""): message
        for message in messages
        if message["author"]["id"] == SHADOW_USER_ID
        and message["embeds"][0]["fields"][0]["value"] == "Left the server"
    }
    return (joins, leaves)

def get_bans(connection, after_dt = None, before_dt = None):
    '''This is a subroutine that gets all of the messages sent by Formula One in the #f1-logs
    channel when a user is banned. This returns a dict of {user_id: ban message}.'''
    messages = connection.get_channel_messages(F1_LOGS_CHANNEL_ID, after_dt = after_dt, before_dt = before_dt)
    return {
        re.search(r"\*\*User:\*\*.*\(([0-9]+)\)", message["embeds"][0]["description"]).group(1): message
        for message in messages
        if message["author"]["id"] == FORMULA_ONE_USER_ID
        and "description" in message["embeds"][0]
        and "**Action:** Ban" in message["embeds"][0]["description"]
    }

def get_fan_role_grants(connection, after_dt = None, before_dt = None):
    '''This is a subroutine that gets all of the times when a user was granted the Fan role
    by the Formula One bot. This returns a dict of {user_id: audit log entry}.'''
    entries = connection.get_audit_log_entries(
        user_id = FORMULA_ONE_USER_ID,
        action_type = MEMBER_ROLE_UPDATE_ACTION_TYPE,
        before_dt = before_dt,
        after_dt = after_dt
    )
    return {
        entry["target_id"]: entry
        for entry in entries
        if entry["changes"][0]["key"] == "$add"
        and entry["changes"][0]["new_value"][0]["name"] == "Fan"
    }

def get_channel_emoji_usage(connection, channel_id, after_dt = None, before_dt = None, limit = 15000):
    '''This returns a dictionary of emoji usage in the specified channel, in the specified time range.
    The dictionary is: {channel_name: {emoji_text: {"messages": int, "reactions": int}}}'''
    channel = connection.get_channel(channel_id)
    output_emoji = {}

    for message in connection.get_channel_messages(channel_id, after_dt = after_dt, before_dt = before_dt, limit = limit):
        message_emoji = re.findall(r"<:(\w+):\d{18}>", message["content"])
        reaction_emoji = [
            reaction["emoji"]["name"]
            for reaction in message["reactions"]
            if reaction["emoji"]["id"]
        ] if "reactions" in message else []

        output_emoji = output_emoji | {
            emoji: {"messages": 0, "reactions": 0}
            for emoji in message_emoji + reaction_emoji
            if emoji not in output_emoji
        }

        for emoji in message_emoji:
            output_emoji[emoji]["messages"] += 1
        for emoji in reaction_emoji:
            output_emoji[emoji]["reactions"] += 1

    return {channel["name"]: output_emoji}

def export_bouncing_users(connection, after_dt = None, before_dt = None):
    '''This exports a CSV of data about users that "bounced" from the server:
    users that join and then quickly leave the server.'''
    (joins, leaves) = get_joins_leaves(connection, after_dt = after_dt, before_dt = before_dt)
    bans = get_bans(connection, after_dt = after_dt, before_dt = before_dt)
    fan_role_grants = get_fan_role_grants(connection, after_dt = after_dt, before_dt = before_dt)
    members = {member["user"]["id"]: member for member in connection.get_all_guild_members(F1_GUILD_ID)}

    user_events = {
        user_id: {
            "join_dt": datetime.datetime.fromisoformat(joins[user_id]["timestamp"]),
            "leave_dt": datetime.datetime.fromisoformat(leaves[user_id]["timestamp"]) if user_id in leaves else None,
            "is_banned": True if user_id in bans else None,
            "had_fan": True if user_id in fan_role_grants else None
        }
        for user_id in joins.keys()
    }

    with open("bouncing_users.csv", "w") as outfile:
        writer = csv.writer(outfile, delimiter = ',', quotechar = '"')
        writer.writerow(["User ID", "User Name", "User Create TS", "Join TS", ">5min Account Age?", "Leave TS", "Duration", "Verified Email?", "Fan Role?", "Banned?", "Status"])

        for user_id, events in tqdm(user_events.items(), desc = "Retrieving user data"):
            if events["leave_dt"] and events["join_dt"] > events["leave_dt"]:
                continue # These are basically bugged because the user left before the time window. Skip them.

            user = members[user_id]["user"] if user_id in members else connection.get_user(user_id)

            writer.writerow([
                user_id,
                user["username"] + "#" + user["discriminator"],
                generate_datetime(user_id).strftime("%Y-%m-%d %H:%M:%S"),
                events["join_dt"].strftime("%Y-%m-%d %H:%M:%S"),
                "Yes" if events["join_dt"] >= generate_datetime(user_id) + datetime.timedelta(minutes = 5) else "No",
                events["leave_dt"].strftime("%Y-%m-%d %H:%M:%S") if events["leave_dt"] else "Not Found",
                str(events["leave_dt"] - events["join_dt"]) if events["leave_dt"] else None,
                "Unknown" if user_id not in members else ("No" if members[user_id]["pending"] else "Yes"),
                "Yes" if events["had_fan"] is True else "No",
                "Yes" if events["is_banned"] is True else "No",
                "Banned" if events["is_banned"] else "Joined and " + ("Left" if events["leave_dt"] else "Stayed")
            ])

def export_fan_eligible_users(connection):
    '''This exports a CSV of data about users that are eligible to receive the Fan role,
    but have not yet been granted it.'''
    members = connection.get_all_guild_members(F1_GUILD_ID)
    guild_roles = connection.get_roles(F1_GUILD_ID)
    eligible_members = [
        member for member in members
        if not member["pending"]
        and FAN_ROLE_ID not in member["roles"]
        and not list(set(member["roles"]) & set(MOD_ROLE_IDS)) # If there's no intersection
        and not ("bot" in member["user"] and member["user"]["bot"])
    ]

    with open("fan_eligible_users.csv", "w") as outfile:
        writer = csv.writer(outfile, delimiter = ',', quotechar = '"')
        writer.writerow(["User ID", "User Name", "Display Name", "Join Date", "Roles"])

        for member in sorted(eligible_members, key = lambda m: m["joined_at"]):
            writer.writerow([
                member["user"]["id"],
                member["user"]["username"] + "#" + member["user"]["discriminator"],
                member["nick"] if member["nick"] else member["user"]["username"],
                member["joined_at"][:10],
                ", ".join([gr["name"] for gr in guild_roles if gr["id"] in member["roles"]])
            ])

def export_emoji_usage(connection, after_dt = None, before_dt = None, limit = 15000):
    '''This exports a CSV of data about which emoji were used, in which channels,
    and with what frequency, over the date range provided.'''
    emoji_usage = {}
    channels_to_scan = [
        F1_GENERAL_CHANNEL_ID,
        F1_DISCUSSION_CHANNEL_ID,
        F1_GRANDSTAND_CHANNEL_ID,
        PADDOCK_CLUB_CHANNEL_ID,
        OFFTRACK_CHANNEL_ID,
        SANDBOX_CHANNEL_ID
    ]

    for channel_id in channels_to_scan:
        emoji_usage = emoji_usage | get_channel_emoji_usage(connection, channel_id, after_dt = after_dt, before_dt = before_dt, limit = limit)

    guild_emoji = {emoji["name"]: emoji["id"] for emoji in connection.get_all_emoji(F1_GUILD_ID)}

    with open("emoji_usage.csv", "w") as outfile:
        writer = csv.writer(outfile, delimiter = ',', quotechar = '"')
        writer.writerow(["Emoji Name", "Channel", "Times Used in Messages", "Times Used as Reaction"])
        for channel, usage_dict in emoji_usage.items():
            for emoji, emoji_dict in usage_dict.items():
                if emoji in guild_emoji:
                    writer.writerow([emoji, channel, emoji_dict["messages"], emoji_dict["reactions"]])

    all_used_emoji = list(itertools.chain.from_iterable([emojis.keys() for channel, emojis in emoji_usage.items()]))
    unused_emoji = sorted([emoji for emoji in guild_emoji.keys() if emoji not in all_used_emoji])

    with open("unused_emoji.csv", "w") as outfile:
        outfile.write("\n".join(["Emoji Name"] + unused_emoji))

if __name__ == "__main__":
    with Connection(TOKEN) as c:
        #export_reaction_users(c, ANNOUNCEMENTS_CHANNEL_ID, MOD_APPLICATION_MESSAGE_ID, "Bonk")
        #export_bouncing_users(c, after_dt = datetime.datetime.today() - datetime.timedelta(weeks = 2))
        #export_fan_eligible_users(c)
        #export_emoji_usage(c, after_dt = datetime.datetime.today() - datetime.timedelta(weeks = 2), limit = 75000)
        #_ = c.get_guild(F1_GUILD_ID)
        breakpoint() # pylint: disable = forgotten-debug-statement