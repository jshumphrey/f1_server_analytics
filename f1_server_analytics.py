#! /usr/bin/env python
'''This provides a wrapper around the Discord HTTP API to help with some common kinds of requests.
This is designed to be importable by another script that's more tailored to a particular use-case.'''

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
ROLE_HIERARCHY = {
    '177408413381165056': {"name": 'Admin', "rank": 1, "flag_score": 1.0},
    '177408501268611073': {"name": 'Stewards', "rank": 2, "flag_score": 0.8},
    '293845938764644352': {"name": 'Marshals', "rank": 3, "flag_score": 0.6},
    '314910132733739009': {"name": 'F1', "rank": 4, "flag_score": 0.4},
    '314910011358707712': {"name": 'F2', "rank": 5, "flag_score": 0.3},
    '314909797445271564': {"name": 'F3', "rank": 6, "flag_score": 0.2},
    '313677111695245312': {"name": 'F4', "rank": 7, "flag_score": 0.1},
    #'328635502792278017': {"name": 'Fan', "rank": 8, "flag_score": 0.05}, # The Fan role no longer exists
}
BELOW_F4_STUB_ROLE = {"name": 'None', "rank": 99, "flag_score": 0.05}
LEFT_SERVER_STUB_ROLE = {"name": 'Left', "rank": 999, "flag_score": 0}

PERMISSIONS_BIT_INDICES = {
    0: "Create Server Invite",
    1: "Kick Members",
    2: "Ban Members",
    3: "Administrator",
    4: "Manage Channels",
    5: "Manage Server Settings",
    6: "Add Reactions",
    7: "View Audit Log",
    8: "Priority Speaker",
    9: "Share Video / Screen",
    10: "View Channels",
    11: "Send Messages and Create Forum Posts",
    12: "Send Text-to-Speech Messages",
    13: "Manage Messages",
    14: "Embed Links",
    15: "Attach Files",
    16: "Read Message History",
    17: "Mention @everyone / @here",
    18: "Use External Emojis (if Nitro)",
    19: "View Guild Insights",
    20: "Connect to Voice Channels",
    21: "Speak in Voice Channels",
    22: "Mute Members in Voice Channels",
    23: "Deafen Members in Voice Channels",
    24: "Move Members Between Voice Channels",
    25: "Use Voice Activity",
    26: "Change Nickname",
    27: "Manage Nicknames",
    28: "Manage Roles",
    29: "Manage Webhooks",
    30: "Manage Emojis and Stickers",
    31: "Use Application Slash Commands",
    32: "Request to Speak in Stage Channels",
    33: "Manage Server Events",
    34: "Manage Threads and Forum Posts",
    35: "Create Public Threads in Channels",
    36: "Create Private Threads in Channels",
    37: "Use External Stickers",
    38: "Send Messages In Threads and Forum Posts",
    39: "Use Embedded Activities",
    40: "Timeout Members",
}

ANNOUNCEMENTS_CHANNEL_ID = "361137849736626177"
F1_GENERAL_CHANNEL_ID = "876046265111167016"
F1_DISCUSSION_CHANNEL_ID = "432208507073331201"
F1_GRANDSTAND_CHANNEL_ID = "825702140118564905"
PADDOCK_CLUB_CHANNEL_ID = "314949863911587840"
OFFTRACK_CHANNEL_ID = "242392969213247500"
SANDBOX_CHANNEL_ID = "242392574193565711"
LOGS_CHANNEL_ID = "273927887034515457"
F1_LOGS_CHANNEL_ID = "447397947261452288"
BLACK_FLAG_QUEUE_CHANNEL_ID = "971819727959769148"
MODERATION_QUEUE_CHANNEL_ID = "920333278593024071"
MOD_QUEUE_ARCHIVE_CHANNEL_ID = "920333356250587156"

SHADOW_USER_ID = "480338490639384576"
FORMULA_ONE_USER_ID = "424900962449358848"
LUX_USER_ID = "145582654857805825"

MOD_USER_IDS = [
    "260058592852443149", # Redacted
    "279015734271541249", # aalpinesnow
    "166938598405439488", # Ant
    "265827741847257089", # Blue
    "262840101581750274", # ciel
    "345495533898563586", # ClickerHappy
    "177386800304750592", # ClickerHappy's alt
    "186051153254023168", # coco
    "144476078377795584", # GalacticHitchHiker
    "297975100668379136", # jonny h
    "145582654857805825", # Lux
    "186057699727769600", # Pjilot Willem-Alexander
    "111928351798636544", # ren
    "417602648422875136", # Sean Archer
    "380314643844956160", # ToAerooNoootDynamicist
    "873258487768039474", # RC_
]

BOT_USER_IDS = [
    "424900962449358848", # Formula One
    "886984180800577636", # Formula One Dev
    "480338490639384576", # Shadow
]

MOD_APPLICATION_MESSAGE_ID = "935642010419879957"

MEMBER_UPDATE_ACTION_TYPE = 24
MEMBER_ROLE_UPDATE_ACTION_TYPE = 25

REPORT_ACTION_REGEX = r"(Punished|Ignored|Banned|Escalated) by \*\*([^\s]+.+\#\d{4})\*\*"
REPORTER_REGEX = r"\*\*Reporter\:\*\* ([^\s]+.+\#\d{4})"

class Connection:
    '''This class wraps a requests Session, wraps the process of making a request via the
    Discord API (handling rate limits, etc.), and includes a number of methods that
    wrap some common individual requests.'''
    def __init__(self, token):
        self.session = requests.Session()

        try:
            self.session.headers = {
                "Authorization": "Bot " + token.strip(),
                "Content-Type": "application/json",
                "X-Ratelimit-Precision": "millisecond"
            }
        except AttributeError as ex:
            raise EnvironmentError("No Discord token was found in the environment - Discord authentication failed!") from ex

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
            logger.debug("Successfully retrieved data using the provided token!")
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
                response.raise_for_status()
                return response.json() # Potential exit from the function - return the JSON of a valid response

            except requests.HTTPError as ex:
                if ex.response.status_code == 429: # 429 errors are "you're requesting too fast" - handle these differently than other errors
                    time_to_sleep = ex.response.json()["retry_after"]
                    logger.debug(f"Hit the Discord rate limiter; sleeping for {time_to_sleep!s} seconds")
                    self.sleep_delay += 0.05 # If we hit the rate limiter, back off the request speed bit by bit.
                    time.sleep(time_to_sleep)
                else:
                    raise ex # Potential exit from the function - crash out due to a bad request

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

    def get_guild_channels(self, guild_id):
        '''This returns the JSON of all Channels for the Guild with the provided Guild ID.'''
        return self.request_json("GET", f"/guilds/{guild_id}/channels")

    def get_channel(self, channel_id):
        '''This returns the JSON for the Channel with the provided Channel ID.'''
        return self.request_json("GET", f"/channels/{channel_id}")

    def get_channel_messages(self, channel_id, after_dt = None, before_dt = None, limit = 15000, progress_bar = True):
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

        with tqdm(desc = f"Retrieving messages in #{channel['name']}", total = limit, disable = not progress_bar) as pbar:
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

    def send_message(self, channel_id, message_dict):
        '''This creates and sends a message in the channel with the provided Channel ID.'''
        return self.request_json("POST", f"/channels/{channel_id}/messages", json = message_dict)

    def delete_message(self, channel_id, message_id):
        '''This deletes the the Message with the provided Message ID. Remember
        that you need the Manage Message permission in the channel to do this!'''
        return self.request_json("DELETE", f"/channels/{channel_id}/messages/{message_id}")

    def get_reacted_messages(self, channel_id, emoji_text, before_dt = None, after_dt = None, limit = 75000, progress_bar = True):
        '''This retrieves all messages in a given channel that are reacted to with the provided emoji_text.

        If the "before" or "after" arguments are provided (or both), only the messages before
        or after (or between) the provided datetimes will be retrieved. If neither argument
        is provided, the most recent messages sent in the channel will be retrieved.'''
        all_messages = self.get_channel_messages(channel_id, before_dt = before_dt, after_dt = after_dt, limit = limit, progress_bar = progress_bar)
        return [
            message for message in all_messages
            if "reactions" in message
            and any([reaction["emoji"]["name"] == emoji_text for reaction in message["reactions"]])
        ]

    def get_audit_log_entries(self, user_id = None, action_type = None, after_dt = None, before_dt = None, limit = 15000, progress_bar = True):
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

        with tqdm(desc = "Retrieving audit log entries", total = limit, disable = not progress_bar) as pbar:
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

    def get_reaction_users(self, channel_id, message_id, emoji_name, emoji_id, progress_bar = True):
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

        with tqdm(desc = "Retrieving reaction users", total = num_users, disable = not progress_bar) as pbar:
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

    def get_all_guild_members(self, guild_id, progress_bar = True):
        '''This returns a list with the JSON of all members of the guild with the provided Guild ID.'''
        members = []
        num_members = self.get_guild_preview(guild_id)["approximate_member_count"]

        with tqdm(desc = "Retrieving all guild members", total = num_members, disable = not progress_bar) as pbar:
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

    def get_highest_role(self, user):
        '''This takes in a user (you can also pass a full guild member object to save an API call)
        and returns the "highest" of their roles, according to the F1 Discord server's role hierarchy.
        If the user has left the guild, or if the user does not belong to any of the ranked roles,
        special role objects are returned to reflect this.'''
        guild_member = user if "roles" in user else self.get_guild_member(F1_GUILD_ID, user["id"])
        if not guild_member:
            return LEFT_SERVER_STUB_ROLE

        rankable_roles = [role for role in guild_member["roles"] if role in ROLE_HIERARCHY]
        if not rankable_roles:
            return BELOW_F4_STUB_ROLE

        return ROLE_HIERARCHY[sorted(rankable_roles, key = lambda r: ROLE_HIERARCHY[r]["rank"])[0]]

def generate_snowflake(input_datetime):
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
    return str(int((input_datetime.timestamp() * 1000) - DISCORD_EPOCH) << 22)

def generate_datetime(snowflake):
    '''This parses the creation datetime from a Discord [whatever] ID.
    This essentially does the reverse of generate_snowflake().'''
    return datetime.datetime.fromtimestamp(((int(snowflake) >> 22) + DISCORD_EPOCH) / 1000, tz = datetime.timezone.utc)

def translate_permissions_intstring(perms_intstring):
    '''This translates a Discord "permissions intstring" - the (potentially) large
    integer-stored-as-a-string that represents a bunch of bitwise yes/nos for various
    permissions - into a list of permission NAMES (via PERMISSIONS_BIT_INDICES) whose
    bits in the integer, if represented in binary, have a value of 1.'''
    permissions_booleans = [bool(int(x)) for x in list(format(int(perms_intstring), "b"))[::-1]]
    enumerated_booleans = list(enumerate(permissions_booleans))
    return [
        PERMISSIONS_BIT_INDICES[index]
        for (index, boolean) in enumerated_booleans
        if boolean is True
    ]

def export_all_permissions(connection, progress_bar = True):
    '''This exports a CSV of all of the permissions on every role and every channel
    in the Discord server. This is primarily useful for backup/restoration purposes.'''
    roles = {role["id"]: role for role in connection.get_roles(F1_GUILD_ID)}
    channels = connection.get_guild_channels(F1_GUILD_ID)
    users = {} # Will be populated with {user_id: user}

    with open("permissions_export.csv", "w", encoding = "utf-8") as outfile:
        writer = csv.writer(outfile, delimiter = ",", quotechar = '"')
        writer.writerow(["Channel Type", "Channel", "Entity Type", "Entity", "Allow/Deny", "Permission"])

        for role in roles.values():
            writer.writerows([
                ["Global", "N/A", "Role", role["name"], "Allow", perm_name]
                for perm_name in translate_permissions_intstring(role["permissions"])
            ])

        for channel in tqdm(channels, desc = "Retrieving channel permissions", disable = not progress_bar):
            for overwrite in channel["permission_overwrites"]:
                if overwrite["type"] == 1:
                    if overwrite["id"] not in users:
                        users[overwrite["id"]] = connection.get_user(overwrite['id'])
                    user = users[overwrite["id"]]

                for perm_type in ["allow", "deny"]:
                    writer.writerows([
                        [
                            "Category" if channel["type"] == 4 else "Channel",
                            channel["name"],
                            "Role" if overwrite["type"] == 0 else "User",
                            roles[overwrite["id"]]["name"] if overwrite["type"] == 0 else f"{user['username']}#{user['discriminator']}",
                            perm_type.title(),
                            perm_name
                        ]
                        for perm_name in translate_permissions_intstring(overwrite[perm_type])
                        if overwrite[perm_type] != "0"
                    ])


def export_reaction_users(connection, channel_id, message_id, emoji_text, progress_bar = True):
    '''This exports a CSV of data about users that reacted to a particular message
    with a particular emoji. Users that are no longer in the server are ignored.'''
    guild_roles = connection.get_roles(F1_GUILD_ID)
    message = connection.get_message(channel_id, message_id)
    emoji = [emoji for emoji in message["reactions"] if emoji["emoji"]["name"] == emoji_text][0]["emoji"]
    users = connection.get_reaction_users(channel_id, message_id, emoji["name"], emoji["id"])
    members = {member["user"]["id"]: member for member in connection.get_all_guild_members(F1_GUILD_ID)}

    with open("reacted_users.csv", "w", encoding = "utf-8") as outfile:
        writer = csv.writer(outfile, delimiter = ',', quotechar = '"')
        writer.writerow(["User ID", "User Name", "Display Name", "Join Date", "Highest FX Role", "Has NoXP?", "Is Banished?"])

        for user in tqdm(users, desc = "Retrieving member data for users", disable = not progress_bar):
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

def get_joins_leaves(connection, after_dt = None, before_dt = None, progress_bar = True):
    '''This is a subroutine that gets all of the messages sent by Shadow in the #logs
    channel when users join or leave the server. This returns a tuple containing two dicts
    of {user_id: join/leave message} - one dict for joins, one for leaves.'''
    messages = connection.get_channel_messages(LOGS_CHANNEL_ID, after_dt = after_dt, before_dt = before_dt, progress_bar = progress_bar)
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

def get_bans(connection, after_dt = None, before_dt = None, progress_bar = True):
    '''This is a subroutine that gets all of the messages sent by Formula One in the #f1-logs
    channel when a user is banned. This returns a dict of {user_id: ban message}.'''
    messages = connection.get_channel_messages(F1_LOGS_CHANNEL_ID, after_dt = after_dt, before_dt = before_dt, progress_bar = progress_bar)
    return {
        re.search(r"\*\*User:\*\*.*\(([0-9]+)\)", message["embeds"][0]["description"]).group(1): message
        for message in messages
        if message["author"]["id"] == FORMULA_ONE_USER_ID
        and "description" in message["embeds"][0]
        and "**Action:** Ban" in message["embeds"][0]["description"]
    }

def get_reports(connection, after_dt = None, before_dt = None):
    """This is a subroutine that sweeps through the Moderation Queue Archive channel and collects
    all of the situations that were raised to the attention of the moderators, whether via
    user reports or by one of the automated message-analysis tools."""
    messages = connection.get_channel_messages(MOD_QUEUE_ARCHIVE_CHANNEL_ID, after_dt = after_dt, before_dt = before_dt)
    report_messages = [
        message for message in messages
        if message["author"]["id"] == FORMULA_ONE_USER_ID
        and message["content"] != ""
        and "embeds" in message
        and "Successfully removed" not in message["embeds"][0]["description"]
        and "Member not found" not in message["embeds"][0]["description"]
        and "NoXP" not in message["embeds"][0]["description"]
        and "Already banned" not in message["content"]
    ]
    reports = []

    for message in report_messages:
        description = message["embeds"][0]["description"]
        report_type = (
            "User Report" if "Report" in description
            else "Perspective API" if "Perspective" in description
            else "Geoff4URLs" if "geoff4URLs" in description
            else "Automatic Mute" if "Posted 3 or more violations" in description
            else "Unknown - " + description[:description.find(r"\n")]
        )
        (report_status, actioning_moderator) = re.search(REPORT_ACTION_REGEX, message["content"]).groups()

        reports.append({
            "message": message,
            "timestamp": datetime.datetime.fromisoformat(message["timestamp"]),
            "user": message["embeds"][0]["author"],
            "report_type": report_type,
            "reporter": re.search(REPORTER_REGEX, description).groups(0)[0] if report_type == "User Report" else "N/A",
            "report_status": report_status,
            "actioning_moderator": actioning_moderator,
        })

    return reports

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

def export_bouncing_users(connection, after_dt = None, before_dt = None, progress_bar = True):
    '''This exports a CSV of data about users that "bounced" from the server:
    users that join and then quickly leave the server.'''
    (joins, leaves) = get_joins_leaves(connection, after_dt = after_dt, before_dt = before_dt, progress_bar = progress_bar)
    bans = get_bans(connection, after_dt = after_dt, before_dt = before_dt, progress_bar = progress_bar)
    #fan_role_grants = get_fan_role_grants(connection, after_dt = after_dt, before_dt = before_dt)
    members = {member["user"]["id"]: member for member in connection.get_all_guild_members(F1_GUILD_ID)}

    user_events = {
        user_id: {
            "join_dt": datetime.datetime.fromisoformat(joins[user_id]["timestamp"]),
            "leave_dt": datetime.datetime.fromisoformat(leaves[user_id]["timestamp"]) if user_id in leaves else None,
            "is_banned": True if user_id in bans else None,
            #"had_fan": True if user_id in fan_role_grants else None
        }
        for user_id in joins.keys()
    }

    with open("bouncing_users.csv", "w", encoding = "utf-8") as outfile:
        writer = csv.writer(outfile, delimiter = ',', quotechar = '"')
        writer.writerow([
            "User ID",
            "User Name",
            "User Create TS",
            "Join TS",
            "Join Date",
            ">5min Account Age?",
            "Leave TS",
            "Duration (minutes)",
            "Verified Email?",
            "Status",
        ])

        for user_id, events in user_events.items():
            if events["leave_dt"] and events["join_dt"] > events["leave_dt"]:
                continue # These are basically bugged because the user left before the time window. Skip them.

            writer.writerow([
                user_id,
                f"{members[user_id]['user']['username']}#{members[user_id]['user']['discriminator']}" if user_id in members else None,
                generate_datetime(user_id).strftime("%Y-%m-%d %H:%M:%S"),
                events["join_dt"].strftime("%Y-%m-%d %H:%M:%S"),
                events["join_dt"].strftime("%Y-%m-%d"),
                "Yes" if events["join_dt"] >= generate_datetime(user_id) + datetime.timedelta(minutes = 5) else "No",
                events["leave_dt"].strftime("%Y-%m-%d %H:%M:%S") if events["leave_dt"] else "Not Found",
                ((events["leave_dt"] - events["join_dt"]).total_seconds() / 60.0) if events["leave_dt"] else None,
                "Unknown" if user_id not in members else ("No" if members[user_id]["pending"] else "Yes"),
                "Banned" if events["is_banned"] else "Joined and " + ("Left" if events["leave_dt"] else "Stayed"),
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
        and not ("bot" in member["user"] and member["user"]["bot"])
    ]

    with open("fan_eligible_users.csv", "w", encoding = "utf-8") as outfile:
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

    with open("emoji_usage.csv", "w", encoding = "utf-8") as outfile:
        writer = csv.writer(outfile, delimiter = ',', quotechar = '"')
        writer.writerow(["Emoji Name", "Channel", "Times Used in Messages", "Times Used as Reaction"])
        for channel, usage_dict in emoji_usage.items():
            for emoji, emoji_dict in usage_dict.items():
                if emoji in guild_emoji:
                    writer.writerow([emoji, channel, emoji_dict["messages"], emoji_dict["reactions"]])

    all_used_emoji = list(itertools.chain.from_iterable([emojis.keys() for channel, emojis in emoji_usage.items()]))
    unused_emoji = sorted([emoji for emoji in guild_emoji.keys() if emoji not in all_used_emoji])

    with open("unused_emoji.csv", "w", encoding = "utf-8") as outfile:
        outfile.write("\n".join(["Emoji Name"] + unused_emoji))

def export_moderation_statistics(connection, after_dt = None, before_dt = None):
    """This exports a CSV of information about moderation action taken on
    the reported messages in the specified timeframe """
    reports = get_reports(connection, after_dt = after_dt, before_dt = before_dt)
    with open("moderation_statistics.csv", "w", encoding = "utf-8") as outfile:
        writer = csv.writer(outfile, delimiter = ",", quotechar = '"')
        writer.writerow([
            "Report Timestamp",
            "Offending Username",
            "Report Type",
            "Reporting Username",
            "Report Status",
            "Actioning Moderator",
        ])
        writer.writerows([[
            report["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            report["user"]["name"],
            report["report_type"],
            report["reporter"],
            report["report_status"],
            report["actioning_moderator"],
        ] for report in reports])

if __name__ == "__main__":
    with Connection(TOKEN) as c:
        #export_reaction_users(c, ANNOUNCEMENTS_CHANNEL_ID, MOD_APPLICATION_MESSAGE_ID, "Bonk")
        #export_bouncing_users(c, after_dt = datetime.datetime.today() - datetime.timedelta(weeks = 8))
        #export_fan_eligible_users(c)
        #export_emoji_usage(c, after_dt = datetime.datetime.today() - datetime.timedelta(weeks = 2), limit = 75000)
        #export_moderation_statistics(c, after_dt = datetime.datetime.today() - datetime.timedelta(weeks = 4))
        #export_all_permissions(c)
        #_ = c.get_guild(F1_GUILD_ID)
        breakpoint() # pylint: disable = forgotten-debug-statement
