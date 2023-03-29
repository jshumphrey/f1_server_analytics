#! /usr/bin/env python
'''This provides a wrapper around the Discord HTTP API to help with some common kinds of requests.
This is designed to be importable by another script that's more tailored to a particular use-case.'''

import csv, copy, datetime, itertools, logging, os, re, time, typing
import dotenv, requests
from tqdm import tqdm
from typing import Optional
import f1_server_constants as f1sc

# Type aliases
Snowflake = str

# Configure the logger so that we have a logger object to use.
logging.basicConfig(level = logging.INFO)
logger = logging.getLogger("f1discord")

dotenv.load_dotenv()
TOKEN = typing.cast(str, os.getenv("DISCORD_TOKEN"))

class Connection:
    '''This class wraps a requests Session, wraps the process of making a request via the
    Discord API (handling rate limits, etc.), and includes a number of methods that
    wrap some common individual requests.'''
    def __init__(self, token: str) -> None:
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
        self.sleep_delay = f1sc.BASE_SLEEP_DELAY
        self.test_token()

    def __enter__(self) -> "Connection":
        return self

    def __exit__(self, exception_type, exception_value, traceback) -> None:
        '''This automatically closes the connection once the with/as is released.'''
        self.session.close()

    def test_token(self) -> None:
        '''This "tests" the token by trying to make a very simple request (requesting
        information about our own user). If this request fails, we know that the token
        is not valid, and the user needs to fix this before trying again.'''
        try:
            self.get_self_user()
            logger.debug("Successfully retrieved data using the provided token!")
        except requests.HTTPError as ex:
            raise EnvironmentError("The token provided is not valid - Discord authentication failed!") from ex

    def bucket_sleep(self) -> None:
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

    def request_json(
        self,
        request_type: str,
        suburl: str,
        **kwargs
    ):
        '''This wraps the process of making a request to a given URL, handling errors,
        and sleeping for the appropriate amount of time to avoid rate limits.
        If/when we receive a valid response, its JSON is returned.'''
        failures = 0

        while True:
            self.bucket_sleep()
            try:
                response = self.session.request(request_type, f1sc.URL_BASE + suburl, **kwargs)
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
                if failures >= f1sc.MAX_FAILURES:
                    logger.debug(f"Encountered too many ConnectionErrors or Timeouts when {request_type}ing {suburl}; crashing out")
                    raise # Potential exit from the function - crash out due to too many ConnectionErrors or Timeouts

            finally:
                self.last_call = time.time()

    def get_self_user(self) -> dict:
        '''This returns the JSON for the User associated to the current Connection.'''
        return self.request_json("GET", "/users/@me")

    def get_guild(self, guild_id: Snowflake) -> dict:
        '''This returns the JSON for the Guild with the provided Guild ID.'''
        return self.request_json("GET", f"/guilds/{guild_id}")

    def get_guild_preview(self, guild_id: Snowflake) -> dict:
        '''This returns the JSON for the Guild Preview with the provided Guild ID.'''
        return self.request_json("GET", f"/guilds/{guild_id}/preview")

    def get_roles(self, guild_id: Snowflake) -> list[dict]:
        '''This returns the JSON of the Roles for the Guild with the provided Guild ID.'''
        return self.request_json("GET", f"/guilds/{guild_id}/roles")

    def get_all_emoji(self, guild_id: Snowflake) -> list[dict]:
        '''This returns the JSON of all of the emoji for the Guild with the provided Guild ID.'''
        return self.get_guild(guild_id)["emojis"]

    def get_guild_channels(self, guild_id: Snowflake) -> list[dict]:
        '''This returns the JSON of all Channels for the Guild with the provided Guild ID.'''
        return self.request_json("GET", f"/guilds/{guild_id}/channels")

    def get_channel(self, channel_id: Snowflake) -> dict:
        '''This returns the JSON for the Channel with the provided Channel ID.'''
        return self.request_json("GET", f"/channels/{channel_id}")

    def get_channel_messages(
        self,
        channel_id: Snowflake,
        after_dt: Optional[datetime.datetime] = None,
        before_dt: Optional[datetime.datetime] = None,
        limit = 15000,
        progress_bar: bool = True
    ) -> list[dict]:
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

    def get_message(self, channel_id: Snowflake, message_id: Snowflake) -> dict:
        '''This returns the JSON for the Message with the provided Message ID.'''
        return self.request_json("GET", f"/channels/{channel_id}/messages/{message_id}")

    def send_message(self, channel_id: Snowflake, message_dict: dict) -> None:
        '''This creates and sends a message in the channel with the provided Channel ID.'''
        self.request_json("POST", f"/channels/{channel_id}/messages", json = message_dict)

    def delete_message(self, channel_id: Snowflake, message_id: Snowflake) -> None:
        '''This deletes the the Message with the provided Message ID. Remember
        that you need the Manage Message permission in the channel to do this!'''
        self.request_json("DELETE", f"/channels/{channel_id}/messages/{message_id}")

    def get_reacted_messages(
        self,
        channel_id: Snowflake,
        emoji_text: str,
        before_dt: Optional[datetime.datetime] = None,
        after_dt: Optional[datetime.datetime] = None,
        limit: int = 75000,
        progress_bar: bool = True
    ) -> list[dict]:
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

    def get_audit_log_entries(
        self,
        user_id: Optional[str] = None,
        action_type = None,
        after_dt: Optional[datetime.datetime] = None,
        before_dt: Optional[datetime.datetime] = None,
        limit: int = 15000,
        progress_bar: bool = True
    ) -> list[dict]:
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
                    suburl = f"/guilds/{f1sc.F1_GUILD_ID}/audit-logs",
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

    def get_reaction_users(
        self,
        channel_id: Snowflake,
        message_id: Snowflake,
        emoji_name: str,
        emoji_id: Snowflake,
        progress_bar: bool = True
    ) -> list[dict]:
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

    def get_user(self, user_id: Snowflake) -> dict:
        '''This returns the JSON for the user with the provided User ID.'''
        return self.request_json("GET", f"/users/{user_id}")

    def get_guild_member(self, guild_id: Snowflake, user_id: Snowflake) -> dict | None:
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

    def get_all_guild_members(self, guild_id: Snowflake, progress_bar: bool = True) -> list[dict]:
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

    def get_highest_role(self, user: dict) -> dict:
        '''This takes in a user (you can also pass a full guild member object to save an API call)
        and returns the "highest" of their roles, according to the F1 Discord server's role hierarchy.
        If the user has left the guild, or if the user does not belong to any of the ranked roles,
        special role objects are returned to reflect this.'''
        guild_member = user if "roles" in user else self.get_guild_member(f1sc.F1_GUILD_ID, user["id"])
        if not guild_member:
            return f1sc.LEFT_SERVER_STUB_ROLE

        rankable_roles = [role for role in guild_member["roles"] if role in f1sc.ROLE_HIERARCHY]
        if not rankable_roles:
            return f1sc.BELOW_F4_STUB_ROLE

        return f1sc.ROLE_HIERARCHY[sorted(rankable_roles, key = lambda r: f1sc.ROLE_HIERARCHY[r]["rank"])[0]]

def pprint_user_name(user: dict) -> str:
    """This is a really simple method that generates the "pretty-printed"
    user_name#user_discriminator from a user object so that you don't have
    to rewrite and rewrite that one-liner every time you need it."""
    if "user" in user: # This is a guild member, not a user
        user = user["user"]
    return f"{user['username']}#{user['discriminator']}"

def generate_snowflake(input_datetime: datetime.datetime) -> str:
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
    return str(int((input_datetime.timestamp() * 1000) - f1sc.DISCORD_EPOCH) << 22)

def generate_datetime(snowflake: Snowflake) -> datetime.datetime:
    '''This parses the creation datetime from a Discord [whatever] ID.
    This essentially does the reverse of generate_snowflake().'''
    return datetime.datetime.fromtimestamp(((int(snowflake) >> 22) + f1sc.DISCORD_EPOCH) / 1000, tz = datetime.timezone.utc)

def translate_permissions_intstring(perms_intstring: str) -> set[str]:
    '''This translates a Discord "permissions intstring" - the (potentially) large
    integer-stored-as-a-string that represents a bunch of bitwise yes/nos for various
    permissions - into a list of permission NAMES (via PERMISSIONS_BIT_INDICES) whose
    bits in the integer, if represented in binary, have a value of 1.'''
    permissions_booleans = [bool(int(x)) for x in list(format(int(perms_intstring), "b"))[::-1]]
    enumerated_booleans = list(enumerate(permissions_booleans))
    return {
        f1sc.PERMISSIONS_BIT_INDICES[index]
        for (index, boolean) in enumerated_booleans
        if boolean is True
        and index in f1sc.PERMISSIONS_BIT_INDICES
    }

def export_all_permissions(connection: Connection, progress_bar: bool = True) -> None:
    '''This exports a CSV of all of the permissions on every role and every channel
    in the Discord server. This is primarily useful for backup/restoration purposes.'''

    # Retrieve all of the roles and set up the role parentage for each one.
    roles = {
        role["id"]: {
            "id": role["id"],
            "name": role["name"],
            "permissions_intstring": role["permissions"],
            "permission_names": translate_permissions_intstring(role["permissions"]),
        }
        for role in connection.get_roles(f1sc.F1_GUILD_ID)
    }
    everyone_role = roles[f1sc.EVERYONE_ROLE_ID]
    role_hierarchy = f1sc.MOD_ROLE_HIERARCHY | f1sc.FX_ROLE_HIERARCHY | f1sc.BOT_ROLE_HIERARCHY

    for role in roles.values():
        if role["id"] == f1sc.EVERYONE_ROLE_ID:
            role["parent_roles"] = [] # Special case; no parent for @everyone
        elif role["id"] not in role_hierarchy:
            role["parent_roles"] = [everyone_role]
        else:
            role["parent_roles"] = [roles[role_hierarchy[role["id"]]["parent"]]]
            while (parent_role_id := role["parent_roles"][-1]["id"]) in role_hierarchy:
                role["parent_roles"].append(roles[role_hierarchy[parent_role_id]["parent"]])

    # Retrieve all of the channels and organize them
    channels = {
        channel["id"]: {
            "id": channel["id"],
            "name": channel["name"],
            "type": channel["type"],
            "parent_id": channel["parent_id"] if "parent_id" in channel else None,
            "role_allows": {} if "permission_overwrites" not in channel else {
                po["id"]: translate_permissions_intstring(po["allow"])
                for po in channel["permission_overwrites"]
                if po["type"] == 0
                and int(po["allow"]) != 0
            },
            "role_denies": {} if "permission_overwrites" not in channel else {
                po["id"]: translate_permissions_intstring(po["deny"])
                for po in channel["permission_overwrites"]
                if po["type"] == 0
                and int(po["deny"]) != 0
            },
            "user_allows": {} if "permission_overwrites" not in channel else {
                po["id"]: translate_permissions_intstring(po["allow"])
                for po in channel["permission_overwrites"]
                if po["type"] == 1
                and int(po["allow"]) != 0
            },
            "user_denies": {} if "permission_overwrites" not in channel else {
                po["id"]: translate_permissions_intstring(po["deny"])
                for po in channel["permission_overwrites"]
                if po["type"] == 1
                and int(po["deny"]) != 0
            },
        }
        for channel in connection.get_guild_channels(f1sc.F1_GUILD_ID)
        if not ("parent_id" in channel and channel["parent_id"] in [
            "360771367274283019", # Voice category - something weird is going on here, exclude for now
            "797482862860697611", # Modmail category - channel perms here get set by the bot, so don't bother
        ])
    }

    # Retrieve data about the users that have user-specific permission overwrites.
    overwrite_user_ids = { # Creates a (distinct) set of all user IDs with overwrites
        user_id
        for channel in channels.values()
        for user_id in set(list(channel["user_allows"]) + list(channel["user_denies"]))
    }

    users = {} # Will be populated with {user_id: user}
    for user_id in tqdm(overwrite_user_ids, desc = "Retrieving user information", disable = not progress_bar):
        users[user_id] = connection.get_guild_member(guild_id = f1sc.F1_GUILD_ID, user_id = user_id)

    # Open the output file and start actually processing the entities.
    with open("permissions_export.csv", "w", encoding = "utf-8") as outfile:
        writer = csv.DictWriter(outfile, delimiter = ",", quotechar = '"', fieldnames = [
            "Channel Type", "Channel Name", "Entity Type", "Entity Name",
            "Allow/Deny", "Permission", "Necessary?", "Notes",
        ])
        writer.writeheader()

        # Process all global role permissions.
        for role in roles.values():
            for perm_name in role["permission_names"]:
                necessary = ("Yes", "")
                for parent_role in role["parent_roles"]:
                    if perm_name in parent_role["permission_names"]:
                        necessary = ("No", f"Already allowed by parent role {parent_role['name']}")
                        break

                writer.writerow({
                    "Channel Type": "Global",
                    "Channel Name": "N/A",
                    "Entity Type": "Role",
                    "Entity Name": role["name"],
                    "Allow/Deny": "Allow",
                    "Permission": perm_name,
                    "Necessary?": necessary[0],
                    "Notes": necessary[1],
                })

        # The difference between role and user permissions is that for user permissions, you have to
        # step back through their other roles to see if they have anything that conflicts with the channel.
        # For role permissions, you don't have to do that - you just check the category and the role hierarchy.

        # The difference between allows and denies (other than which permissions you're checking) is that
        # you don't have to check the role hierarchy on denies, because roles can't be denied permissions globally.

        for permission_type in ["role_allows", "role_denies", "user_allows", "user_denies"]:
            for channel in channels.values():
                everyone_denies = (
                    channel["role_denies"][f1sc.EVERYONE_ROLE_ID]
                    if f1sc.EVERYONE_ROLE_ID in channel["role_denies"]
                    else set()
                )

                for entity_id, perm_names in channel[permission_type].items():
                    for perm_name in perm_names:
                        necessary = ("Yes", "") # Initially set this to "Yes", then try to find a reason to override this

                        # If this is a role allow, does the role (or a parent) already have that permission?
                        if permission_type == "role_allows":
                            role = roles[entity_id]

                            if perm_name in everyone_denies:
                                necessary = ("Yes", "Needed to override channel's @everyone denial")
                                for parent_role in role["parent_roles"]:
                                    if (
                                        parent_role["id"] in channel["role_allows"]
                                        and perm_name in channel["role_allows"][parent_role["id"]]
                                    ):
                                        necessary = ("No", f"Already allowed by parent role {parent_role['name']}")
                                        break

                            else:
                                if perm_name in role["permission_names"]:
                                    necessary = ("No", "Already globally allowed for this role")
                                else:
                                    for parent_role in role["parent_roles"]:
                                        if perm_name in parent_role["permission_names"]:
                                            necessary = ("No", f"Already allowed by parent role {parent_role['name']}")
                                            break

                        # If this is a role deny, did the role even have those permissions in the first place?
                        if permission_type == "role_denies":
                            role = roles[entity_id]
                            perms = copy.copy(everyone_role["permission_names"])
                            for parent_role in role["parent_roles"]:
                                perms |= parent_role["permission_names"]
                            if perm_name not in perms:
                                necessary = ("No", "Role never had this permission to begin with")

                        # If this is a user allow, does the user already have the permission from a role?
                        elif permission_type == "user_allows":
                            user = users[entity_id]
                            if perm_name in everyone_denies:
                                necessary = ("Yes", "Needed to override channel's @everyone denial")
                                for user_role in [roles[role_id] for role_id in user["roles"]]:
                                    if (
                                        user_role["id"] in channel["role_allows"]
                                        and perm_name in channel["role_allows"][user_role["id"]]
                                    ):
                                        necessary = ("No", f"Already allowed by user's role {user_role['name']}")
                                        break

                            else:
                                for user_role in [roles[role_id] for role_id in user["roles"]]:
                                    if perm_name in user_role["permission_names"]:
                                        necessary = ("No", f"Already allowed by user's role {user_role['name']}")
                                        break

                        # If this is a user deny, did the user even have those permissions in the first place?
                        elif permission_type == "user_denies":
                            user = users[entity_id]
                            perms = copy.copy(everyone_role["permission_names"])

                            for user_role in [roles[role_id] for role_id in user["roles"]]:
                                perms |= user_role["permission_names"]

                            for role_id, perm_names in channel["role_allows"].items():
                                if role_id in user["roles"]:
                                    perms |= perm_names
                            for role_id, perm_names in channel["role_denies"].items():
                                if role_id in user["roles"]:
                                    perms -= perm_names
                            # Don't need to check user allows because you can't set allowed and denied simultaneously
                            # Don't need to check user denies because that's the perm we're currently looking at

                            if perm_name not in perms:
                                necessary = ("No", "User never had this permission to begin with")

                        writer.writerow({
                            "Channel Type": "Category" if channel["type"] == 4 else "Channel",
                            "Channel Name": channel["name"],
                            "Entity Type": "Role" if "role" in permission_type else "User",
                            "Entity Name": (
                                roles[entity_id]["name"]
                                if "role" in permission_type
                                else pprint_user_name(users[entity_id])
                            ),
                            "Allow/Deny": "Allow" if "allow" in permission_type else "Deny",
                            "Permission": perm_name,
                            "Necessary?": necessary[0],
                            "Notes": necessary[1],
                        })

def export_reaction_users(
    connection: Connection,
    channel_id: Snowflake,
    message_id: Snowflake,
    emoji_text: str,
    progress_bar: bool = True
) -> None:
    '''This exports a CSV of data about users that reacted to a particular message
    with a particular emoji. Users that are no longer in the server are ignored.'''
    guild_roles = connection.get_roles(f1sc.F1_GUILD_ID)
    message = connection.get_message(channel_id, message_id)
    emoji = [emoji for emoji in message["reactions"] if emoji["emoji"]["name"] == emoji_text][0]["emoji"]
    users = connection.get_reaction_users(channel_id, message_id, emoji["name"], emoji["id"])
    members = {member["user"]["id"]: member for member in connection.get_all_guild_members(f1sc.F1_GUILD_ID)}

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

def get_joins_leaves(
    connection: Connection,
    after_dt: Optional[datetime.datetime] = None,
    before_dt: Optional[datetime.datetime] = None,
    progress_bar: bool = True
) -> tuple[dict, dict]:
    '''This is a subroutine that gets all of the messages sent by Shadow in the #logs
    channel when users join or leave the server. This returns a tuple containing two dicts
    of {user_id: join/leave message} - one dict for joins, one for leaves.'''
    messages = connection.get_channel_messages(f1sc.LOGS_CHANNEL_ID, after_dt = after_dt, before_dt = before_dt, progress_bar = progress_bar)
    joins = {
        message["embeds"][0]["footer"]["text"].replace("User ID: ", ""): message
        for message in messages
        if message["author"]["id"] == f1sc.SHADOW_USER_ID
        and message["embeds"][0]["fields"][0]["value"] == "Joined the server"
    }
    leaves = {
        message["embeds"][0]["footer"]["text"].replace("User ID: ", ""): message
        for message in messages
        if message["author"]["id"] == f1sc.SHADOW_USER_ID
        and message["embeds"][0]["fields"][0]["value"] == "Left the server"
    }
    return (joins, leaves)

def get_bans(
    connection: Connection,
    after_dt: Optional[datetime.datetime] = None,
    before_dt: Optional[datetime.datetime] = None,
    progress_bar: bool = True
) -> dict:
    '''This is a subroutine that gets all of the messages sent by Formula One in the #f1-logs
    channel when a user is banned. This returns a dict of {user_id: ban message}.'''
    messages = connection.get_channel_messages(f1sc.F1_LOGS_CHANNEL_ID, after_dt = after_dt, before_dt = before_dt, progress_bar = progress_bar)
    return {
        re.search(r"\*\*User:\*\*.*\(([0-9]+)\)", message["embeds"][0]["description"]).group(1): message # type: ignore
        for message in messages
        if message["author"]["id"] == f1sc.FORMULA_ONE_USER_ID
        and "description" in message["embeds"][0]
        and "**Action:** Ban" in message["embeds"][0]["description"]
    }

def get_reports(
    connection: Connection,
    after_dt: Optional[datetime.datetime] = None,
    before_dt: Optional[datetime.datetime] = None
) -> list[dict]:
    """This is a subroutine that sweeps through the Moderation Queue Archive channel and collects
    all of the situations that were raised to the attention of the moderators, whether via
    user reports or by one of the automated message-analysis tools."""
    messages = connection.get_channel_messages(f1sc.MOD_QUEUE_ARCHIVE_CHANNEL_ID, after_dt = after_dt, before_dt = before_dt)
    report_messages = [
        message for message in messages
        if message["author"]["id"] == f1sc.FORMULA_ONE_USER_ID
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
        (report_status, actioning_moderator) = re.search(f1sc.REPORT_ACTION_REGEX, message["content"]).groups() # type: ignore

        reports.append({
            "message": message,
            "timestamp": datetime.datetime.fromisoformat(message["timestamp"]),
            "user": message["embeds"][0]["author"],
            "report_type": report_type,
            "reporter": re.search(f1sc.REPORTER_REGEX, description).groups(0)[0] if report_type == "User Report" else "N/A", # type: ignore
            "report_status": report_status,
            "actioning_moderator": actioning_moderator,
        })

    return reports

def get_fan_role_grants(
    connection: Connection,
    after_dt: Optional[datetime.datetime] = None,
    before_dt: Optional[datetime.datetime] = None
) -> dict:
    '''This is a subroutine that gets all of the times when a user was granted the Fan role
    by the Formula One bot. This returns a dict of {user_id: audit log entry}.'''
    entries = connection.get_audit_log_entries(
        user_id = f1sc.FORMULA_ONE_USER_ID,
        action_type = f1sc.MEMBER_ROLE_UPDATE_ACTION_TYPE,
        before_dt = before_dt,
        after_dt = after_dt
    )
    return {
        entry["target_id"]: entry
        for entry in entries
        if entry["changes"][0]["key"] == "$add"
        and entry["changes"][0]["new_value"][0]["name"] == "Fan"
    }

def get_channel_emoji_usage(
    connection: Connection,
    channel_id: Snowflake,
    after_dt: Optional[datetime.datetime] = None,
    before_dt: Optional[datetime.datetime] = None,
    limit: int = 15000
) -> dict[str, dict]:
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

def export_bouncing_users(
    connection: Connection,
    after_dt: Optional[datetime.datetime] = None,
    before_dt: Optional[datetime.datetime] = None,
    progress_bar: bool = True
) -> None:
    '''This exports a CSV of data about users that "bounced" from the server:
    users that join and then quickly leave the server.'''
    (joins, leaves) = get_joins_leaves(connection, after_dt = after_dt, before_dt = before_dt, progress_bar = progress_bar)
    bans = get_bans(connection, after_dt = after_dt, before_dt = before_dt, progress_bar = progress_bar)
    #fan_role_grants = get_fan_role_grants(connection: Connection, after_dt = after_dt, before_dt = before_dt)
    members = {member["user"]["id"]: member for member in connection.get_all_guild_members(f1sc.F1_GUILD_ID)}

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

def export_fan_eligible_users(connection: Connection) -> None:
    '''This exports a CSV of data about users that are eligible to receive the Fan role,
    but have not yet been granted it.'''
    members = connection.get_all_guild_members(f1sc.F1_GUILD_ID)
    guild_roles = connection.get_roles(f1sc.F1_GUILD_ID)
    eligible_members = [
        member for member in members
        if not member["pending"]
        and f1sc.FAN_ROLE_ID not in member["roles"]
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

def export_emoji_usage(
    connection: Connection,
    after_dt: Optional[datetime.datetime] = None,
    before_dt: Optional[datetime.datetime] = None,
    limit: int = 15000
) -> None:
    '''This exports a CSV of data about which emoji were used, in which channels,
    and with what frequency, over the date range provided.'''
    emoji_usage = {}
    channels_to_scan = [
        f1sc.F1_GENERAL_CHANNEL_ID,
        f1sc.F1_DISCUSSION_CHANNEL_ID,
        f1sc.F1_GRANDSTAND_CHANNEL_ID,
        f1sc.PADDOCK_CLUB_CHANNEL_ID,
        f1sc.OFFTRACK_CHANNEL_ID,
        f1sc.SANDBOX_CHANNEL_ID
    ]

    for channel_id in channels_to_scan:
        emoji_usage = emoji_usage | get_channel_emoji_usage(
            connection,
            channel_id,
            after_dt = after_dt,
            before_dt = before_dt,
            limit = limit,
        )

    guild_emoji = {emoji["name"]: emoji["id"] for emoji in connection.get_all_emoji(f1sc.F1_GUILD_ID)}

    with open("emoji_usage.csv", "w", encoding = "utf-8") as outfile:
        writer = csv.writer(outfile, delimiter = ',', quotechar = '"')
        writer.writerow(["Emoji Name", "Channel", "Times Used in Messages", "Times Used as Reaction"])
        for channel, usage_dict in emoji_usage.items():
            for emoji, emoji_dict in usage_dict.items():
                if emoji in guild_emoji:
                    writer.writerow([emoji, channel, emoji_dict["messages"], emoji_dict["reactions"]])

    all_used_emoji = list(itertools.chain.from_iterable([emojis.keys() for _, emojis in emoji_usage.items()]))
    unused_emoji = sorted([emoji for emoji in guild_emoji.keys() if emoji not in all_used_emoji])

    with open("unused_emoji.csv", "w", encoding = "utf-8") as outfile:
        outfile.write("\n".join(["Emoji Name"] + unused_emoji))

def export_moderation_statistics(
    connection: Connection,
    after_dt: Optional[datetime.datetime] = None,
    before_dt: Optional[datetime.datetime] = None
) -> None:
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

def export_all_members(connection: Connection) -> None:
    """This exports a CSV of all server members."""
    members = connection.get_all_guild_members(f1sc.F1_GUILD_ID)
    with open("members.csv", "w", encoding = "utf-8") as outfile:
        writer = csv.writer(outfile, delimiter = ',', quotechar = '"')
        writer.writerow(["User ID", "User Name", "Highest FX Role"])

        for member in members:
            writer.writerow([
                member["user"]["id"],
                member["user"]["username"] + "#" + member["user"]["discriminator"],
                connection.get_highest_role(member)["name"]
            ])

def export_member_roles(connection: Connection) -> None:
    """This exports a CSV of all roles held by all members in the server."""
    roles_dict = {role["id"]: role for role in connection.get_roles(f1sc.F1_GUILD_ID)}
    members = connection.get_all_guild_members(f1sc.F1_GUILD_ID)

    with open("member_roles.csv", "w", encoding = "utf-8") as outfile:
        writer = csv.writer(outfile, delimiter = ',', quotechar = '"')
        writer.writerow(["User ID", "User Name", "Role ID", "Role Name"])

        for member in members:
            if member["roles"] == []:
                continue

            for role_id in member["roles"]:
                if role_id in roles_dict:
                    writer.writerow([
                        member["user"]["id"],
                        member["user"]["username"] + "#" + member["user"]["discriminator"],
                        role_id,
                        roles_dict[role_id]["name"],
                    ])
