"""This script uses the f1_server_analytics toolkit to export data about server permissions.

Not only does this dump out data about what permissions are in place (for backup purposes),
it also attempts to determine whether each permission grant/deny is actually necessary -
that is, whether the permission setting could be removed without impacting anything."""

# pylint: disable = invalid-name, too-few-public-methods, too-many-instance-attributes

import csv
import copy
from tqdm import tqdm
from typing import Literal, Optional

import f1_server_analytics as f1sa
import f1_server_constants as f1sc

ROLE_HIERARCHY = f1sc.MOD_ROLE_HIERARCHY | f1sc.FX_ROLE_HIERARCHY | f1sc.BOT_ROLE_HIERARCHY

# These are permissions that are okay to see explicitly denied even when they're not technically necessary.
# This is usually because some roles get these permissions, but it wouldn't be appropriate to add that
# to the role hierarchy.
ACCEPTABLE_DENIES = {"Add Reactions", "Attach Files", "Embed Links"}

# These are permissions entities that appear on channels in the API, but not in Discord's UI.
# Adding them to this set allows them to be ignored.
GHOST_PERMISSIONS = { # (Channel ID, User/Role ID)
    ("1042140830158291045", "1042395617399414815"), # GT44#3560 in sports
    ("829816960568655924", "713110394780123197"), # DanielRGolding#4152 in r/Formula1 Stage
    ("825702140118564905", "808002254710898708"), # 𝙂𝙪𝙘𝙘𝙞 𝙘𝙤𝙛𝙛𝙞𝙣#0054 in f1-grandstand-read-pinned
    ("1024053231246119053", "376222609525964811"), # FknParker999 예언#4645 in live voice
    ("1024053231246119053", "218003903256592385"), # DatedRhyme#9463 in live voice
    ("876046265111167016", "521898375726104579"), # ThatGuyAnderson#5404 in f1-general
    ("431627942766968834", "459068609558347776"), # XXXRiley#8835 in f1tv-n-broadcast
    ("314949863911587840", "808002254710898708"), # 𝙂𝙪𝙘𝙘𝙞 𝙘𝙤𝙛𝙛𝙞𝙣#0054 in paddock
    ("436530724292526081", "422422296620302337"), # omegagamer737#1384 in f1-fantasy-official
    ("998922729455636570", "733135516215804055"), # Matias 888#8668 in sim-racing-beta
    ("998922729455636570", "215270136712527872"), # GODRAV#2364 in sim-racing-beta
    ("998922729455636570", "437355269098438667"), # Arend#2562 in sim-racing-beta
    ("998922729455636570", "298274436803723274"), # Lucas#9178 in sim-racing-beta
    ("998922729455636570", "989069445433528400"), # anonymouhh#2298 in sim-racing-beta
    ("998922729455636570", "856286790185123891"), # Memphis5050#4897 in sim-racing-beta
    ("998922729455636570", "426860313888161794"), # hush#0848 in sim-racing-beta
    ("959447281885671485", "830192967250608178"), # jensonvelcro#1172 in place_voting
    ("959447281885671485", "188856766136713216"), # trom.bonne#2282 in place_voting
    ("959447281885671485", "755277590570336326"), # Hamilton✪Forever#3056 in place_voting
    ("959447281885671485", "448143136494190592"), # Drac#6798 in place_voting
    ("959447281885671485", "232250374214516737"), # Das_Blinkenlights#0434 in place_voting
    ("960856313615777794", "830192967250608178"), # jensonvelcro#1172 in place_hall-of-shame
    ("960856313615777794", "448143136494190592"), # Drac#6798 in place_hall-of-shame
    ("960856313615777794", "188856766136713216"), # trom.bonne#2282 in place_hall-of-shame
    ("960856313615777794", "755277590570336326"), # Hamilton✪Forever#3056 in place_hall-of-shame
    ("940631898835795998", "808002254710898708"), # 𝙂𝙪𝙘𝙘𝙞 𝙘𝙤𝙛𝙛𝙞𝙣#0054 in helper-interest
    ("942836348635738182", "808002254710898708"), # 𝙂𝙪𝙘𝙘𝙞 𝙘𝙤𝙛𝙛𝙞𝙣#0054 in feedback-temp
    ("687707105863663616", "408185351363100673"), # Severina#6247 in quarantine
    ("687707105863663616", "422422296620302337"), # omegagamer737#1384 in quarantine
    ("687707105863663616", "533346534549356555"), # andre_SC#7101 in quarantine
}

Snowflake = str
PermName = str
NecessaryTuple = tuple[Literal["Yes", "No", "Error"], str]

class Role:
    """A Discord role."""
    role_id: Snowflake
    name: str
    position: int
    permissions_intstring: str
    permission_names: set[PermName]
    parent_roles: list["Role"] = []

    def __init__(self, role_json: dict) -> None:
        self.role_id = role_json["id"]
        self.name = role_json["name"]
        self.position = role_json["position"]
        self.permissions_intstring = role_json["permissions"]
        self.permission_names = f1sa.translate_permissions_intstring(self.permissions_intstring)

    def __str__(self) -> str:
        return f"Role {self.name}"

    def __repr__(self) -> str:
        return (
            "<Role: "
            f"role_id: {self.role_id}, name: {self.name}, position = {self.position}, "
            f"permissions_intstring: {self.permissions_intstring}, permission_names: {self.permission_names}, "
            ">"
        )

class Channel:
    """A Discord channel."""
    channel_id: Snowflake
    name: str
    type: int
    position: int
    parent_id: Optional[Snowflake]

    role_allows: dict[Snowflake, set[PermName]]
    role_denies: dict[Snowflake, set[PermName]]
    user_allows: dict[Snowflake, set[PermName]]
    user_denies: dict[Snowflake, set[PermName]]

    def __init__(self, channel_json: dict) -> None:
        self.channel_id = channel_json["id"]
        self.name = channel_json["name"]
        self.type = channel_json["type"]
        self.position = channel_json["position"]
        self.parent_id = channel_json.get("parent_id")

        self.role_allows = {} if "permission_overwrites" not in channel_json else {
            po["id"]: f1sa.translate_permissions_intstring(po["allow"])
            for po in channel_json["permission_overwrites"]
            if po["type"] == 0
            and int(po["allow"]) != 0
            and (self.channel_id, po["id"]) not in GHOST_PERMISSIONS
        }
        self.role_denies = {} if "permission_overwrites" not in channel_json else {
            po["id"]: f1sa.translate_permissions_intstring(po["deny"])
            for po in channel_json["permission_overwrites"]
            if po["type"] == 0
            and int(po["deny"]) != 0
            and (self.channel_id, po["id"]) not in GHOST_PERMISSIONS
        }
        self.user_allows = {} if "permission_overwrites" not in channel_json else {
            po["id"]: f1sa.translate_permissions_intstring(po["allow"])
            for po in channel_json["permission_overwrites"]
            if po["type"] == 1
            and int(po["allow"]) != 0
            and (self.channel_id, po["id"]) not in GHOST_PERMISSIONS
        }
        self.user_denies = {} if "permission_overwrites" not in channel_json else {
            po["id"]: f1sa.translate_permissions_intstring(po["deny"])
            for po in channel_json["permission_overwrites"]
            if po["type"] == 1
            and int(po["deny"]) != 0
            and (self.channel_id, po["id"]) not in GHOST_PERMISSIONS
        }

    def __str__(self) -> str:
        return f"Channel {self.name}"

    def __repr__(self) -> str:
        return (
            "<Channel: "
            f"channel_id: {self.channel_id}, name: {self.name}, position = {self.position}, type: {self.type}, "
            f"parent_id: {self.parent_id}, role_allows: {self.role_allows}, role_denies: {self.role_denies}, "
            f"user_allows: {self.user_allows}, user_denies: {self.user_denies}, "
            ">"
        )

    def is_role_perm_allowed(self, role: Role, perm_name: PermName) -> bool:
        """Returns a boolean indicating whether the provided Role is
        explicitly granted the provided permission in this Channel."""
        if role.role_id not in self.role_allows:
            return False
        if perm_name in self.role_allows[role.role_id]:
            return True
        return False

    def is_role_perm_denied(self, role: Role, perm_name: PermName) -> bool:
        """Returns a boolean indicating whether the provided Role is
        explicitly denied the provided permission in this Channel."""
        if role.role_id not in self.role_denies:
            return False
        if perm_name in self.role_denies[role.role_id]:
            return True
        return False

def get_roles(connection: f1sa.Connection) -> dict[Snowflake, Role]:
    """Retrieves the list of roles from Discord, organizes and reformats them."""

    roles = {
        role_json["id"]: Role(role_json)
        for role_json in connection.get_roles(f1sc.F1_GUILD_ID)
    }

    everyone_role = roles[f1sc.EVERYONE_ROLE_ID]

    for role in [r for r in roles.values() if r.role_id != f1sc.EVERYONE_ROLE_ID]:
        if role.role_id not in ROLE_HIERARCHY:
            role.parent_roles = [everyone_role]
        else:
            role.parent_roles = [roles[ROLE_HIERARCHY[role.role_id]["parent"]]]
            while (parent_role_id := role.parent_roles[-1].role_id) in ROLE_HIERARCHY:
                role.parent_roles.append(roles[ROLE_HIERARCHY[parent_role_id]["parent"]])

    return roles

def get_channels(connection: f1sa.Connection) -> dict[Snowflake, Channel]:
    """Retrieves the list of channels from Discord, organizes and reformats them."""
    return {
        channel_json["id"]: Channel(channel_json)
        for channel_json in connection.get_guild_channels(f1sc.F1_GUILD_ID)
    }

def get_users(connection: f1sa.Connection, channels: dict[Snowflake, Channel]) -> dict[Snowflake, dict]:
    """Retrieves the list of user JSONs from Discord for the users with permission overwrites."""
    overwrite_user_ids = { # Creates a (distinct) set of all user IDs with overwrites
        user_id
        for channel in channels.values()
        for user_id in set(list(channel.user_allows) + list(channel.user_denies))
    }

    users = {} # Will be populated with {user_id: user}
    for user_id in tqdm(overwrite_user_ids, desc = "Retrieving user information"):
        users[user_id] = connection.get_guild_member(guild_id = f1sc.F1_GUILD_ID, user_id = user_id)

    return users

def get_channel_everyone_denies(channel: Channel) -> set[PermName]:
    """Returns the set of permission names that are denied to @everyone in the provided channel."""
    try:
        return channel.role_denies[f1sc.EVERYONE_ROLE_ID]
    except KeyError:
        return set()

def process_roles(roles: dict[Snowflake, Role]) -> list[dict]:
    """Process the global role permissions and return a list of dicts
    ready to be passed off to the writer."""

    output_records = []
    for role in roles.values():
        for perm_name in role.permission_names:
            necessary = ("Yes", "")
            for parent_role in reversed(role.parent_roles):
                if perm_name in parent_role.permission_names:
                    necessary = ("No", f"Already allowed by parent role {parent_role.name}")
                    break

            output_records.append({
                "Channel Type": "Global",
                "Channel Name": "N/A",
                "Channel ID": "N/A",
                "Entity Type": "Role",
                "Entity Name": role.name,
                "Entity ID": role.role_id,
                "Allow/Deny": "Allow",
                "Permission": perm_name,
                "Necessary?": necessary[0],
                "Notes": necessary[1],
            })

    return output_records

def process_channel_role_allows(
    channel: Channel,
    roles: dict[Snowflake, Role]
) -> list[dict]:
    """Process the channel-specific role allows and return a list of dicts
    ready to be passed off to the writer."""

    output_records = []
    for role_id, perm_names in sorted(channel.role_allows.items(), key = lambda x: roles[x[0]].position):
        role = roles[role_id]
        for perm_name in perm_names:
            necessary = is_role_allow_necessary(channel, role, perm_name)
            output_records.append({
                "Channel Type": "Category" if channel.type == 4 else "Channel",
                "Channel Name": channel.name,
                "Channel ID": channel.channel_id,
                "Entity Type": "Role",
                "Entity Name": role.name,
                "Entity ID": role.role_id,
                "Allow/Deny": "Allow",
                "Permission": perm_name,
                "Necessary?": necessary[0],
                "Notes": necessary[1],
            })

    return output_records

def process_channel_role_denies(
    channel: Channel,
    roles: dict[Snowflake, Role]
) -> list[dict]:
    """Process the channel-specific role denies and return a list of dicts
    ready to be passed off to the writer."""

    output_records = []
    for role_id, perm_names in sorted(channel.role_denies.items(), key = lambda x: roles[x[0]].position):
        role = roles[role_id]
        for perm_name in perm_names:
            necessary = is_role_deny_necessary(channel, role, perm_name)
            output_records.append({
                "Channel Type": "Category" if channel.type == 4 else "Channel",
                "Channel Name": channel.name,
                "Channel ID": channel.channel_id,
                "Entity Type": "Role",
                "Entity Name": role.name,
                "Entity ID": role.role_id,
                "Allow/Deny": "Deny",
                "Permission": perm_name,
                "Necessary?": necessary[0],
                "Notes": necessary[1],
            })

    return output_records

def process_channel_user_allows(
    channel: Channel,
    roles: dict[Snowflake, Role],
    users: dict[Snowflake, dict],
) -> list[dict]:
    """Process the channel-specific user allows and return a list of dicts
    ready to be passed off to the writer."""

    output_records = []
    for user_id, perm_names in channel.user_allows.items():
        user = users[user_id]
        for perm_name in perm_names:
            necessary = is_user_allow_necessary(channel, user, perm_name, roles)
            output_records.append({
                "Channel Type": "Category" if channel.type == 4 else "Channel",
                "Channel Name": channel.name,
                "Channel ID": channel.channel_id,
                "Entity Type": "User",
                "Entity Name": f1sa.pprint_user_name(user),
                "Entity ID": user_id,
                "Allow/Deny": "Allow",
                "Permission": perm_name,
                "Necessary?": necessary[0],
                "Notes": necessary[1],
            })

    return output_records

def process_channel_user_denies(
    channel: Channel,
    roles: dict[Snowflake, Role],
    users: dict[Snowflake, dict],
) -> list[dict]:
    """Process the channel-specific user denies and return a list of dicts
    ready to be passed off to the writer."""

    output_records = []
    for user_id, perm_names in channel.user_denies.items():
        user = users[user_id]
        for perm_name in perm_names:
            necessary = is_user_deny_necessary(channel, user, perm_name, roles)
            output_records.append({
                "Channel Type": "Category" if channel.type == 4 else "Channel",
                "Channel Name": channel.name,
                "Channel ID": channel.channel_id,
                "Entity Type": "User",
                "Entity Name": f1sa.pprint_user_name(user),
                "Entity ID": user_id,
                "Allow/Deny": "Deny",
                "Permission": perm_name,
                "Necessary?": necessary[0],
                "Notes": necessary[1],
            })

    return output_records

def is_role_allow_necessary(
    channel: Channel,
    role: Role,
    perm_name: PermName,
) -> NecessaryTuple:
    """Determine whether an individual allowance of a particular permission
    to a particular role in a particular channel is necessary or not."""

    necessary = ("Yes", "")

    #if channel.channel_id == "360811693393182732" and  role.name == "Marshals":
    #    breakpoint()

    # If the permission is denied to @everyone, then the new necessary status
    # is that yes, it's necessary because it's denied to everyone.
    # But we still need to check the parent roles before committing to that.
    if perm_name in get_channel_everyone_denies(channel):
        necessary = ("Yes", "Needed to override channel's @everyone denial")

    else: # Only check this if it's not denied to @everyone in this channel
        # If this role already has this permission globally, it doesn't need to be re-granted.
        if perm_name in role.permission_names:
            return ("No", "Already globally allowed for this role")

        # If the permission is granted globally by any parent role, it's not necessary.
        for parent_role in reversed([role] + role.parent_roles):
            if perm_name in parent_role.permission_names:
                return ("No", f"Already globally allowed by parent role {parent_role.name}")

    # If the permission is granted in this channel by any parent role, it's also not necessary.
    # We can't do these checks in the same step, because we want notifications about global
    # grants to supersede notifications about channel grants. (Trust me.)
    for parent_role in reversed(role.parent_roles):
        if channel.is_role_perm_allowed(parent_role, perm_name):
            return ("No", f"Already allowed in this channel by parent role {parent_role.name}")

    return necessary

def is_role_deny_necessary(
    channel: Channel,
    role: Role,
    perm_name: PermName,
) -> NecessaryTuple:
    """Determine whether an individual denial of a particular permission
    to a particular role in a particular channel is necessary or not."""

    # Some special-case permissions are automatically allowed.
    # See the comment above ACCEPTABLE_DENIES.
    if perm_name in ACCEPTABLE_DENIES:
        return ("Yes", "Special exception - this permission is always allowed to be denied")

    # If there are any parent roles (except @everyone) that GRANT the permission, this denial DOES NOT WORK.
    # Discord doesn't know about role parentage, and "can" beats "can't", so the permission is granted.
    for parent_role in [r for r in role.parent_roles if r.role_id != f1sc.EVERYONE_ROLE_ID]:
        if channel.is_role_perm_allowed(parent_role, perm_name):
            return ("Error", f"Blocked by explicit grant in this channel to parent role {parent_role.name}")

    # We don't need to re-deny permissions that are already denied to a parent role.
    for parent_role in reversed(role.parent_roles):
        if channel.is_role_perm_denied(parent_role, perm_name):
            return ("No", f"Already denied in this channel by parent role {parent_role.name}")

    # If the role or its parents never had this permission to begin with, we don't need to deny it.
    if perm_name not in set().union(*[r.permission_names for r in [role] + role.parent_roles]):
        return ("No", "Role never had this permission to begin with")

    return ("Yes", "")

def is_user_allow_necessary(
    channel: Channel,
    user: dict,
    perm_name: PermName,
    roles: dict[Snowflake, Role],
) -> NecessaryTuple:
    """Determine whether an individual allowance of a particular permission
    to a particular user in a particular channel is necessary or not."""

    necessary = ("Yes", "")

    # If the permission is denied to @everyone, then the new default status
    # is that yes, it's necessary because it's denied to everyone.
    # But we still need to check the parent roles before committing to that.
    if perm_name in get_channel_everyone_denies(channel):
        necessary = ("Yes", "Needed to override channel's @everyone denial")

    else: # Only check this if it's not denied to @everyone in this channel
        # If the permission is granted globally by any parent role, it's not necessary.
        for user_role in sorted([roles[role_id] for role_id in user["roles"]], key = lambda r: r.position):
            if perm_name in user_role.permission_names: # Granted globally
                return ("No", f"Already globally allowed by user's role {user_role.name}")

    # If the permission is granted in this channel by any parent role, it's also not necessary.
    # We can't do these checks in the same step, because we want notifications about global
    # grants to supersede notifications about channel grants. (Trust me.)
    for user_role in sorted([roles[role_id] for role_id in user["roles"]], key = lambda r: r.position):
        if channel.is_role_perm_allowed(user_role, perm_name): # Or granted in this channel
            return ("No", f"Already allowed in this channel by user's role {user_role.name}")

    return necessary

def is_user_deny_necessary(
    channel: Channel,
    user: dict,
    perm_name: PermName,
    roles: dict[Snowflake, Role],
) -> NecessaryTuple:
    """Determine whether an individual denial of a particular permission
    to a particular user in a particular channel is necessary or not."""

    # Build up the user's permission set, starting with permissions from @everyone
    perms = copy.deepcopy(roles[f1sc.EVERYONE_ROLE_ID].permission_names)

    # Add in any permissions the user gets from the global permissions of their roles
    for user_role in [roles[role_id] for role_id in user["roles"]]:
        perms |= user_role.permission_names

    # Add in any permissions the user gets from the channel-specific permissions of their roles
    for role_id, perm_names in channel.role_allows.items():
        if role_id in user["roles"]:
            perms |= perm_names

    # Remove any permissions the user is denied from channel-specific denials of their roles
    for role_id, perm_names in channel.role_denies.items():
        if role_id in user["roles"]:
            perms -= perm_names

    # We don't need to check the channel's user_allows because you can't set allowed and denied simultaneously

    if perm_name not in perms:
        return ("No", "User never had this permission to begin with")
    return ("Yes", "")

def export_permissions():
    """Export all permission overwrites in the server, and assess whether they're necessary."""

    with f1sa.Connection(f1sa.TOKEN) as conn:
        roles = get_roles(conn)
        channels = get_channels(conn)
        users = get_users(conn, channels)

    with open("permissions_export.csv", "w", encoding = "utf-8") as outfile:
        writer = csv.DictWriter(outfile, delimiter = ",", quotechar = '"', fieldnames = [
            "Channel Type", "Channel Name", "Channel ID", "Entity Type", "Entity Name",
            "Entity ID", "Allow/Deny", "Permission", "Necessary?", "Notes",
        ])

        writer.writeheader()
        writer.writerows(process_roles(roles))

        for channel in sorted(channels.values(), key = lambda c: c.position):
            writer.writerows(process_channel_role_allows(channel, roles))
            writer.writerows(process_channel_role_denies(channel, roles))
            writer.writerows(process_channel_user_allows(channel, roles, users))
            writer.writerows(process_channel_user_denies(channel, roles, users))

def export_empty_permissions():
    """Export all permission overwrites in the server that don't actually do anything."""
    with f1sa.Connection(f1sa.TOKEN) as conn:
        channels_json = conn.get_guild_channels(f1sc.F1_GUILD_ID)
        roles_dict = {role["id"]: role for role in conn.get_roles(f1sc.F1_GUILD_ID)}

        empty_permissions = []
        for channel_json in channels_json:
            if "permission_overwrites" in channel_json:
                empty_permissions += [
                    [channel_json["name"], roles_dict[po["id"]]["name"]]
                    for po in channel_json["permission_overwrites"]
                    if po["type"] == 0 # Role overwrites only
                    and po["id"] != f1sc.EVERYONE_ROLE_ID
                    and int(po["allow"]) == 0
                    and int(po["deny"]) == 0
                ]

        if empty_permissions:
            print(
                f"Found {len(empty_permissions)} permission overwrites with no grants/denies. "
                "See empty_permissions.csv for more information."
            )
            with open("empty_permissions.csv", "w", encoding = "utf-8") as outfile:
                writer = csv.writer(outfile, delimiter = ",", quotechar = '"')
                writer.writerow(["Channel Name", "Entity Name"])
                writer.writerows(empty_permissions)

export_permissions()
export_empty_permissions()
