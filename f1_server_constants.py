"""This file defines a large number of "constants" and other magic strings that are used by
the f1_server_analytics script. These were moved here once they started to take up too much
space in the header of f1_server_analytics."""

#API-related constants
DISCORD_EPOCH = 1420070400000

URL_BASE = "https://discord.com/api/v9"
BASE_SLEEP_DELAY = 0.5 # This is the number of seconds to sleep between requests.
MAX_FAILURES = 5

"""Hardcoded constants regarding the channel and role structure of the F1 discord server."""
F1_GUILD_ID = "177387572505346048"

# Channels
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

# Users
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

# Roles
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

# Other
MOD_APPLICATION_MESSAGE_ID = "935642010419879957"
MEMBER_UPDATE_ACTION_TYPE = 24
MEMBER_ROLE_UPDATE_ACTION_TYPE = 25

# Permissions bit indices. For example, the bit in the 0th position of a Discord
# permissions binary integer corresponds to the "Create Server Invite" permission.
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

# Regexes for parsing moderation activity.
REPORT_ACTION_REGEX = r"(Punished|Ignored|Banned|Escalated) by \*\*([^\s]+.+\#\d{4})\*\*"
REPORTER_REGEX = r"\*\*Reporter\:\*\* ([^\s]+.+\#\d{4})"
