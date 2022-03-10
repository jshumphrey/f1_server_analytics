#! /usr/bin/env python
'''This is a standalone script to dump out information about the F1 Discord server and its users.'''

import csv, dotenv, logging, os, requests, time # pylint: disable = unused-import
from tqdm import tqdm # pylint: disable = unused-import

# Configure the logger so that we have a logger object to use.
logging.basicConfig(level = logging.INFO)
logger = logging.getLogger("f1discord")

dotenv.load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")

URL_BASE = "https://discord.com/api/v9"
BASE_SLEEP_DELAY = 1.0 # This is the number of seconds to sleep between requests.
MAX_FAILURES = 5

F1_GUILD_ID = "177387572505346048"
ANNOUNCEMENTS_CHANNEL_ID = "361137849736626177"
REACTED_MESSAGE_ID = "935642010419879957"

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

def main():
    '''Execute top-level functionality.'''
    with Connection(TOKEN) as c:
        guild = c.get_guild(F1_GUILD_ID)
        guild_roles = c.get_roles(F1_GUILD_ID)
        message = c.get_message(ANNOUNCEMENTS_CHANNEL_ID, REACTED_MESSAGE_ID)
        emoji = [emoji for emoji in message["reactions"] if emoji["emoji"]["name"] == "Bonk"][0]["emoji"]
        users = c.get_reaction_users(ANNOUNCEMENTS_CHANNEL_ID, REACTED_MESSAGE_ID, emoji["name"], emoji["id"])

        with open("reacted_users.csv", "w") as outfile:
            writer = csv.writer(outfile, delimiter = ',', quotechar = '"')
            writer.writerow(["User ID", "User Name", "Display Name", "Join Date", "Highest FX Role", "Has NoXP?", "Is Banished?"])

            for user in tqdm(users, desc = "Retrieving member data for users"):
                member = c.get_guild_member(guild["id"], user["id"])
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

main()