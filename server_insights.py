#! /usr/bin/env python
# pylint: disable = unused-variable, forgotten-debug-statement, missing-module-docstring

import csv # pylint: disable = unused-import
import apiclient, google, time
from tqdm import tqdm

OAUTH_SCOPES = [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/spreadsheets"
]
PRIVATE_KEY_FILE = "private_key_file.json"

URL_BASE = 'https://sheets.googleapis.com/v4/spreadsheets/'
STATISTICS_SHEET_ID = '12xnb6-Cwaytpzqua6t7aG08QQajkNB89SnG1uR7CDGs'

BASE_SLEEP_DELAY = 1

DATA_TABS = [
    {"filename": "guild-activation.csv", "a1_range": "'Activation'!A:D"},
    {"filename": "guild-communicators.csv", "a1_range": "'Communicators'!A:C"},
    {"filename": "guild-leavers.csv", "a1_range": "'Leavers Raw'!A:C"},
    {"filename": "guild-message-activity.csv", "a1_range": "'Messages'!A:C"},
    {"filename": "guild-muters.csv", "a1_range": "'Muters Raw'!A:C"},
    {"filename": "guild-retention.csv", "a1_range": "'Retention'!A:C"},
]

class Spreadsheet:
    '''This wraps a Google API Client Spreadsheets object and exposes
    its underlying methods in a way that doesn't suck.'''
    # pylint: disable = missing-function-docstring
    def __init__(self, private_key_file, spreadsheet_id):
        self.credentials = google.oauth2.service_account.Credentials.from_service_account_file(
            private_key_file,
            scopes = OAUTH_SCOPES,
        )
        self.service = apiclient.discovery.build(
            serviceName = "sheets",
            version = "v4",
            credentials = self.credentials
        )
        self.resource = self.service.spreadsheets() # pylint: disable = no-member

        self.spreadsheet_id = spreadsheet_id
        self.last_call = time.time()
        self.sleep_delay = BASE_SLEEP_DELAY

    def bucket_sleep(self):
        time_since_last_call = round(time.time() - self.last_call, 4)
        time_to_sleep = max(self.sleep_delay - time_since_last_call, 0)
        if time_to_sleep > 0:
            time.sleep(time_to_sleep)

    def get_spreadsheet(self):
        self.bucket_sleep()
        return self.resource.get(spreadsheetId = self.spreadsheet_id).execute()

    def clear_a1_ranges(self, a1_ranges):
        self.bucket_sleep()
        return self.resource.values().batchClear(
            spreadsheetId = self.spreadsheet_id,
            body = {"ranges": a1_ranges}
        ).execute()

    def append_rows_to_a1_range(self, a1_range, rows):
        self.bucket_sleep()
        return self.resource.values().append(
            spreadsheetId = self.spreadsheet_id,
            range = a1_range,
            valueInputOption = "USER_ENTERED",
            body = {
                "majorDimension": "ROWS",
                "values": rows
            }
        ).execute()

def main():
    '''Handle top-level functionality.'''
    s = Spreadsheet(PRIVATE_KEY_FILE, STATISTICS_SHEET_ID)

    for tab in tqdm(DATA_TABS):
        s.clear_a1_ranges(tab["a1_range"])
        with open(tab["filename"], "r") as infile:
            reader = csv.reader(infile, delimiter = ",", quotechar = "'")
            append = s.append_rows_to_a1_range(
                a1_range = tab["a1_range"],
                rows = list(reader)
            )

if __name__ == "__main__":
    main()
