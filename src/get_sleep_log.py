from datetime import datetime
import urllib.request
import json
from pathlib import Path

from keys import CLIENT_ID, CLIENT_SECRET, REDIRECT_URL
from verify_oath2 import FitbitAuthorization


def get_sleep_log_by_date_range(
    access_token: str,
    start_date: datetime,
    end_date: datetime,
):

    url = (
        "https://api.fitbit.com/1.2/user/-/sleep/date/"
        f"{start_date:%Y-%m-%d}/{end_date:%Y-%m-%d}.json"
    )
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    req = urllib.request.Request(url=url, headers=headers)
    with urllib.request.urlopen(req) as res:
        body = json.load(res)
    print(body)

    output_filename = Path("temp.json")
    with output_filename.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(body, f, indent=2)


if __name__ == "__main__":
    fitbit_auth = FitbitAuthorization(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_url=REDIRECT_URL,
        is_debug=True,
    )
    access_token = fitbit_auth.get_access_token()
    start_date = datetime(2025, 1, 1)
    end_date = datetime(2025, 1, 1)

    get_sleep_log_by_date_range(access_token, start_date, end_date)
