import random
import string
import hashlib
import base64
import time
import urllib.parse
import configparser
import json
import dataclasses
from datetime import datetime
import queue

# third-party library
import requests

# my python files
from httpserver import MyHttpServer
from settings import AUTH_DATA_FILENAME
from keys import CLIENT_ID, CLIENT_SECRET
from test_values import REFRESH_TOKEN, ACCESS_TOKEN


AUTH_REQ = "AUTHORIZATION_REQUEST_PARAMETERS"
AUTH_RESP = "AUTHORIZATION_RESPONSE"
TOKEN_REQ = "TOKEN_REQUEST_PARAMETERS"
TOKEN_RESP = "TOKEN_RESPONSE_PARAMETERS"


def sha256hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).digest()


def base64_url_encode(value: str) -> str:
    return base64.urlsafe_b64encode(value).decode("utf-8").replace("=", "")


def create_random_str(len: int) -> str:
    ALPHANUMERIC_CHARS = string.ascii_letters + string.digits
    return "".join([random.choice(ALPHANUMERIC_CHARS) for _ in range(len)])


@dataclasses.dataclass
class AuthorizationRequestParameters:
    client_id: str
    code_challenge: str
    state: str
    redirect_uri: str
    scope: list
    code_challenge_method: str = "S256"
    response_type: str = "code"

    def __post_init__(self):
        pass

    def __str__(self) -> str:
        scope_str = "+".join(self.scope)
        params_list = [
            f"response_type={self.response_type}",
            f"client_id={self.client_id}",
            f"scope={scope_str}",
            f"code_challenge={self.code_challenge}",
            f"code_challenge_method={self.code_challenge_method}",
            f"state={self.state}",
            f"redirect_uri={create_encoded_url(self.redirect_uri)}",
        ]
        return "&".join(params_list)


@dataclasses.dataclass
class TokenRequestParameters:
    client_id: str
    code_verifier: str  # PKCE Code Verifier
    redirect_uri: str
    code: str
    grant_type: str = "authorization_code"

    def __post_init__(self):
        pass


@dataclasses.dataclass
class ProofKeyForCodeExchange:
    len_: int
    code_verifier: str = dataclasses.field(init=False)
    code_challenge: str = dataclasses.field(init=False)

    def __post_init__(self):
        self.code_verifier = create_random_str(self.len_)
        self.code_challenge = base64_url_encode(sha256hash(self.code_verifier))


def create_encoded_url(url: str) -> str:
    return urllib.parse.quote(url, safe="")


class Authorization:
    def __init__(self):
        pass

    def generate_pkce(self):
        pass

    def request_authorization(self):
        pass

    def request_token_using_auth_code(self):
        pass

    def request_token_using_refresh_code(self):
        pass


def main():
    q = queue.Queue(1)

    # PKCE, Proof Key for Code Exchange
    pkce_len = 128
    pkce = ProofKeyForCodeExchange(pkce_len)
    print(f"code_challenge = {pkce.code_challenge}")

    state_len = 32
    state = create_random_str(state_len)
    print(f"state = {state}")

    my_http_server = MyHttpServer(q=q)

    # Start http server
    my_http_server.start_server()

    auth_req_params = AuthorizationRequestParameters(
        client_id=CLIENT_ID,
        code_challenge=pkce.code_challenge,
        scope=["sleep", "activity"],
        state=state,
        redirect_uri=my_http_server.address,
    )
    AUTH_URL = f"https://www.fitbit.com/oauth2/authorize?{auth_req_params}"
    print(f"Open {AUTH_URL}\n")

    for i in range(20):
        print(f"\rtime = {i+1}", end="")
        if not q.empty():  # Check queue
            auth_resp = q.get()  # {"code": code, "state": state}
            print()
            my_http_server.stop_server(sleep_time=1)
            break
        time.sleep(1)
    else:
        print()
        my_http_server.stop_server(sleep_time=1)
        return None

    if auth_req_params.state != auth_resp["state"]:
        print(f"state error: redirected_state = {auth_resp["state"]}")
        return None

    token_req_params = TokenRequestParameters(
        client_id=auth_req_params.client_id,
        code_verifier=pkce.code_verifier,
        redirect_uri=auth_req_params.redirect_uri,
        code=auth_resp["code"],
    )

    # record token request parameters
    config = configparser.ConfigParser()
    config["TOKEN_REQUEST_PARAMETERS"] = dataclasses.asdict(token_req_params)
    with AUTH_DATA_FILENAME.open("w", encoding="utf-8", newline="\n") as f:
        config.write(f)

    if input("Continue? [y](y/n):").lower() not in ["", "y"]:
        return None
    get_tokens()

    return True


def get_tokens():
    config = configparser.ConfigParser()
    config.read(AUTH_DATA_FILENAME)
    auth_data = dict(config["TOKEN_REQUEST_PARAMETERS"])

    client_id_and_secret = f"{auth_data["client_id"]}:{CLIENT_SECRET}"
    basic_token = base64.b64encode(client_id_and_secret.encode()).decode()
    print(basic_token)

    response = requests.post(
        "https://api.fitbit.com/oauth2/token",
        data=auth_data,
        headers={
            "Authorization": f"Basic {basic_token}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    print(response.status_code)
    print(response.text)  # str


def get_tokens_from_refresh_token():
    config = configparser.ConfigParser()
    config.read(AUTH_DATA_FILENAME)
    auth_data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": REFRESH_TOKEN,
    }

    client_id_and_secret = f"{auth_data["client_id"]}:{CLIENT_SECRET}"
    basic_token = base64.b64encode(client_id_and_secret.encode()).decode()
    print(basic_token)

    response = requests.post(
        "https://api.fitbit.com/oauth2/token",
        data=auth_data,
        headers={
            "Authorization": f"Basic {basic_token}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    print(response.status_code)
    print(response.text)  # str


def get_sleep_log_by_date_range():
    """
    curl -X GET "https://api.fitbit.com/1.2/user/-/sleep/date/2020-01-01/2020-01-05.json" \
        -H "accept: application/json" \
        -H "authorization: Bearer <access_token>"
    """

    start_date = datetime(2025, 1, 1)
    end_date = datetime(2025, 1, 5)
    response = requests.get(
        f"https://api.fitbit.com/1.2/user/-/sleep/date/{start_date:%Y-%m-%d}/{end_date:%Y-%m-%d}.json",
        headers={
            "Authorization": f"Bearer {ACCESS_TOKEN}",
            "Accept": "application/json",
        },
    )
    print(response.status_code)
    print(response.text)  # str
    return json.loads(response.text)


if __name__ == "__main__":
    # from pprint import pprint

    # get_tokens()
    main()
    # pprint(get_sleep_log_by_date_range())
