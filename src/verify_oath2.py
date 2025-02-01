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
from keys import CLIENT_ID, CLIENT_SECRET, REDIRECT_URL


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
class FitbitApplicationInformation:
    client_id: str
    client_secret: str
    redirect_url: str
    basic_token: str = dataclasses.field(init=False)

    def __post_init__(self):
        self.basic_token = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode(),
        ).decode()


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
    grant_type: str = dataclasses.field(init=False)


@dataclasses.dataclass
class TokenRequestFromCodeParameters(TokenRequestParameters):
    code_verifier: str  # PKCE code verifier
    redirect_uri: str
    code: str  # authorization code

    def __post_init__(self):
        self.grant_type = "authorization_code"


@dataclasses.dataclass
class TokenRequestFromRefreshTokenParameters(TokenRequestParameters):
    refresh_token: str

    def __post_init__(self):
        self.grant_type = "refresh_token"


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


class FitbitAuthorization:
    def __init__(self, is_debug: bool = False):
        self.app_info = FitbitApplicationInformation(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            redirect_url=REDIRECT_URL,
        )
        self.config = configparser.ConfigParser()
        self.config.read(AUTH_DATA_FILENAME)
        self.is_debug = is_debug

    def get_access_token(self) -> str | None:
        if "TOKEN_INFORMATION" in self.config:
            token_info = self.config["TOKEN_INFORMATION"]
            now = datetime.now().timestamp()
            if now > float(token_info["expiration_unixtime"]):
                # has invalid token
                pass
            elif token := self.config["TOKEN_RESPONSE_PARAMETERS"]["access_token"]:
                return token

        if "TOKEN_REQUEST_FROM_REFRESH_CODE_PARAMETERS" in self.config:
            # has refresh token
            req_params = self.create_token_req_from_refresh_token_params()
            token = self.request_token_common(req_params)
        else:
            # request token newly
            req_params = self.request_authorization()
            token = self.request_token_common(req_params)

        return token

    def request_authorization(self) -> TokenRequestFromCodeParameters | None:
        q = queue.Queue(1)

        # generate PKCE, Proof Key for Code Exchange
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
            client_id=self.app_info.client_id,
            code_challenge=pkce.code_challenge,
            scope=["sleep"],
            state=state,
            redirect_uri=self.app_info.redirect_url,
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

        token_req_params = TokenRequestFromCodeParameters(
            client_id=auth_req_params.client_id,
            code_verifier=pkce.code_verifier,
            redirect_uri=auth_req_params.redirect_uri,
            code=auth_resp["code"],
        )

        # record token request parameters
        self.config["TOKEN_REQUEST_FROM_CODE_PARAMETERS"] = dataclasses.asdict(
            token_req_params,
        )
        self.save_config_file()

        if self.is_debug:
            # For debug
            debug_message = "[DEBUG] request token? [y](y/n):"
            if input(debug_message).lower() in ["", "y"]:
                return None
            token = self.request_token_common(token_req_params)
            print(f"token = {token}")

        return token_req_params

    def create_token_req_from_code_params(
        self,
    ) -> TokenRequestFromCodeParameters:
        PARAM_NAME = "TOKEN_REQUEST_FROM_CODE_PARAMETERS"
        if PARAM_NAME not in self.config:
            print(f"No {PARAM_NAME} in {AUTH_DATA_FILENAME}")
            return False
        params = dict(self.config[PARAM_NAME])
        return TokenRequestFromCodeParameters(**params)

    def create_token_req_from_refresh_token_params(
        self,
    ) -> TokenRequestFromRefreshTokenParameters:
        if "TOKEN_RESPONSE_PARAMETERS" not in self.config:
            print(f"No TOKEN_RESPONSE_PARAMETERS in {AUTH_DATA_FILENAME}")
            return False
        existing_token_resp = dict(self.config["TOKEN_RESPONSE_PARAMETERS"])

        token_request_params = TokenRequestFromRefreshTokenParameters(
            client_id=self.app_info.client_id,
            refresh_token=existing_token_resp["refresh_token"],
        )
        PARAM_NAME = "TOKEN_REQUEST_FROM_REFRESH_CODE_PARAMETERS"
        self.config[PARAM_NAME] = dataclasses.asdict(token_request_params)
        self.save_config_file()

        return token_request_params

    def request_token_common(
        self,
        token_request_params: TokenRequestParameters,
    ) -> str:
        # get current datetime
        requested_datetime = datetime.now()
        # send post to Fitbit web api
        response = requests.post(
            "https://api.fitbit.com/oauth2/token",
            data=dataclasses.asdict(token_request_params),
            headers={
                "Authorization": f"Basic {self.app_info.basic_token}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

        if response.status_code != 200:
            # error
            return ""

        if self.is_debug:
            print(response.status_code)
            print(response.text)  # str

        token_resp = json.loads(response.text)
        self.save_token_response(token_resp, requested_datetime)

        return token_resp["access_token"]

    def save_token_response(
        self,
        token_resp: dict[str, str],
        requested_datetime: datetime,
    ) -> None:

        self.config["TOKEN_RESPONSE_PARAMETERS"] = token_resp

        requested_unixtime = requested_datetime.timestamp()
        expiration_unixtime = requested_unixtime + token_resp["expires_in"]
        expiration_datetime = datetime.fromtimestamp(expiration_unixtime)
        token_info = {
            "requested_unixtime": requested_unixtime,
            "expiration_unixtime": expiration_unixtime,
            "expiration_local_datetime": expiration_datetime,
        }
        self.config["TOKEN_INFORMATION"] = token_info
        self.save_config_file()

    def save_config_file(self) -> None:
        with AUTH_DATA_FILENAME.open("w", encoding="utf-8", newline="\n") as f:
            self.config.write(f)


def get_sleep_log_by_date_range(access_token):
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
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        },
    )
    print(response.status_code)
    print(response.text)  # str
    return json.loads(response.text)


if __name__ == "__main__":
    fitbit_auth = FitbitAuthorization(is_debug=True)
    # fitbit_auth.request_authorization()
    access_token = fitbit_auth.get_access_token()
    print(access_token)
    # get_sleep_log_by_date_range(access_token)
