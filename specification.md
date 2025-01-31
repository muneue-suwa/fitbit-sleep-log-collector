# Specification

## Authorization data

Save required and retrieved data to ini file.

`.fitbit_auth.ini`

```ini
[AUTHORIZATION_REQUEST_PARAMETERS]
client_id =
scope =
code_challenge =
code_challenge_method = S256
response_type = code

[AUTHORIZATION_RESPONSE_PARAMETERS]
code =
toekn =

[TOKEN_REQUEST_PARAMETERS]
client_id =
code =
code_verifier =
redirect_uri =
grant_type = authorization_code

[TOKEN_RESPONSE_PARAMETERS]
access_token =
expires_in =
refresh_token =
scope =
token_type =
user_id =

[TOKEN_INFORMATION]
requested_unixtime =
expiration_unixtime =
expiration_local_datetime =
```
