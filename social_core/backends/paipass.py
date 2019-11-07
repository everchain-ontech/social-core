"""
    PAIPASS Oauth2 backend
"""
from .oauth import BaseOAuth2
from ..exceptions import AuthCanceled, AuthUnknownError


class PaipassOAuth2(BaseOAuth2):
    """Facebook OAuth2 authentication backend"""
    name = "paipass"
    ID_KEY = "email"
    REDIRECT_STATE = False
    RESPONSE_TYPE = None
    ACCESS_TOKEN_METHOD = "POST"
    SCOPE_SEPARATOR = r" "
    AUTHORIZATION_URL = "https://api.demo.p19dev.com/oauth/authorize"
    ACCESS_TOKEN_URL = "https://api.demo.p19dev.com/oauth/token"
    USER_DATA_URL = "https://api.demo.p19dev.com/attributes/paipass/user.data/0"
    EXTRA_DATA = [("expires", "expires"), ]

    def auth_complete_credentials(self):
        return self.get_key_and_secret()

    def get_user_details(self, response):
        """Return user details from Facebook account"""
        email = response.get("email")
        return {"email": email, "username": email.split("@")[0]}

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        params = self.setting("PROFILE_EXTRA_PARAMS", {})
        params["access_token"] = access_token
        return self.get_json(self.USER_DATA_URL, params=params)

    def process_error(self, data):
        super(PaipassOAuth2, self).process_error(data)
        if data.get("error_code"):
            raise AuthCanceled(self, data.get("error_message") or
                               data.get("error_code"))

    def do_auth(self, access_token, response=None, *args, **kwargs):
        response = response or {}

        data = self.user_data(access_token)

        if not isinstance(data, dict):
            raise AuthUnknownError(self, "An error ocurred while retrieving "
                                         "users Facebook data")

        data["access_token"] = access_token
        if "expires_in" in response:
            data["expires"] = response["expires_in"]

        if self.data.get("granted_scopes"):
            data["granted_scopes"] = self.data["granted_scopes"].split(",")

        if self.data.get("denied_scopes"):
            data["denied_scopes"] = self.data["denied_scopes"].split(",")

        kwargs.update({"backend": self, "response": data})
        return self.strategy.authenticate(*args, **kwargs)

