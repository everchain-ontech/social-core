from six.moves.urllib_parse import urlencode

from .oauth import OAuth1Test


class PaipassOAuth2Test(OAuth1Test):
    backend_path = 'social_core.backends.paipass.PaipassOAuth2'
    user_data_url = 'https://api.demo.p19dev.com/attributes/paipass/user.data/0'
    expected_username = 'foobar'
    access_token_body = urlencode({
        'access_token': 'c52ce891-e0a3-4eec-9203-7bfd1a7e10b8',
        'token_type': 'bearer',
        'expires_in': 17396,
        'scope': 'READ_ALL.PAIPASS.EMAIL'})
    request_token_body = urlencode({
        'name': None,
        'nameVerified': False,
        'email': 'foobar@everchain.info',
        'emailVerified': False,
        'phone': None,
        'phoneVerified': True,
        'ongoingEmailVerification': None,
        'ongoingNameVerification': None,
        'ongoingPhoneVerification': None,
        'newEmail': None,
        'newPhone': None,
        'newName': None,
        'accountVerified': None,
        'identityVerificationStatus': None,
        'premiumLevel': None,
        'rejectionReason': None
    })

    def test_login(self):
        self.do_login()

    def test_partial_pipeline(self):
        self.do_partial_pipeline()
