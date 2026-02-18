import base64
import json
import logging
import os
import random
import string
from urllib.parse import urlencode

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from auth.auth_server.controllers.base import BaseController
from auth.auth_server.controllers.base_async import BaseAsyncControllerWrapper
from auth.auth_server.controllers.token import TokenController
from auth.auth_server.controllers.user import UserController
from auth.auth_server.exceptions import Err
from auth.auth_server.utils import (
    check_kwargs_is_empty, pop_or_raise, check_string_attribute)
from tools.optscale_exceptions.common_exc import (
    WrongArgumentsException, ForbiddenException)

LOG = logging.getLogger(__name__)


class AzureVerifyTokenError(Exception):
    pass


class InvalidAuthorizationToken(Exception):
    def __init__(self, details):
        super().__init__('Invalid authorization token: ' + details)


class GoogleOauth2Provider:
    DEFAULT_TOKEN_URI = 'https://oauth2.googleapis.com/token'

    def __init__(self):
        self._client_id = os.environ.get('GOOGLE_OAUTH_CLIENT_ID')
        self._client_secret = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET')

    def client_id(self):
        if not self._client_id:
            raise ForbiddenException(Err.OA0012, [])
        return self._client_id

    def client_secret(self):
        if not self._client_secret:
            raise ForbiddenException(Err.OA0012, [])
        return self._client_secret

    def exchange_token(self, code, redirect_uri):
        request_body = {
            "grant_type": 'authorization_code',
            "client_secret": self.client_secret(),
            "client_id": self.client_id(),
            "code": code,
            'redirect_uri': redirect_uri,
        }
        request = google_requests.Request()
        response = request(
            url=self.DEFAULT_TOKEN_URI,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=urlencode(request_body).encode("utf-8"),
        )
        response_body = (
            response.data.decode("utf-8")
            if hasattr(response.data, "decode")
            else response.data
        )
        if response.status != 200:
            raise ValueError(response_body)
        response_data = json.loads(response_body)
        return response_data['id_token']

    def verify(self, code, **kwargs):
        try:
            redirect_uri = kwargs.pop('redirect_uri', None)
            token = self.exchange_token(code, redirect_uri)
            token_info = id_token.verify_oauth2_token(
                token, google_requests.Request(), self.client_id())
            if not token_info.get('email_verified', False):
                raise ForbiddenException(Err.OA0012, [])
            email = token_info['email']
            name = token_info.get('name', email)
            return email, name
        except (ValueError, KeyError) as ex:
            LOG.error(str(ex))
            raise ForbiddenException(Err.OA0012, [])


class MicrosoftOauth2Provider:
    def __init__(self):
        self._client_id = os.environ.get('MICROSOFT_OAUTH_CLIENT_ID')
        self._tenant_id = os.environ.get('MICROSOFT_OAUTH_TENANT_ID')
        if not self._tenant_id:
            raise ForbiddenException(Err.OA0012, [])
        self.config_url = (f"https://login.microsoftonline.com/{self._tenant_id}/v2.0/"
                           "well-known/openid-configuration")

    def client_id(self):
        if not self._client_id:
            raise ForbiddenException(Err.OA0012, [])
        return self._client_id

    def ensure_bytes(self, key):
        if isinstance(key, str):
            key = key.encode('utf-8')
        return key

    def decode_value(self, val):
        val_bytes = self.ensure_bytes(val)
        # Correct base64url padding: need (4 - len % 4) % 4 '=' chars
        padding = (4 - len(val_bytes) % 4) % 4
        decoded = base64.urlsafe_b64decode(val_bytes + b'=' * padding)
        return int.from_bytes(decoded, 'big')

    def rsa_pem_from_jwk(self, jwk):
        return RSAPublicNumbers(
            n=self.decode_value(jwk['n']),
            e=self.decode_value(jwk['e'])
        ).public_key(default_backend()).public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_token_info(self, token):
        headers = jwt.get_unverified_header(token)
        if not headers:
            raise InvalidAuthorizationToken('missing headers')
        try:
            return headers['kid'], headers['alg']
        except KeyError:
            raise InvalidAuthorizationToken(f'invalid headers: {headers}')

    def get_azure_data(self):
        try:
            resp = requests.get(self.config_url, timeout=30)
        except requests.exceptions.RequestException as ex:
            raise AzureVerifyTokenError(
                f'Network error fetching {self.config_url}: {ex}') from ex
        if not resp.ok:
            raise AzureVerifyTokenError(
                f'Received {resp.status_code} response '
                f'code from {self.config_url}')
        try:
            config_map = resp.json()
        except (ValueError, TypeError, KeyError):
            raise AzureVerifyTokenError(
                f'Received malformed response from {self.config_url}')
        try:
            issuer = config_map['issuer'].format(
                tenantid=self._tenant_id)
            jwks_uri = config_map['jwks_uri']
        except KeyError:
            raise AzureVerifyTokenError(f'Invalid config map: {config_map}')

        try:
            resp = requests.get(jwks_uri, timeout=30)
        except requests.exceptions.RequestException as ex:
            raise AzureVerifyTokenError(
                f'Network error fetching {jwks_uri}: {ex}') from ex
        if not resp.ok:
            raise AzureVerifyTokenError(
                f'Received {resp.status_code} response code from {jwks_uri}')
        try:
            jwks = resp.json()
        except (ValueError, TypeError, KeyError):
            raise AzureVerifyTokenError(
                f'Received malformed response from {jwks_uri}')
        return {
            'issuer': issuer,
            'issuers': [
                issuer,
                f'https://sts.windows.net/{self._tenant_id}/'
            ],
            'jwks': jwks,
            'aud': [self.client_id()]
        }

    def get_jwk(self, kid, jwks):
        keys = jwks.get('keys')
        if not isinstance(keys, list):
            raise AzureVerifyTokenError(f'Invalid jwks: {jwks}')
        for jwk in keys:
            if jwk.get('kid') == kid:
                return jwk
        raise InvalidAuthorizationToken('kid not recognized')

    def get_public_key(self, kid, jwks):
        jwk = self.get_jwk(kid, jwks)
        return self.rsa_pem_from_jwk(jwk)

    def verify(self, token, **kwargs):
        try:
            # redirect_uri is Google-specific, not used by Microsoft
            kwargs.pop('redirect_uri', None)
            check_kwargs_is_empty(**kwargs)
            kid, alg = self.get_token_info(token)
            azure_data = self.get_azure_data()
            public_key = self.get_public_key(kid, azure_data['jwks'])
            LOG.debug('Decoding Microsoft token with issuer: %s, aud: %s, alg: %s',
                      azure_data['issuer'], azure_data['aud'], alg)
            # Try each valid issuer (v2.0 and legacy v1.0 sts.windows.net)
            last_exc = None
            result = None
            for issuer in azure_data['issuers']:
                try:
                    result = jwt.decode(token, public_key,
                                        audience=azure_data['aud'],
                                        issuer=issuer,
                                        algorithms=[alg])
                    break
                except jwt.InvalidIssuerError as ex:
                    last_exc = ex
                    continue
            if result is None:
                raise jwt.InvalidIssuerError(
                    f'No matching issuer. Tried: {azure_data["issuers"]}') from last_exc
            # preferred_username may be absent for guest/B2B accounts
            email = (result.get('preferred_username') or
                     result.get('email') or
                     result.get('upn'))
            if not email:
                raise InvalidAuthorizationToken(
                    'no email claim (preferred_username/email/upn) in token')
            name = result.get('name', email)
            return email, name
        except (InvalidAuthorizationToken, AzureVerifyTokenError) as ex:
            LOG.error('Microsoft token verification error: %s', str(ex))
            raise ForbiddenException(Err.OA0012, [])
        except jwt.ExpiredSignatureError as ex:
            LOG.error('Microsoft JWT token expired: %s', str(ex))
            raise ForbiddenException(Err.OA0012, [])
        except jwt.InvalidIssuerError as ex:
            LOG.error('Microsoft JWT issuer mismatch: %s', str(ex))
            raise ForbiddenException(Err.OA0012, [])
        except jwt.InvalidAudienceError as ex:
            LOG.error('Microsoft JWT audience mismatch: %s', str(ex))
            raise ForbiddenException(Err.OA0012, [])
        except jwt.PyJWTError as ex:
            LOG.error('Microsoft JWT error (%s): %s', type(ex).__name__, str(ex))
            raise ForbiddenException(Err.OA0012, [])


class SignInController(BaseController):
    def __init__(self, db_session, config=None):
        self._user_ctl = None
        self._token_ctl = None
        super().__init__(db_session, config)

    @property
    def user_ctl(self):
        if not self._user_ctl:
            self._user_ctl = UserController(self._session, self._config)
        return self._user_ctl

    @property
    def token_ctl(self):
        if not self._token_ctl:
            self._token_ctl = TokenController(self._session, self._config)
        return self._token_ctl

    @staticmethod
    def _get_input(**input_):
        provider = pop_or_raise(input_, 'provider')
        check_string_attribute('provider', provider)
        token = pop_or_raise(input_, 'token')
        check_string_attribute('token', token, max_length=65536)
        ip = input_.pop('ip', None)
        redirect_uri = input_.pop('redirect_uri', None)
        check_kwargs_is_empty(**input_)
        return provider, token, ip, redirect_uri

    @staticmethod
    def _get_verifier_class(provider):
        return {
            'google': GoogleOauth2Provider,
            'microsoft': MicrosoftOauth2Provider
        }.get(provider)

    @staticmethod
    def _gen_password():
        return ''.join(random.choice(
            string.digits + string.ascii_letters + string.punctuation
        ) for _ in range(33))

    def signin(self, **kwargs):
        provider, token, ip, redirect_uri = self._get_input(**kwargs)
        verifier_class = self._get_verifier_class(provider)
        if not verifier_class:
            raise WrongArgumentsException(Err.OA0067, [provider])
        email, display_name = verifier_class().verify(
            token, redirect_uri=redirect_uri)
        user = self.user_ctl.get_user_by_email(email)
        register = user is None
        if not user:
            user = self.user_ctl.create(
                email=email, display_name=display_name,
                password=self._gen_password(),
                self_registration=True, token='',
                is_password_autogenerated=True)
        user.verified = True
        token_dict = self.token_ctl.create_token_by_user_id(
            user_id=user.id, ip=ip, provider=provider,
            register=register)
        token_dict['user_email'] = user.email
        return token_dict


class SignInAsyncController(BaseAsyncControllerWrapper):
    def _get_controller_class(self):
        return SignInController
