# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Invenio-OAuthClient provides OAuth web authorization support."""

from __future__ import absolute_import, print_function

from flask_login import user_logged_out, current_user
from flask_oauthlib.client import OAuth as FlaskOAuth
from flask_oauthlib.client import OAuthRemoteApp

from authlib.flask.client import OAuth as Auth
import os
from . import config
from .handlers import authorized_default_handler, disconnect_handler, \
    make_handler, make_token_getter, oauth_logout_handler, response_token_setter
from .utils import load_or_import_from_config, obj_or_import_string
from .models import RemoteToken

from invenio_db import db

class _OAuthClientState(object):
    """OAuth client state storing registered actions."""

    def __init__(self, app):
        """Initialize state."""
        self.app = app
        self.handlers = {}
        self.disconnect_handlers = {}
        self.signup_handlers = {}

        # Connect signal to remove access tokens on logout
        user_logged_out.connect(oauth_logout_handler)

        self.oauth = Auth()
        # self.oauth = app.extensions.get('oauthlib.client') or Auth()

        # Add remote applications
        self.oauth.init_app(app)

        remote_app_class = load_or_import_from_config(
            'OAUTHCLIENT_REMOTE_APP', app, default=OAuthRemoteApp
        )

        for remote_app, conf in app.config[
                'OAUTHCLIENT_REMOTE_APPS'].items():
            # Prevent double creation problems
            # if not self.oauth[remote_app]:
                # use this app's specific remote app class if there is one.
            current_remote_app_class = obj_or_import_string(
                conf.get('remote_app'), default=remote_app_class
            )
            # Register the remote app. We are doing this because the
            # current version of OAuth.remote_app does not allow to specify
            # the remote app class. Use it once it is fixed.
            # self.oauth.remote_apps[remote_app] = current_remote_app_class(

            def update_token(token):
                # import ipdb;ipdb.set_trace()

                class CC(object):
                    name = 'cern'
                    client_id = 'cap_service_react_3'
                
                c = CC()
                
                _token = response_token_setter(c, token)


                # import ipdb;ipdb.set_trace()
                db.session.commit()
                return _token

                # user = current_user
                # if not user.is_anonymous:
                #     uid = user.id
                #     cid = os.environ.get('INVENIO_CERN_APP_CREDENTIALS_KEY')

                #     # Check for already existing token
                #     t = RemoteToken.get(uid, cid, token_type=token['token_type'])


                #     if t:
                #         t.update_token(token)
                #     else:
                #         t = RemoteToken.create(
                #             uid, cid, token, '',
                #             token_type=token['token_type'], extra_data=extra_data
                #         )

                #     return t

            def fetch_token(remote='cern', token=''):
                """Retrieve OAuth access token.

                Used by flask-oauthlib to get the access token when making requests.

                :param remote: The remote application.
                :param token: Type of token to get. Data passed from ``oauth.request()`` to
                    identify which token to retrieve. (Default: ``''``)
                :returns: The token.
                """

                # session_key = token_session_key(remote)

                # if session_key not in session and current_user.is_authenticated:
                    # Fetch key from token store if user is authenticated, and the key
                    # isn't already cached in the session.
                remote_token = RemoteToken.get(
                    current_user.get_id(),
                    'cap_service_react_3',
                    token_type='bearer',
                )

                    # if remote_token is None:
                    #     return None

                    # # Store token and secret in session
                t = remote_token.token()
                    # t = (t.access_token, t.secret)
                    # session[session_key] = t

                return t



            self.oauth.register(
                # self.oauth,
                remote_app,
                client_id=os.environ.get('INVENIO_CERN_APP_CREDENTIALS_KEY'),
                client_secret=os.environ.get('INVENIO_CERN_APP_CREDENTIALS_SECRET'),
                request_token_url=None,
                request_token_params=None,
                access_token_url='https://oauth.web.cern.ch/OAuth/Token',
                access_token_params=None,
                access_token_method='POST',
                refresh_token_url='https://oauth.web.cern.ch/OAuth/Token',
                # refresh_token_params=None,
                authorize_url='https://oauth.web.cern.ch/OAuth/Authorize',
                api_base_url='https://oauth.web.cern.ch/',
                client_kwargs={
                    'scope': 'Name Email Bio Groups',
                    'show_login': 'true',
                    'access_type': 'offline'
                },
                # fetch_token=token_getter
                fetch_token=fetch_token,
                update_token=update_token
            )

            remote = self.oauth._clients[remote_app]

            # # Register authorized handler
            self.handlers[remote_app] = conf.get('authorized_handler', authorized_default_handler)

            # # Register disconnect handler
            # self.disconnect_handlers[remote_app] = make_handler(
            #     conf.get('disconnect_handler', disconnect_handler),
            #     remote,
            #     with_response=False,
            # )

            # Register sign-up handlers
            def dummy_handler(remote, *args, **kargs):
                pass

            signup_handler = conf.get('signup_handler', dict())
            account_info_handler = make_handler(
                signup_handler.get('info', dummy_handler),
                remote,
                with_response=False
            )
            account_setup_handler = make_handler(
                signup_handler.get('setup', dummy_handler),
                remote,
                with_response=False
            )
            account_view_handler = make_handler(
                signup_handler.get('view', dummy_handler),
                remote,
                with_response=False
            )

            self.signup_handlers[remote_app] = dict(
                info=account_info_handler,
                setup=account_setup_handler,
                view=account_view_handler,
            )


class InvenioOAuthClient(object):
    """Invenio Oauthclient extension."""

    def __init__(self, app=None):
        """Extension initialization."""
        if app:
            self._state = self.init_app(app)

    def init_app(self, app):
        """Flask application initialization."""
        self.init_config(app)
        state = _OAuthClientState(app)
        app.extensions['invenio-oauthclient'] = state
        return state

    def init_config(self, app):
        """Initialize configuration."""
        for k in dir(config):
            if k.startswith('OAUTHCLIENT_'):
                app.config.setdefault(k, getattr(config, k))

        @app.before_first_request
        def override_template_configuration():
            """Override template configuration."""
            template_key = app.config.get(
                'OAUTHCLIENT_TEMPLATE_KEY',
                'SECURITY_LOGIN_USER_TEMPLATE'  # default template key
            )
            if template_key is not None:
                template = app.config[template_key]  # keep the old value
                app.config['OAUTHCLIENT_LOGIN_USER_TEMPLATE_PARENT'] = template
                app.config[template_key] = app.config.get(
                    'OAUTHCLIENT_LOGIN_USER_TEMPLATE',
                    'invenio_oauthclient/login_user.html'
                )
