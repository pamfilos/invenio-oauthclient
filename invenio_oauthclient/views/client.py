# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2018 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Client blueprint used to handle OAuth callbacks."""

from __future__ import absolute_import

from flask import Blueprint, abort, current_app, flash, redirect, request, \
    url_for, jsonify, session
from flask_login import current_user
from flask_oauthlib.client import OAuthException
from invenio_db import db
from itsdangerous import BadData, TimedJSONWebSignatureSerializer
from werkzeug.local import LocalProxy

from .._compat import _create_identifier
from ..handlers import set_session_next_url, token_getter, response_token_setter, get_session_next_url
from ..proxies import current_oauthclient
from ..utils import get_safe_redirect_target, oauth_get_user, oauth_authenticate, oauth_register,fill_form, create_csrf_disabled_registrationform
from ..models import RemoteToken
from ..signals import account_info_received, account_setup_committed, \
    account_setup_received
blueprint = Blueprint(
    'invenio_oauthclient',
    __name__,
    url_prefix='/oauth',
    static_folder='../static',
    template_folder='../templates',
)


serializer = LocalProxy(
    lambda: TimedJSONWebSignatureSerializer(
        current_app.config['SECRET_KEY'],
        expires_in=current_app.config['OAUTHCLIENT_STATE_EXPIRES'],
    )
)


@blueprint.record_once
def post_ext_init(state):
    """Setup blueprint."""
    app = state.app

    app.config.setdefault(
        'OAUTHCLIENT_SITENAME',
        app.config.get('THEME_SITENAME', 'Invenio'))
    app.config.setdefault(
        'OAUTHCLIENT_BASE_TEMPLATE',
        app.config.get('BASE_TEMPLATE',
                       'invenio_oauthclient/base.html'))
    app.config.setdefault(
        'OAUTHCLIENT_COVER_TEMPLATE',
        app.config.get('COVER_TEMPLATE',
                       'invenio_oauthclient/base_cover.html'))
    app.config.setdefault(
        'OAUTHCLIENT_SETTINGS_TEMPLATE',
        app.config.get('SETTINGS_TEMPLATE',
                       'invenio_oauthclient/settings/base.html'))


@blueprint.route('/login/<remote_app>/')
def login(remote_app):
    """Send user to remote application for authentication."""

    # oauth = current_app.extensions['oauthlib.client']
    oauth = current_oauthclient.oauth

    # if remote_app not in oauth.remote_apps:
    #     return abort(404)
    if remote_app not in oauth._clients:
        return abort(404)

    # Get redirect target in safe manner.
    next_param = get_safe_redirect_target(arg='next')

    # Redirect URI - must be registered in the remote service.
    callback_url = url_for(
        '.authorized',
        remote_app=remote_app,
        _external=True,
    )

    # Create a JSON Web Token that expires after OAUTHCLIENT_STATE_EXPIRES
    # seconds.
    state_token = serializer.dumps({
        'app': remote_app,
        'next': next_param,
        'sid': _create_identifier(),
    })

    client = oauth.create_client(remote_app)

    return client.authorize_redirect(callback_url)
    # oauth[remote_app].authorize(
    #     callback=callback_url,
    #     state=state_token,
    # )


@blueprint.route('/authorized/<remote_app>/')
def authorized(remote_app=None):
    """Authorized handler callback."""
    if remote_app not in current_oauthclient.oauth._clients:
        return abort(404)

    state_token = request.args.get('state')
    # import ipdb; ipdb.set_trace()

    # Verify state parameter
    # try:
    #     assert state_token
    #     # Checks authenticity and integrity of state and decodes the value.
    #     state = serializer.loads(state_token)
    #     # Verify that state is for this session, app and that next parameter
    #     # have not been modified.
    #     assert state['sid'] == _create_identifier()
    #     assert state['app'] == remote_app
    #     # Store next URL
    #     set_session_next_url(remote_app, state['next'])
    # except (AssertionError, BadData):
    #     if current_app.config.get('OAUTHCLIENT_STATE_ENABLED', True) or (
    #        not(current_app.debug or current_app.testing)):
    #         abort(403)

    # try:
    #     # client = current_oauthclient.oauth.create_client(remote_app)
    #     # token = client.authorize_access_token()
    #     # handler = current_oauthclient.handlers[remote_app](
    #     #         request,
    #     #         remote_app
    #     #     )
    #     # handler()
    # except OAuthException as e:
    #     if e.type == 'invalid_response':
    #         abort(500)
    #     else:
    #         raise

    return save_token('cern')


    # return handler
    # return redirect('/me')


def save_token(remote, *args, **kwargs):
    """Handle sign-in/up functionality.

    :param remote: The remote application.
    :param resp: The response.
    :returns: Redirect response.
    """
    # Remove any previously stored auto register session key
    # session.pop(token_session_key(remote.name) + '_autoregister', None)

    # Store token in session
    # ----------------------
    # Set token in session - token object only returned if
    # current_user.is_autenticated().


    client = current_oauthclient.oauth._clients[remote]
    # token = response_token_setter(client, resp)
    handlers = current_oauthclient.signup_handlers[remote]
    token = client.authorize_access_token()

    # Sign-in/up user
    # ---------------
    if not current_user.is_authenticated:
        print(token)
        res = client.get('https://oauthresource.web.cern.ch/api/Me')
        print(res.json())
        # import ipdb;ipdb.set_trace()

        account_info = handlers['info'](client)
        # account_info_received.send(
        #     client, token=token, response=resp, account_info=account_info
        # )

        user = oauth_get_user(
            client.client_id,
            account_info=account_info,
            access_token=token_getter(client),
        )

        if user is None:
            # Auto sign-up if user not found
            form = create_csrf_disabled_registrationform()
            form = fill_form(
                form,
                account_info['user']
            )
            user = oauth_register(form)

            # if registration fails ...
            if user is None:
                # requires extra information
                session[
                    token_session_key(client.name) + '_autoregister'] = True
                session[token_session_key(client.name) +
                        '_account_info'] = account_info
                session[token_session_key(client.name) +
                        '_response'] = resp
                db.session.commit()
                return redirect('/')

        # Authenticate user
        if not oauth_authenticate(client.client_id, user,
                                  require_existing_link=False):
            return current_app.login_manager.unauthorized()


        # RemoteToken.create(
        #     current_user.id, client.client_id, token, 'secret'
        # )
        # Link account
        # ------------
        # Need to store token in database instead of only the session when
        # called first time.
    _token = response_token_setter(client, token)

    # Setup account
    # -------------
    if not _token.remote_account.extra_data:
        account_setup = handlers['setup'](client, _token)
        account_setup_received.send(
            remote, token=_token, response={}, account_setup=account_setup
        )
        db.session.commit()
        account_setup_committed.send(remote, token=token)
    else:
        db.session.commit()

    # Redirect to next
    next_url = get_session_next_url(remote)
    if next_url:
        return redirect(next_url)
    return redirect('/me')


@blueprint.route('/signup/<remote_app>/', methods=['GET', 'POST'])
def signup(remote_app):
    """Extra signup step."""
    if remote_app not in current_oauthclient.signup_handlers:
        return abort(404)
    res = current_oauthclient.signup_handlers[remote_app]['view']()
    return abort(404) if res is None else res


@blueprint.route('/disconnect/<remote_app>/')
def disconnect(remote_app):
    """Disconnect user from remote application.

    Removes application as well as associated information.
    """
    if remote_app not in current_oauthclient.disconnect_handlers:
        return abort(404)

    ret = current_oauthclient.disconnect_handlers[remote_app]()
    db.session.commit()
    return ret
