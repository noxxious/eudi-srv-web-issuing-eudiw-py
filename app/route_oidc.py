# coding: utf-8
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""
The PID Issuer Web service is a component of the PID Provider backend. 
Its main goal is to issue the PID and MDL in cbor/mdoc (ISO 18013-5 mdoc) and SD-JWT format.


This route_oidc.py file is the blueprint for the route /oidc of the PID Issuer Web service.
"""
import base64
import hashlib
import io
import re
import sys
import uuid
import urllib.parse
import segno
import traceback

from flask import (
    Blueprint,
    jsonify,
    Response,
    request,
    session,
    current_app,
    redirect,
    render_template,
    url_for,
)
from flask.helpers import make_response
import os
import werkzeug

from flask_cors import CORS
from idpyoidc.message.oidc import AuthorizationRequest
from idpyoidc.message.oauth2 import ResponseMessage
import json
import sys
from typing import Union
from urllib.parse import urlparse

from idpyoidc.message.oidc import AccessTokenRequest
from idpyoidc.server.exception import FailedAuthentication, ClientAuthenticationError
from idpyoidc.server.oidc.token import Token

from app.misc import auth_error_redirect, authentication_error_redirect, scope2details

from datetime import datetime, timedelta

import requests

from .app_config.config_service import ConfService as cfgservice
from .app_config.config_oidc_endpoints import ConfService as cfgoidc

from . import oidc_metadata, openid_metadata, oauth_metadata

oidc = Blueprint("oidc", __name__, url_prefix="/")
CORS(oidc)  # enable CORS on the blue print

# variable for PAR requests
from app.data_management import (
    getSessionId_accessToken,
    parRequests,
    transaction_codes,
    deferredRequests,
    session_ids,
    getSessionId_requestUri,
    getSessionId_authCode,
)


def _add_cookie(resp: Response, cookie_spec: Union[dict, list]):
    kwargs = {k: v for k, v in cookie_spec.items() if k not in ("name",)}
    kwargs["path"] = "/"
    kwargs["samesite"] = "Lax"
    resp.set_cookie(cookie_spec["name"], **kwargs)


def add_cookie(resp: Response, cookie_spec: Union[dict, list]) -> None:
    if isinstance(cookie_spec, list):
        for _spec in cookie_spec:
            _add_cookie(resp, _spec)
    elif isinstance(cookie_spec, dict):
        _add_cookie(resp, cookie_spec)


""" @oidc.route("/static/<path:path>")
def send_js(path):
    return send_from_directory("static", path) """


""" @oidc.route("/static/jwks.json")
def keys():
    fname = os.path.join("static", jwks)
    return open(fname).read()
    return send_from_directory('static', 'jwks.json') """


def do_response(endpoint, req_args, error="", **args) -> Response:
    info = endpoint.do_response(request=req_args, error=error, **args)
    # _log = current_app.logger
    logger = cfgservice.app_logger.getChild("do_response")

    try:
        _response_placement = info["response_placement"]
    except KeyError:
        _response_placement = endpoint.response_placement

    if _response_placement == "body":
        log_msg = {"message": "error response" if error else "response", "error": error, "info": info["response"], "placement": _response_placement}
        logger.error(log_msg) if error else logger.info(log_msg)
        resp = make_response(info["response"], info.get("response_code", 400 if error else 200))
    else:  # _response_placement == 'url':
        logger.info({"message": "redirect to: {}".format(info["response"])})
        resp = redirect(info["response"])

    for key, value in info["http_headers"]:
        resp.headers[key] = value

    if "cookie" in info:
        add_cookie(resp, info["cookie"])

    return resp

def verify(authn_method):
    """
    Authentication verification

    :param url_endpoint: Which endpoint to use
    :param kwargs: response arguments
    :return: HTTP redirect
    """
    # kwargs = dict([(k, v) for k, v in request.form.items()])

    logger = cfgservice.app_logger.getChild("verify")

    try:
        username = authn_method.verify(username=request.args.get("username"))

        auth_args = authn_method.unpack_token(request.args.get("jws_token"))
    except:
        logger.error(
            "Authorization verification: username or jws_token not found"
        )
        if "jws_token" in request.args:
            return authentication_error_redirect(
                jws_token=request.args.get("jws_token"),
                error="invalid_request",
                error_description="Authentication verification Error",
            )
        else:
            return render_template(
                "misc/500.html", error="Authentication verification Error"
            )

    authz_request = AuthorizationRequest().from_urlencoded(auth_args["query"])

    endpoint = current_app.server.get_endpoint("authorization")

    _session_id = endpoint.create_session(
        authz_request,
        username,
        auth_args["authn_class_ref"],
        auth_args["iat"],
        authn_method,
    )

    args = endpoint.authz_part2(request=authz_request, session_id=_session_id)

    if isinstance(args, ResponseMessage) and "error" in args:
        logger.error({"message": f"Authorization error: {args["error"]}", "args": args.to_json()}) 
        return make_response(args.to_json(), 400)

    if "session_id" not in session:
        logger.error({"message": f"session is not available", "args": args.to_json()}) 
        return make_response(args.to_json(), 400)
        
    session_ids[session["session_id"]]["auth_code"] = args["response_args"]["code"]

    logText = (
        ", Session ID: "
        + session["session_id"]
        + ", "
        + "Authorization Response, Code: "
        + args["response_args"]["code"]
    )

    if "state" in args["response_args"]:

        logText = logText + ", State: " + args["response_args"]["state"]

    logger.info(logText)

    return do_response(endpoint, request, **args)


@oidc.route("/verify/user", methods=["GET"])
def verify_user():
    authn_method = current_app.server.get_context().authn_broker.get_method_by_id(
        "user"
    )
    try:
        return verify(authn_method)
    except FailedAuthentication as exc:
        cfgservice.app_logger.error("Authorization verification failed")
        return render_template("misc/500.html", error=str(exc))


@oidc.route("/.well-known/<service>")
def well_known(service):
    if service == "openid-credential-issuer":
        info = {
            "response": oidc_metadata,
            "http_headers": [
                ("Content-type", "application/json; charset=utf-8"),
                ("Pragma", "no-cache"),
                ("Cache-Control", "no-store"),
            ],
        }

        _http_response_code = info.get("response_code", 200)
        resp = make_response(info["response"], _http_response_code)

        for key, value in info["http_headers"]:
            resp.headers[key] = value

        return resp
    elif service == "oauth-authorization-server":
        info = {
            "response": oauth_metadata,
            "http_headers": [
                ("Content-type", "application/json; charset=utf-8"),
                ("Pragma", "no-cache"),
                ("Cache-Control", "no-store"),
            ],
        }

        _http_response_code = info.get("response_code", 200)
        resp = make_response(info["response"], _http_response_code)

        for key, value in info["http_headers"]:
            resp.headers[key] = value

        return resp

    elif service == "openid-configuration":
        # _endpoint = current_app.server.get_endpoint("provider_config")
        info = {
            "response": openid_metadata,
            "http_headers": [
                ("Content-type", "application/json; charset=utf-8"),
                ("Pragma", "no-cache"),
                ("Cache-Control", "no-store"),
            ],
        }

        _http_response_code = info.get("response_code", 200)
        resp = make_response(info["response"], _http_response_code)

        for key, value in info["http_headers"]:
            resp.headers[key] = value

        return resp

    elif service == "webfinger":
        _endpoint = current_app.server.get_endpoint("discovery")
    else:
        return make_response("Not supported", 400)

    return service_endpoint(_endpoint)


@oidc.route("/registration", methods=["GET", "POST"])
def registration():
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
    code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
    code_challenge = code_challenge.replace("=", "")

    response = service_endpoint(current_app.server.get_endpoint("registration"))

    return response


@oidc.route("/registration_api", methods=["GET", "DELETE"])
def registration_api():
    if request.method == "DELETE":
        return service_endpoint(current_app.server.get_endpoint("registration_delete"))
    else:
        return service_endpoint(current_app.server.get_endpoint("registration_read"))


@oidc.route("/authorization", methods=["GET"])
def authorization():
    return service_endpoint(current_app.server.get_endpoint("authorization"))


# @oidc.route("/authorizationV2", methods=["GET"])
def authorizationv2(
    client_id,
    redirect_uri,
    response_type,
    scope=None,
    code_challenge_method=None,
    code_challenge=None,
    authorization_details=None,
):

    client_secret = str(uuid.uuid4())

    current_app.server.get_endpoint("registration").process_request_authorization(
        client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri
    )

    # return service_endpoint(current_app.server.get_endpoint("authorization"))
    url = urllib.parse.urljoin(
        cfgservice.service_url,
        "authorization?redirect_uri="
        + redirect_uri
        + "&response_type="
        + response_type
        + "&client_id="
        + client_id,
    )

    if scope:
        url = url + "&scope=" + scope

    if authorization_details:
        url = url + "&authorization_details=" + authorization_details

    if code_challenge and code_challenge_method:
        url = url + "&code_challenge="
        +code_challenge
        +"&code_challenge_method="
        +code_challenge_method

    payload = {}
    headers = {}
    response = requests.request("GET", url, headers=headers, data=payload)

    if response.status_code != 200:
        cfgservice.app_logger.error("Authorization endpoint invalid request")
        return auth_error_redirect(redirect_uri, "invalid_request")

    response = response.json()

    args = {}
    if "authorization_details" in response:
        args.update({"authorization_details": response["authorization_details"]})
    if "scope" in response:
        args.update({"scope": response["scope"]})
    if not args:
        cfgservice.app_logger.error("Authorization args not found")
        return authentication_error_redirect(
            jws_token=response["token"],
            error=response["error"],
            error_description=response["error_description"],
        )

    params = {"token": response["token"]}

    params.update(args)

    session["authorization_params"] = params

    session_id = str(uuid.uuid4())
    session_ids.update(
        {session_id: {"expires": datetime.now() + timedelta(minutes=60)}}
    )
    session["session_id"] = session_id
    cfgservice.app_logger.info(
        ", Session ID: "
        + session_id
        + ", "
        + "Authorization Request, Payload: "
        + str(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": response_type,
                "scope": scope,
                "code_challenge_method": code_challenge_method,
                "code_challenge": code_challenge,
                "authorization_details": authorization_details,
            }
        )
    )

    return redirect(response["url"])


@oidc.route("/authorizationV3", methods=["GET"])
def authorizationV3():

    if "request_uri" not in request.args:
        try:
            client_id = request.args.get("client_id")
            redirect_uri = request.args.get("redirect_uri")
            response_type = request.args.get("response_type")
            scope = request.args.get("scope")
            code_challenge_method = request.args.get("code_challenge_method")
            code_challenge = request.args.get("code_challenge")
            authorization_details = request.args.get("authorization_details")
        except:
            return make_response("Authorization v2 error", 400)
        return authorizationv2(
            client_id,
            redirect_uri,
            response_type,
            scope,
            code_challenge_method,
            code_challenge,
            authorization_details,
        )

    try:
        request_uri = request.args.get("request_uri")
    except:
        cfgservice.app_logger.error("Authorization request_uri not found")
        return make_response("Authorization error", 400)

    if not request_uri in parRequests:  # unknow request_uri => return error
        # needs to be changed to an appropriate error message, and need to be logged
        # return service_endpoint(current_app.server.get_endpoint("authorization"))
        cfgservice.app_logger.error(
            "Authorization request_uri not found in parRequests"
        )
        return make_response("Request_uri not found", 400)

    session_id = getSessionId_requestUri(request_uri)

    if session_id == None:
        cfgservice.app_logger.error("Authorization request_uri not found.")
        return make_response("Request_uri not found", 400)

    cfgservice.app_logger.info(
        ", Session ID: "
        + session_id
        + ", "
        + "Authorization Request, Payload: "
        + str(dict(request.args))
    )

    session["session_id"] = session_id

    par_args = parRequests[request_uri]["req_args"]

    if "scope" not in par_args:
        par_args["scope"] = "openid"

    url = urllib.parse.urljoin(
        cfgservice.service_url,
        "authorization?redirect_uri="
        + par_args["redirect_uri"]
        + "&response_type="
        + par_args["response_type"]
        + "&scope="
        + par_args["scope"]
        + "&client_id="
        + par_args["client_id"]
        + "&request_uri="
        + request_uri,
    )

    payload = {}
    headers = {}
    response = requests.request("GET", url, headers=headers, data=payload)

    if response.status_code != 200:
        cfgservice.app_logger.error("Authorization endpoint invalid request")
        return auth_error_redirect(par_args["redirect_uri"], "invalid_request")

    response = response.json()

    args = {}
    if "authorization_details" in response:
        args.update({"authorization_details": response["authorization_details"]})
    if "scope" in response:
        args.update({"scope": response["scope"]})
    if not args:
        cfgservice.app_logger.error("Authorization args not found")
        return authentication_error_redirect(
            jws_token=response["token"],
            error=response["error"],
            error_description=response["error_description"],
        )

    params = {"token": response["token"]}

    params.update(args)

    session["authorization_params"] = params

    return redirect(response["url"])


@oidc.route("/pid_authorization")
def pid_authorization_get():

    presentation_id = request.args.get("presentation_id")

    url = (
        cfgservice.dynamic_presentation_url
        + presentation_id
        + "?nonce=hiCV7lZi5qAeCy7NFzUWSR4iCfSmRb99HfIvCkPaCLc="
    )
    headers = {
        "Content-Type": "application/json",
    }

    response = requests.request("GET", url, headers=headers)
    if response.status_code != 200:
        error_msg = str(response.status_code)
        return jsonify({"error": error_msg}), 500
    else:
        data = {"message": "Sucess"}
        return jsonify({"message": data}), 200


@oidc.route("/auth_choice", methods=["GET"])
def auth_choice():
    token = request.args.get("token")
    logger = cfgservice.app_logger.getChild("auth_choice")

    supported_credencials = cfgservice.auth_method_supported_credencials
    pid_auth = True
    country_selection = True

    if "authorization_params" not in session:
        logger.info("Authorization Params didn't exist in Authentication Choice")
        return render_template(
            "misc/500.html",
            error="Invalid Authentication. No authorization details or scope found.",
        )

    authorization_params = session["authorization_params"]

    authorization_details = []
    if "authorization_details" in authorization_params:
        authorization_details.extend(
            json.loads(authorization_params["authorization_details"])
        )
    if "scope" in authorization_params:
        authorization_details.extend(scope2details(authorization_params["scope"]))

    credentials_requested = []
    for cred in authorization_details:
        if "credential_configuration_id" in cred:
            if cred["credential_configuration_id"] not in credentials_requested:
                credentials_requested.append(cred["credential_configuration_id"])
        elif "vct" in cred:
            if cred["vct"] not in credentials_requested:
                credentials_requested.append(cred["vct"])
    logger.info({
        "authorization_details": authorization_details,
        "authorization_params": authorization_params,
        "credentials_requested": credentials_requested,
    })

    for cred in credentials_requested:
        if (
            cred in supported_credencials["PID_login"]
            and cred not in supported_credencials["country_selection"]
        ):
            country_selection = False
        elif (
            cred not in supported_credencials["PID_login"]
            and cred in supported_credencials["country_selection"]
        ):
            pid_auth = False

    error = ""
    if pid_auth == False and country_selection == False:
        error = "Combination of requested credentials is not valid!"

    return render_template(
        "misc/auth_method.html",
        pid_auth=pid_auth,
        country_selection=country_selection,
        error=error,
        redirect_url=cfgservice.service_url,
    )

    # return render_template("misc/auth_method.html")


@oidc.route("/token_service", methods=["POST"])
def token_service():

    # session_id = request.cookies.get("session")

    response = service_endpoint(current_app.server.get_endpoint("token"))

    return response


@oidc.route("/token", methods=["POST"])
def token():
    logger = cfgservice.app_logger.getChild("token")

    req_args = dict([(k, v) for k, v in request.form.items()])

    response = None

    if req_args["grant_type"] == "authorization_code":

        session_id = getSessionId_authCode(req_args["code"])

        logger.info(
            ", Session ID: "
            + session_id
            + ", "
            + "Authorization Token Request, Payload: "
            + str(request.form.to_dict())
        )

        response = service_endpoint(current_app.server.get_endpoint("token"))

        logger.info(
            ", Session ID: "
            + session_id
            + ", "
            + "Authorization Token Response, Payload: "
            + str(json.loads(response.get_data()))
        )

        response_json = json.loads(response.get_data())

        if "access_token" in response_json:
            session_ids[session_id]["access_token"] = response_json["access_token"]

        if "refresh_token" in response_json:
            session_ids[session_id]["refresh_token"] = response_json["refresh_token"]

    elif (
        req_args["grant_type"] == "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    ):

        if "pre-authorized_code" not in req_args:
            return make_response("invalid_request", 400)

        if "tx_code" not in req_args:
            if "0" != transaction_codes[code]["tx_code"]:
                error_message = {
                    "error": "invalid_request",
                    "description": "invalid tx_code",
                }
            response = make_response(jsonify(error_message), 400)
            return response

        code = req_args["pre-authorized_code"]

        if code not in transaction_codes:
            error_message = {
                "error": "invalid_request",
                "description": "invalid or expired tx_code",
            }
            response = make_response(jsonify(error_message), 400)
            return response

        preauth_code = transaction_codes[code]["pre_auth_code"]

        session_id = getSessionId_authCode(preauth_code)

        logger.info(
            ", Session ID: "
            + session_id
            + ", "
            + "Pre-Authorized Token Request, Payload: "
            + str(request.form.to_dict())
        )

        if req_args["tx_code"] != transaction_codes[code]["tx_code"]:
            error_message = {
                "error": "invalid_request",
                "description": "invalid tx_code",
            }
            response = make_response(jsonify(error_message), 400)
            return response

        url = urllib.parse.urljoin(cfgservice.service_url, "token_service")
        redirect_url = "preauth"

        payload = (
            "grant_type=authorization_code&code="
            + preauth_code
            + "&redirect_uri="
            + redirect_url
            + "&client_id=ID&state=vFs5DfvJqoyHj7_dZs2JbdklePg6pMLsUHHmVIfobRw&code_verifier=FnWCRIhpJtl6IYwVVYB8gZkQsmvBVLfU4HQiABPopYQ6gvIZBwMrXg"
        )
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = requests.request("POST", url, headers=headers, data=payload)
        if response.status_code != 200:
            return make_response("invalid_request", 400)

        # response = response.json()
        logger.info("Token response: " + str(response.json()))

        transaction_codes.pop(code)

        logger.info(
            ", Session ID: "
            + session_id
            + ", "
            + "Pre-Authorized Token Response, Payload: "
            + str(response.json())
        )

        response_json = response.json()

        if "access_token" in response_json:
            session_ids[session_id]["access_token"] = response_json["access_token"]

        if "refresh_token" in response_json:
            session_ids[session_id]["refresh_token"] = response_json["refresh_token"]

        return response_json

    else:
        response = service_endpoint(current_app.server.get_endpoint("token"))
        logger.info(
            "Token response: " + str(json.loads(response.get_data()))
        )

    return response


@oidc.route("/introspection", methods=["POST"])
def introspection_endpoint():
    return service_endpoint(current_app.server.get_endpoint("introspection"))


@oidc.route("/userinfo", methods=["GET", "POST"])
def userinfo():
    return service_endpoint(current_app.server.get_endpoint("userinfo"))


@oidc.route("/session", methods=["GET"])
def session_endpoint():
    return service_endpoint(current_app.server.get_endpoint("session"))


@oidc.route("/pushed_authorization", methods=["POST"])
def par_endpoint():
    return service_endpoint(current_app.server.get_endpoint("pushed_authorization"))


@oidc.route("/pushed_authorizationv2", methods=["POST"])
def par_endpointv2():
    logger = cfgservice.app_logger.getChild("pushed_authorizationV2")
    session_id = str(uuid.uuid4())

    logger.info(
        ", Session ID: "
        + session_id
        + ", "
        + "Pushed Authorization Request, Payload: "
        + str(request.form.to_dict())
    )

    redirect_uri = None
    try:
        redirect_uri = request.form["redirect_uri"]

        client_id = request.form["client_id"]
    except:
        logger.error("PAR: client_id or redirect_uri not found")
        if redirect_uri:
            return auth_error_redirect(
                redirect_uri, "invalid_request", "invalid parameters"
            )
        else:
            return make_response("PARv2 error", 400)

    client_secret = str(uuid.uuid4())
    session["redirect_uri"] = redirect_uri
    current_app.server.get_endpoint("registration").process_request_authorization(
        client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri
    )

    response = service_endpoint(current_app.server.get_endpoint("pushed_authorization"))

    logger.info(
        ", Session ID: "
        + session_id
        + ", "
        + "Pushed Authorization Response, Payload: "
        + str(json.loads(response.get_data()))
    )

    session_ids.update(
        {
            session_id: {
                "expires": datetime.now() + timedelta(minutes=60),
                "request_uri": json.loads(response.get_data())["request_uri"],
            }
        }
    )

    return response


@oidc.route("/credential", methods=["POST"])
def credential():
    logger = cfgservice.app_logger.getChild("credential")

    headers = dict(request.headers)
    payload = json.loads(request.data)

    if "Authorization" not in headers:
        return make_response("Authorization error", 400)

    access_token = headers["Authorization"][7:]
    session_id = getSessionId_accessToken(access_token)

    logger.info(
        {
            "message": f"session ID: {session_id}, Credential Request",
            "session_id": session_id,
            "session": session,
            "request": payload,
            "headers": headers,
        }
    )
    _response = service_endpoint(current_app.server.get_endpoint("credential"))

    if isinstance(_response, Response):
        logger.info(
            {
                "message": f"session ID: {session_id}, Credential Response",
                "session_id": session_id,
                "response": json.loads(_response.get_data()),
            }
        )
        return _response

    if (
        "transaction_id" in _response
        and _response["transaction_id"] not in deferredRequests
    ):

        request_data = request.data
        request_headers = dict(request.headers)
        deferredRequests.update(
            {
                _response["transaction_id"]: {
                    "data": request_data,
                    "headers": request_headers,
                    "expires": datetime.now()
                    + timedelta(minutes=cfgservice.deffered_expiry),
                }
            }
        )
        _response = jsonify(_response)
        logger.info(
            {
                "message": f"session ID: {session_id}, Credential Response",
                "session_id": session_id,
                "response": _response,
            }
        )

        return make_response(_response, 202)
    logger.info(
        {
            "message": f"session ID: {session_id}, Credential Response",
            "session_id": session_id,
            "session": session,
            "response": _response,
        }
    )

    return _response


@oidc.route("/batch_credential", methods=["POST"])
def batchCredential():

    logger = cfgservice.app_logger.getChild("batch_credential")

    headers = dict(request.headers)
    payload = json.loads(request.data)

    if "Authorization" not in headers:
        return make_response("Authorization error", 400)

    access_token = headers["Authorization"][7:]
    session_id = getSessionId_accessToken(access_token)

    logger.info(
        {
            "message": f"session ID: {session_id}, Batch Credential Request",
            "session_id": session_id,
            "session": session,
            "request": payload,
            "headers": headers,
        }
    )

    _response = service_endpoint(current_app.server.get_endpoint("credential"))

    if isinstance(_response, Response):
        logger.info(
            {
                "message": f"session ID: {session_id}, Batch Credential Response",
                "session_id": session_id,
                "response": json.loads(_response.get_data()),
            }
        )
        return _response

    if (
        "transaction_id" in _response
        and _response["transaction_id"] not in deferredRequests
    ):

        request_data = request.data
        request_headers = dict(request.headers)
        deferredRequests.update(
            {
                _response["transaction_id"]: {
                    "data": request_data,
                    "headers": request_headers,
                    "expires": datetime.now()
                    + timedelta(minutes=cfgservice.deffered_expiry),
                }
            }
        )

        _response = jsonify(_response)
        logger.info(
            {
                "message": f"session ID: {session_id}, Batch Credential Response",
                "session_id": session_id,
                "response": _response,
            }
        )
        return make_response(_response, 202)

    logger.info(
        {
            "message": f"session ID: {session_id}, Batch Credential Response",
            "session_id": session_id,
            "session": session,
            "response": _response,
        }
    )

    return _response


@oidc.route("/notification", methods=["POST"])
def notification():

    headers = dict(request.headers)
    payload = json.loads(request.data)

    if "Authorization" not in headers:
        return make_response("Authorization error", 400)

    access_token = headers["Authorization"][7:]
    session_id = getSessionId_accessToken(access_token)

    cfgservice.app_logger.info(
        ", Session ID: "
        + session_id
        + ", "
        + "Notification Request, Payload: "
        + str(payload)
    )

    _resp = service_endpoint(current_app.server.get_endpoint("notification"))

    if isinstance(_resp, Response):
        cfgservice.app_logger.info(
            ", Session ID: "
            + session_id
            + ", "
            + "Notification response, Payload: "
            + str(_resp)
        )
        return _resp

    cfgservice.app_logger.info(
        ", Session ID: "
        + session_id
        + ", "
        + "Notification response, Payload: "
        + str(_resp)
    )

    return _resp


@oidc.route("/deferred_credential", methods=["POST"])
def deferred_credential():

    headers = dict(request.headers)
    payload = json.loads(request.data)
    if "Authorization" not in headers:
        return make_response("Authorization error", 400)

    access_token = headers["Authorization"][7:]
    session_id = getSessionId_accessToken(access_token)

    cfgservice.app_logger.info(
        ", Session ID: "
        + session_id
        + ", "
        + "Deferred Credential Request, Payload:, Payload: "
        + str(payload)
    )

    _resp = service_endpoint(current_app.server.get_endpoint("deferred_credential"))

    if isinstance(_resp, Response):
        cfgservice.app_logger.info(
            ", Session ID: "
            + session_id
            + ", "
            + "Deferred response, Payload: "
            + str(json.loads(_resp.get_data()))
        )
        return _resp

    cfgservice.app_logger.info(
        ", Session ID: "
        + session_id
        + ", "
        + "Deferred response, Payload: "
        + str(_resp)
    )

    return _resp


@oidc.route("credential_offer_choice", methods=["GET"])
def credential_offer():
    """Page for selecting credentials

    Loads credentials supported by EUDIW Issuer
    """
    credentialsSupported = oidc_metadata["credential_configurations_supported"]

    credentials = {"sd-jwt vc format": {}, "mdoc format": {}}

    for cred in credentialsSupported:
        credential = credentialsSupported[cred]

        if credential["format"] == "vc+sd-jwt":
            # if credential["scope"] == "eu.europa.ec.eudiw.pid.1":
            if (
                cred in cfgservice.auth_method_supported_credencials["PID_login"]
                or cred
                in cfgservice.auth_method_supported_credencials["country_selection"]
            ):
                credentials["sd-jwt vc format"].update(
                    # {"Personal Identification Data": cred}
                    {cred: credential["display"][0]["name"]}
                )

        if credential["format"] == "mso_mdoc":
            if (
                cred in cfgservice.auth_method_supported_credencials["PID_login"]
                or cred
                in cfgservice.auth_method_supported_credencials["country_selection"]
            ):
                credentials["mdoc format"].update(
                    {cred: credential["display"][0]["name"]}
                )

    return render_template(
        "openid/credential_offer.html",
        cred=credentials,
        redirect_url=cfgservice.service_url,
        credential_offer_URI="openid-credential-offer://",
    )


""" @oidc.route("/test_dump", methods=["GET", "POST"])
def dump_test():
    _store = current_app.server.context.dump()
    
    print("\n------Store-----\n", _store)
    print("\n------Store type-----\n", type(_store))
    
    json_string = json.dumps(_store, indent=4)
    
    with open("data.json", "w") as json_file:
        json_file.write(json_string)
    return "dump"

@oidc.route("/test_load", methods=["GET", "POST"])
def load_test():
    print("load_test\n")
    with open("data.json", "r") as json_file:
    # Load the JSON data from the file
        data = json.loads(json_file.read())
        print("\n-----Data-----\n",data)
        current_app.server.context.load(data)

    return "load" """


@oidc.route("/credential_offer", methods=["GET", "POST"])
def credentialOffer():

    credentialsSupported = oidc_metadata["credential_configurations_supported"]
    auth_choice = request.form.get("Authorization Code Grant")
    form_keys = request.form.keys()
    credential_offer_URI = request.form.get("credential_offer_URI")

    if "proceed" in form_keys:
        form = list(form_keys)
        form.remove("proceed")
        form.remove("credential_offer_URI")
        form.remove("Authorization Code Grant")
        all_exist = all(credential in credentialsSupported for credential in form)

        if all_exist:
            credentials_id = form
            session["credentials_id"] = credentials_id
            credentials_id_list = json.dumps(form)
            if auth_choice == "pre_auth_code":
                session["credential_offer_URI"] = credential_offer_URI
                return redirect(
                    url_for("preauth.preauthRed", credentials_id=credentials_id_list)
                )

            else:

                credential_offer = {
                    "credential_issuer": urlparse(cfgservice.service_url)
                    ._replace(path="")
                    .geturl(),
                    "credential_configuration_ids": credentials_id,
                    "grants": {"authorization_code": {}},
                }

                # create URI
                json_string = json.dumps(credential_offer)

                uri = (
                    f"{credential_offer_URI}credential_offer?credential_offer="
                    + urllib.parse.quote(json_string, safe=":/")
                )

                # Generate QR code
                # img = qrcode.make("uri")
                # QRCode.print_ascii()

                qrcode = segno.make(uri)
                out = io.BytesIO()
                qrcode.save(out, kind="png", scale=3)

                """ qrcode.to_artistic(
                    background=cfgtest.qr_png,
                    target=out,
                    kind="png",
                    scale=4,
                ) """
                # qrcode.terminal()
                # qr_img_base64 = qrcode.png_data_uri(scale=4)

                qr_img_base64 = "data:image/png;base64," + base64.b64encode(
                    out.getvalue()
                ).decode("utf-8")

                wallet_url = urllib.parse.urljoin(
                    cfgservice.wallet_test_url, "credential_offer"
                )

                return render_template(
                    "openid/credential_offer_qr_code.html",
                    wallet_dev=wallet_url
                    + "?credential_offer="
                    + json.dumps(credential_offer),
                    url_data=uri,
                    qrcode=qr_img_base64,
                )

    else:
        return redirect(
            urllib.parse.urljoin(cfgservice.service_url, "credential_offer_choice")
        )


""" @oidc.route("/testgetauth", methods=["GET"])
def testget():
    if "error" in request.args:
        response = (
            request.args.get("error") + "\n" + request.args.get("error_description")
        )
        return response
    else:
        return request.args.get("code") """


IGNORE = ["cookie", "user-agent"]


def service_endpoint(endpoint):
    # _log = current_app.logger
    logger = cfgservice.app_logger.getChild("service_endpoint").getChild(endpoint.name)
    logger.info('At the "{}" endpoint'.format(endpoint.name))

    http_info = {
        "headers": {
            k: v for k, v in request.headers.items(lower=True) if k not in IGNORE
        },
        "method": request.method,
        "url": request.url,
        # name is not unique
        "cookie": [{"name": k, "value": v} for k, v in request.cookies.items()],
    }
    logger.info(f"http_info: {http_info}")

    if endpoint.name == "credential":
        try:
            accessToken = http_info["headers"]["authorization"][7:]
            req_args = request.json
            req_args["access_token"] = accessToken
            req_args["oidc_config"] = cfgoidc
            req_args["aud"] = (
                urlparse(cfgservice.service_url)._replace(path="").geturl()
            )
            args = endpoint.process_request(req_args)
            if "response_args" in args:
                if "error" in args["response_args"]:
                    error = args["response_args"]["error"]
                    error_description = args["response_args"].get("error_description", "")
                    logger.error({
                        "message": f"error in credential response args: {error} {error_description}", 
                        "args":args,
                        "req_args": req_args
                    })
                    return (
                        jsonify(args["response_args"]),
                        400,
                        {"Content-Type": "application/json"},
                    )
                response = args["response_args"]
            else:
                if isinstance(args, ResponseMessage) and "error" in args:
                    logger.error("Error response in credential: {}".format(args))
                    response = make_response(args.to_json(), 400)
                else:
                    response = do_response(endpoint, args, **args)
            return response
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            err_msg = ResponseMessage(
                error="invalid_request", error_description=str(err)
            )
            return make_response(err_msg.to_json(), 400)

    if endpoint.name == "notification":
        try:
            accessToken = http_info["headers"]["authorization"][7:]
            req_args = request.json
            req_args["access_token"] = accessToken
            req_args["oidc_config"] = cfgoidc
            _resp = endpoint.process_request(req_args)

            if isinstance(_resp, ResponseMessage) and "error" in _resp:
                logger.error("Error response in notification: {}".format(_resp))
                _resp = make_response(_resp.to_json(), 400)

        except Exception as err:
            logger.error({"message": "Generic error in service endpoint", "err": err})
            return make_response(
                json.dumps({"error": "invalid_request", "error_description": str(err)}),
                400,
            )

        return _resp

    if endpoint.name == "deferred_credential":
        try:
            accessToken = http_info["headers"]["authorization"][7:]
            req_args = request.json
            req_args["access_token"] = accessToken
            req_args["oidc_config"] = cfgoidc
            args = endpoint.process_request(req_args)
            if "response_args" in args:
                if "error" in args["response_args"]:
                    return (
                        jsonify(args["response_args"]),
                        400,
                        {"Content-Type": "application/json"},
                    )
                response = args["response_args"]
            else:
                if isinstance(args, ResponseMessage) and "error" in args:
                    cfgservice.app_logger.error("Error response: {}".format(args))
                    response = make_response(args.to_json(), 400)
                else:
                    response = do_response(endpoint, args, **args)
            return response

        except Exception as err:
            cfgservice.app_logger.error(err)
            return make_response(
                json.dumps({"error": "invalid_request", "error_description": str(err)}),
                400,
            )

    if request.method == "GET":
        try:
            args = request.args.to_dict()
            if "client_id" in args:
                args["client_id"] = args["client_id"].split(".")[0]
            req_args = endpoint.parse_request(args, http_info=http_info)
        except ClientAuthenticationError as err:
            logger.error(err)
            return make_response(
                json.dumps(
                    {"error": "unauthorized_client", "error_description": str(err)}
                ),
                401,
            )
        except Exception as err:
            logger.error(err)
            return make_response(
                json.dumps({"error": "invalid_request", "error_description": str(err)}),
                400,
            )
    else:
        if request.data:
            if isinstance(request.data, str):
                req_args = request.data
            else:
                req_args = request.data.decode()
        else:
            req_args = dict([(k, v) for k, v in request.form.items()])
        try:
            req_args = endpoint.parse_request(req_args, http_info=http_info)
        except Exception as err:
            logger.error(err)
            err_msg = ResponseMessage(
                error="invalid_request", error_description=str(err)
            )
            return make_response(err_msg.to_json(), 400)

    if isinstance(req_args, ResponseMessage) and "error" in req_args:
        logger.error("Error response: {}".format(req_args))
        _resp = make_response(req_args.to_json(), 400)
        if request.method == "POST":
            _resp.headers["Content-type"] = "application/json"
        return _resp
    try:
        logger.info(
            {
                "message": "Service Endpoint request",
                "session": session,
                "request": req_args
            }
        )

        if isinstance(endpoint, Token):
            args = endpoint.process_request(
                AccessTokenRequest(**req_args), http_info=http_info
            )
        else:
            args = endpoint.process_request(
                request=req_args, http_info=http_info, oidc_config=cfgoidc
            )
    except Exception as err:
        message = traceback.format_exception(*sys.exc_info())
        logger.error(message)
        err_msg = ResponseMessage(error="invalid_request", error_description=str(err))
        return make_response(err_msg.to_json(), 400)

    # _log.info("Response args: {}".format(args))

    # "pushed_authorization"
    if (
        endpoint.name == "pushed_authorization"
        and "http_response" in args
        and "request_uri" in args["http_response"]
        and "expires_in" in args["http_response"]
    ):
        parRequests[args["http_response"]["request_uri"]] = {
            "req_args": req_args.to_dict(),
            "expires": args["http_response"]["expires_in"]
            + int(datetime.timestamp(datetime.now())),
        }

    if "redirect_location" in args:
        return redirect(args["redirect_location"])
    if "http_response" in args:
        return make_response(args["http_response"], 200)

    response = do_response(endpoint, req_args, **args)
    return response


@oidc.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return "bad request!", 400
