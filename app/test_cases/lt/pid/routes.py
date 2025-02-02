"""
Test cases for Lithuanian PID issuer interop tests.
"""

from datetime import datetime, date, timedelta
from flask_cors import CORS
from flask import Blueprint, Flask, render_template, request, session
from flask_api import status
from urllib.parse import urljoin

from app_config.config_service import ConfService as cfgserv
from misc import (
    generate_unique_id,
    calculate_age,
)

from .test_cases import test_cases

blueprint = Blueprint("test_lt_pid", __name__, url_prefix="/testcase/lt/pid/")
CORS(blueprint)  # enable CORS on the blue print

app = Flask(__name__)
from app.data_management import form_dynamic_data


@blueprint.route("/pid_test_case_form", methods=["GET", "POST"])
def pid_test_case_form():
    """Form page for test cases.
    Form page where the user can select mDL test case.
    """
    session["route"] = "/testcase/lt/pid/pid_test_case_form"
    session["version"] = "0.5"
    session["country"] = "LT"
    # if GET
    if request.method == "GET":
        # print("/pid/form GET: " + str(request.args))
        if (
            session.get("country") is None or session.get("returnURL") is None
        ):  # someone is trying to connect directly to this endpoint
            return (
                "Error 101: " + cfgserv.error_list["101"] + "\n",
                status.HTTP_400_BAD_REQUEST,
            )

    if "Cancelled" in request.form.keys():  # Form request Cancelled
        return render_template("misc/auth_method.html")

    form_data = request.form.to_dict()

    test_case = form_data.get("case", "1")

    pid_data = test_cases.get(test_case, test_cases["default"])

    user_id = generate_unique_id()

    pid_data["PID"].update(
        {
            "issuing_country": session["country"],
            "issuing_authority": cfgserv.pid_issuing_authority,
        }
    )

    form_dynamic_data[user_id] = pid_data["PID"].copy()
    form_dynamic_data[user_id].update(
        {"expires": datetime.now() + timedelta(minutes=cfgserv.form_expiry)}
    )

    if "jws_token" not in session or "authorization_params" in session:
        session["jws_token"] = session["authorization_params"]["token"]
    session["returnURL"] = cfgserv.OpenID_first_endpoint

    doctype_config = cfgserv.config_doctype["eu.europa.ec.eudi.pid.1"]

    today = date.today()
    expiry = today + timedelta(days=doctype_config["validity"])

    pid_data["PID"].update({"estimated_issuance_date": today.strftime("%Y-%m-%d")})
    pid_data["PID"].update({"estimated_expiry_date": expiry.strftime("%Y-%m-%d")})
    pid_data["PID"].update({"issuing_country": session["country"]}),
    pid_data["PID"].update({"issuing_authority": doctype_config["issuing_authority"]})
    pid_data["PID"].update(
        {
            "age_over_18": (
                True if calculate_age(pid_data["PID"]["birth_date"]) >= 18 else False
            )
        }
    )
    pid_data["PID"].update({"un_distinguishing_sign": "LT"}),

    return render_template(
        "dynamic/form_authorize.html",
        presentation_data=pid_data,
        user_id="LT." + user_id,
        redirect_url=urljoin(cfgserv.service_url, "dynamic/redirect_wallet"),
    )
