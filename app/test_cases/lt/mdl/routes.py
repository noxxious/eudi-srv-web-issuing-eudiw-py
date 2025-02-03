"""
Test cases for Lithuanian mDL issuer interop tests.
"""

from datetime import datetime, date, timedelta
from flask_cors import CORS
from flask import Blueprint, Flask, redirect, render_template, request, session
from flask_api import status
from pathlib import Path
from urllib.parse import urljoin

from app_config.config_service import ConfService as cfgserv
from test_cases.helper import add_number_to_image, convert_image_to_base64
from misc import (
    generate_unique_id,
    calculate_age,
)

from .test_cases import test_cases

blueprint = Blueprint("test_lt_mdl", __name__, url_prefix="/testcase/lt/mdl/")
CORS(blueprint)  # enable CORS on the blue print

app = Flask(__name__)

from app.data_management import form_dynamic_data


@blueprint.route("/mdl_test_case_form", methods=["GET", "POST"])
def mdl_test_case_form():
    """
    Form page for test cases.
    Form page where the user can select mDL test case.
    """
    session["route"] = "/testcase/lt/mdl/mdl_test_case_form"
    session["version"] = "0.5"
    session["country"] = "LT"
    logger = cfgserv.app_logger.getChild("credential")

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

    test_case_number = int(form_data.get("case", "1"))
    test_case = str(test_case_number)

    # this is needed because of signature_usual_mark and usual_mark field uncertainty between ISO and POTENTIAL UC4 Test event doc
    if test_case_number > 8:
        test_case = str(test_case_number - 8)

    mdl_data = test_cases.get(test_case, test_cases["default"])
    user_id = generate_unique_id()

    if mdl_data["mDL"]["portrait"] == "M":
        mdl_data["mDL"]["portrait"] = add_number_to_image(
            Path(__file__).parent / "static" / "image.jpeg", test_case_number
        )
    else:
        mdl_data["mDL"]["portrait"] = add_number_to_image(
            Path(__file__).parent / "static" / "image2.jpeg", test_case_number
        )

    # add signature field (depending on test case number either to signature_usual_mark or usual_mark field
    signature_path = Path(__file__).parent / "static" / "signature.jpg"

    if test_case_number > 8:
        mdl_data["mDL"].update({"usual_mark": convert_image_to_base64(signature_path)})
    else:
        mdl_data["mDL"].update(
            {"signature_usual_mark": convert_image_to_base64(signature_path)}
        )

    mdl_data["mDL"].update(
        {
            "issuing_country": session["country"],
            "issuing_authority": cfgserv.mdl_issuing_authority,
        }
    )

    form_dynamic_data[user_id] = mdl_data["mDL"].copy()
    form_dynamic_data[user_id].update(
        {"expires": datetime.now() + timedelta(minutes=cfgserv.form_expiry)}
    )

    if "jws_token" not in session or "authorization_params" in session:
        session["jws_token"] = session["authorization_params"]["token"]
    session["returnURL"] = cfgserv.OpenID_first_endpoint

    doctype_config = cfgserv.config_doctype["org.iso.18013.5.1.mDL"]

    today = date.today()
    expiry = today + timedelta(days=doctype_config["validity"])

    for privilege in mdl_data["mDL"]["driving_privileges"]:
        if "expiry_date" not in privilege:
            privilege["expiry_date"] = expiry.strftime("%Y-%m-%d")

    mdl_data["mDL"].update({"estimated_issuance_date": today.strftime("%Y-%m-%d")})
    mdl_data["mDL"].update({"estimated_expiry_date": expiry.strftime("%Y-%m-%d")})
    mdl_data["mDL"].update({"issuing_country": session["country"]}),
    mdl_data["mDL"].update({"issuing_authority": doctype_config["issuing_authority"]})
    mdl_data["mDL"].update(
        {
            "age_over_18": (
                True if calculate_age(mdl_data["mDL"]["birth_date"]) >= 18 else False
            )
        }
    )
    mdl_data["mDL"].update({"un_distinguishing_sign": "LT"}),

    user_id = ("LT." + user_id,)

    logger.info(
        {
            "message": "Issued mDL attestation",
            "attestation": mdl_data,
            "user_id": user_id,
        }
    )

    return render_template(
        "dynamic/form_authorize.html",
        presentation_data=mdl_data,
        user_id=user_id,
        redirect_url=urljoin(cfgserv.service_url, "dynamic/redirect_wallet"),
    )
