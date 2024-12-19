import os
import json

from ..app_config.config_service import ConfService

from .openid_configuration import build_openid_configuration


def build_metadata(cfgserv: ConfService):
    oidc_metadata = {
        "credential_issuer": cfgserv.service_url,
        "credential_endpoint": cfgserv.service_url + "/credential",
        "batch_credential_endpoint": cfgserv.service_url + "/batch_credential",
        "notification_endpoint": cfgserv.service_url + "/notification",
        "deferred_credential_endpoint": cfgserv.service_url + "/deferred_credential",
        "credential_configurations_supported": {},
    }
    openid_metadata = build_openid_configuration(cfgserv)

    credentials_supported = {}

    dir_path = os.path.dirname(os.path.realpath(__file__))

    for file in os.listdir(os.path.join(dir_path, "credentials_supported")):
        if not file.endswith("json"):
            continue

        json_path = os.path.join(dir_path, "credentials_supported", file)
        try:
            with open(json_path, encoding="utf-8") as json_file:
                credential = json.load(json_file)
                credentials_supported.update(credential)

        except FileNotFoundError as e:
            cfgserv.app_logger.exception(
                "Metadata Error: file not found. %s - %s", json_path, e
            )
        except json.JSONDecodeError as e:
            cfgserv.app_logger.exception(
                "Metadata Error: Metadata Unable to decode JSON. %s - %s", json_path, e
            )
        except Exception as e:
            cfgserv.app_logger.exception(
                "Metadata Error: An unexpected error occurred. %s -  %s", json_path, e
            )

    oidc_metadata["credential_configurations_supported"] = credentials_supported

    return oidc_metadata, openid_metadata
