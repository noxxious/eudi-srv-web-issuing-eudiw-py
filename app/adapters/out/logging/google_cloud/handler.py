import json
import os
import sys
from google.cloud.logging_v2.handlers import StructuredLogHandler

# from logging import StreamHandler

from flask import request

class CustomEncoder(json.JSONEncoder):
    """Cutom encoder with fallback to pure string encoding for unknown types."""
    def default(self, obj):
        try:
            return super().default(obj)
        except Exception:
            return str(obj)

class GoogleCloudHandler(StructuredLogHandler):
    """Logging handler to log in json format, readable by GCP."""

    def __init__(
        self,
        *,
        labels=None,
        stream=None,
        project_id=None,
        json_encoder_cls=CustomEncoder,
        **kwargs,
    ):
        super(GoogleCloudHandler, self).__init__(
            labels=labels,
            stream=stream,
            project_id=project_id,
            json_encoder_cls=json_encoder_cls,
            **kwargs,
        )

    def emit(self, record):
        # Get project_id from Cloud Run environment
        project = os.environ.get("GOOGLE_CLOUD_PROJECT")

        # Build structured log messages as an object.
        global_log_fields = {}
        if request:
            trace_header = request.headers.get("X-Cloud-Trace-Context")

            if trace_header and project:
                trace = trace_header.split("/")
                record["logging.googleapis.com/trace"] = f"projects/{project}/traces/{trace[0]}" 
                record["trace"] = trace[0] 

        record["trace"] = f"projects/{project}/traces/{record.trace}"

        # Complete a structured log entry.
        record.severity = record.levelname
        super().emit(record)

        # print(json.dumps(record))
        sys.stdout.flush()
