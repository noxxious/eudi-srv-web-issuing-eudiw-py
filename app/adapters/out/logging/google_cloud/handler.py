import json
import logging
import os
import sys
from logging import StreamHandler

from flask import request


class GoogleCloudHandler(StreamHandler):
    def __init__(self):
        StreamHandler.__init__(self)

    def emit(self, record):
        msg = self.format(record)
        # Get project_id from Cloud Run environment
        project = os.environ.get('GOOGLE_CLOUD_PROJECT')

        # Build structured log messages as an object.
        global_log_fields = {}
        trace_header = request.headers.get('X-Cloud-Trace-Context')

        if trace_header and project:
            trace = trace_header.split('/')
            global_log_fields['logging.googleapis.com/trace'] = (
                f"projects/{project}/traces/{trace[0]}")

        # Complete a structured log entry.
        entry = dict(severity=record.levelname, message=msg)
        print(json.dumps(entry))
        sys.stdout.flush()