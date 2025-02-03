import json
import os
import sys
from google.cloud.logging_v2.handlers import StructuredLogHandler
#from logging import StreamHandler

from flask import request


class GoogleCloudHandler(StructuredLogHandler):
    def __init__(self):
        super(GoogleCloudHandler, self).__init__()

    def emit(self, record):
        # Get project_id from Cloud Run environment
        project = os.environ.get('GOOGLE_CLOUD_PROJECT')

        # Build structured log messages as an object.
        global_log_fields = {}
        if request:
            trace_header = request.headers.get('X-Cloud-Trace-Context')

            if trace_header and project:
                trace = trace_header.split('/')
                record['logging.googleapis.com/trace'] = f"projects/{project}/traces/{trace[0]}"

        # Complete a structured log entry.
        record.severity=record.levelname
        super().emit(record)
    
        #print(json.dumps(record))
        sys.stdout.flush()
    