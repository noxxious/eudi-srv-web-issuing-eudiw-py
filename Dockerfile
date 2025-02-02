FROM python:3.12 AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /app

COPY app/requirements.txt /requirements.txt

WORKDIR /

# TODO: oscrypto not detecting OpenSSL>3 git+https://github.com/wbond/oscrypto.git
RUN python3 -m venv venv \ 
    && /venv/bin/pip install \
    --no-cache-dir -r requirements.txt
    # \
    #-I git+https://github.com/wbond/oscrypto.git

FROM python:3.12

RUN mkdir -p /tmp/log_dev \
    && chmod -R 755 /tmp/log_dev \
    && mkdir -p /etc/eudiw/pid-issuer/cert \
    && mkdir -p /etc/eudiw/pid-issuer/privkey

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /venv /venv
COPY ./app /app

WORKDIR /app

ENV PORT=5000
ENV HOST=0.0.0.0
ENV EIDAS_NODE_URL="https://preprod.issuer.eudiw.dev/EidasNode/"
ENV DYNAMIC_PRESENTATION_URL="https://dev.verifier-backend.eudiw.dev/ui/presentations/"
ENV SERVICE_URL="http://127.0.0.1:${PORT}/"
ENV FLASK_SECRET="secret"
ENV REVOCATION_API_KEY="secret"
ENV EIDASNODE_LIGHTTOKEN_SECRET="secret"
ENV FLASK_RUN_PORT=$PORT
ENV FLASK_RUN_HOST=$HOST
ENV REQUESTS_CA_BUNDLE=/app/secrets/cert.pem
ENV USE_GCP_LOGGER=0
ENV USE_FILE_LOGGER=1
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV ENABLED_COUNTRIES=""
ENV PID_ISSUING_AUTHORITY="Test PID Issuer"
ENV PID_ORG_ID="Test mDL Issuer"
ENV MDL_ISSUING_AUTHORITY="Test mDL Issuer"
ENV QEAA_ISSUING_AUTHORITY="Test QEAA Issuer"

EXPOSE $PORT

VOLUME /app/secrets/cert.pem
VOLUME /app/secrets/cert.key
VOLUME /etc/eudiw/pid-issuer/privKey
VOLUME /etc/eudiw/pid-issuer/cert
VOLUME /tmp/log_dev

#ENV FLASK_APP=app \
#    FLASK_RUN_PORT=$PORT\
#    FLASK_RUN_HOST=$HOST\
#    SERVICE_URL="https://127.0.0.1:5000/" \
#    EIDAS_NODE_URL="${EIDAS_NODE_URL}"
#    DYNAMIC_PRESENTATION_URL="${DYNAMIC_PRESENTATION_URL}"

#ENTRYPOINT [ "/venv/bin/flask" ]
#CMD ["run", "--cert=/app/secrets/cert.pem", "--key=/app/secrets/key.pem"]
CMD ["/venv/bin/flask", "--app", ".", "run"]
