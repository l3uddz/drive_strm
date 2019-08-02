FROM python:3.7-alpine

LABEL maintainer="l3uddz"

# Arguments for build tracking
ARG BRANCH=
ARG COMMIT=

# Env vars
ENV \
  APP_DIR=/app \
  BRANCH=${BRANCH} \
  COMMIT=${COMMIT} \
  DRIVE_STRM_CONFIG_PATH=/config/config.json \
  DRIVE_STRM_VAULT_PATH=/config/vault.db \
  DRIVE_STRM_LOG_PATH=/config/activity.log

# Copy app
COPY [".", "${APP_DIR}"]

# Install dependencies
RUN \
  echo "** BRANCH: ${BRANCH} COMMIT: ${COMMIT} **" && \
  echo "** Install build dependencies **" && \
  apk --no-cache -U add --virtual .build-deps gcc musl-dev && \
  echo "** Install PIP dependencies **" && \
  pip install --no-cache-dir --upgrade pip setuptools && \
  pip install --no-cache-dir --upgrade -r ${APP_DIR}/requirements.txt && \
  echo "** Remove build dependencies **" && \
  apk del .build-deps

# Change directory
WORKDIR ${APP_DIR}

# Volumes
VOLUME ["/config", "/strm"]

# Port
EXPOSE 7294

# Entrypoint
ENTRYPOINT ["python", "drive_strm.py"]

# Default command
CMD ["run"]
