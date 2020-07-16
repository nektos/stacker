FROM python:3.8-alpine
MAINTAINER Casey Lee

RUN apk add --no-cache git build-base libffi-dev openssl-dev ncurses-dev openssh-client

COPY requirements.txt /app/
WORKDIR /app

RUN pip install -r requirements.txt

COPY hooks /app/hooks
COPY lookup /app/lookup

ENV PYTHONPATH "${PYTHONPATH}:/app"
ENTRYPOINT ["stacker"]
CMD ["-h"]
