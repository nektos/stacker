FROM python:3.8-alpine
MAINTAINER Casey Lee

COPY requirements.txt /app/
WORKDIR /app

RUN pip install -r requirements.txt

ENTRYPOINT ["stacker"]
CMD ["-h"]
