FROM python:3.12-alpine3.21

WORKDIR /app

COPY requirements.txt .

RUN apk update && apk add --no-cache ca-certificates

RUN pip install --upgrade pip
RUN pip install --trusted-host pypi.python.org --trusted-host files.pythonhosted.org --trusted-host pypi.org -r requirements.txt

COPY . .