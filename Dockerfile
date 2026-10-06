FROM python:3.11-alpine as builder
RUN apk --update add bash nano g++ libxml2-dev libxslt-dev jpeg-dev zlib-dev
COPY ./requirements.txt /vampi/requirements.txt
WORKDIR /vampi
RUN pip install -r requirements.txt

# Build a fresh container, copying across files & compiled parts
FROM python:3.11-alpine
RUN apk --update add --no-cache libxml2 libxslt jpeg
COPY . /vampi
WORKDIR /vampi
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/bin /usr/local/bin
ENV vulnerable=1
ENV tokentimetolive=60

ENTRYPOINT ["python"]
CMD ["app.py"]
