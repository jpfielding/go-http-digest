FROM golang:1.16 as builder

WORKDIR /sandbox
COPY ./ ./

RUN set -eux \
    && go mod tidy \
    && go test -v ./pkg/* \
    && CGO_ENABLED=0 GOOS=linux go build -o http-digest cmd/*.go


### the deployed image
FROM alpine

# add certs then wipe the cache
RUN set -eux \
    && apk --update add ca-certificates \
    && rm -rf /var/cache/apk/*

COPY --from=builder /sandbox/http-digest /usr/local/bin/
RUN set -eux \
    && chmod +x /usr/local/bin/http-digest \ 
    && mkdir -p /app/data

ENTRYPOINT ["/bin/sh", "-c","/usr/local/bin/http-digest"]
CMD []