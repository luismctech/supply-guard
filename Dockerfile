FROM alpine:3.21@sha256:22e0ec13c0db6b3e1ba3280e831fc50ba7bffe58e81f31670a64b1afede247bc

RUN apk add --no-cache ca-certificates && \
    adduser -D -h /home/supplyguard supplyguard

COPY supply-guard /usr/local/bin/

USER supplyguard

ENTRYPOINT ["supply-guard"]
