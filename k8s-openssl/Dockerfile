FROM alpine:3.18

# Set by docker automatically
ARG TARGETOS
ARG TARGETARCH

RUN apk --upgrade --no-cache add openssl curl

RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

WORKDIR /app
USER 1000
