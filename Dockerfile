FROM golang:1.18.3-alpine3.16 as builder

WORKDIR /build
COPY . ./

RUN go mod download -x
RUN CGO_ENABLED=0 GOOS=linux go build -o xliic-firewall-injector .

FROM busybox
COPY --from=builder /build/xliic-firewall-injector /bin/
EXPOSE 8080
ENTRYPOINT ["/bin/xliic-firewall-injector"]
