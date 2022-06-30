FROM golang:1.17-alpine3.15 as builder

WORKDIR /build
COPY . ./

RUN go mod download -x
RUN CGO_ENABLED=0 GOOS=linux go build -o xliic-firewall-injector .

FROM busybox
COPY --from=builder /build/xliic-firewall-injector /bin/
EXPOSE 8080
ENTRYPOINT ["/bin/xliic-firewall-injector"]
