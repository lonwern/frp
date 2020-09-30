FROM alpine:latest

ENV FRP_VERSION 0.33.0-tls

COPY files /

WORKDIR /frpc
ENTRYPOINT ["/frpc/frpc"]
CMD ["-c", "frpc.ini"]
