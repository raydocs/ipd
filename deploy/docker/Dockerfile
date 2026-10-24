FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/ipd ./cmd/ipd

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/ipd /ipd
EXPOSE 8787
ENV IPD_HTTP_ADDR=0.0.0.0:8787 \
    IPD_DNS_ADDR=127.0.0.1:5353 \
    IPD_STUN_ADDR=127.0.0.1:34780 \
    IPD_TLS_ADDR=127.0.0.1:8443 \
    IPD_DATA_DIR=/var/lib/ipd \
    IPD_SHARE_ENABLED=false \
    IPD_LABELS_ENABLED=false
VOLUME /var/lib/ipd
USER 65532:65532
ENTRYPOINT ["/ipd"]
CMD ["serve"]
