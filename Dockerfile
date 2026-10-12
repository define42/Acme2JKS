FROM golang:latest AS builder
WORKDIR /app/
COPY go.mod go.mod
COPY go.sum go.sum
COPY *.go ./

RUN CGO_ENABLED=0 go build -o /main .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /main /main
ENTRYPOINT ["/main"]
