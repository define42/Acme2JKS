FROM golang:latest AS builder
WORKDIR /app/
COPY go.mod go.mod
COPY go.sum go.sum
COPY main.go main.go

RUN CGO_ENABLED=0 go build -o /main main.go

FROM scratch
COPY --from=builder /main /main
ENTRYPOINT ["/main"]
