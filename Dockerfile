FROM golang:1.25.5 AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o policy_engine .

########################################################################
# APP Image
########################################################################

FROM debian:bookworm-slim AS app

COPY --from=builder /src/policy_engine /

CMD ["/policy_engine"]
