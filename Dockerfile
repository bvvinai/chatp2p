FROM golang:1.22

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY main.go main.go
COPY network.go network.go
RUN go build -v -o /usr/local/bin/app ./...
EXPOSE 8080
CMD ["app"]
