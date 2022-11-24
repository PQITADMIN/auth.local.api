# Start from golang base image
FROM golang:alpine as builder

# Enable go modules
ENV GO111MODULE=on
RUN apk --update add --no-cache ca-certificates openssl git tzdata && update-ca-certificates

# Install git. (alpine image does not have git in it)
RUN apk update && apk add --no-cache git

# Set current working directory
WORKDIR /app

# Note here: To avoid downloading dependencies every time we
# build image. Here, we are caching all the dependencies by
# first copying go.mod and go.sum files and downloading them,
# to be used every time we build the image if the dependencies
# are not changed.

# Copy go mod and sum files
COPY go.mod ./
COPY go.sum ./

# Download all dependencies.
RUN go mod download

# Now, copy the source code
COPY . .

# Note here: CGO_ENABLED is disabled for cross system compilation
# It is also a common best practise.

# Build the application.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./bin/main .

# Finally our multi-stage to build a small image
# Start a new stage from scratch
FROM scratch

# Copy the Pre-built binary file
COPY --from=builder /app/bin/main .

FROM scratch
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
# This line will copy all certificates to final image
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
WORKDIR /app
COPY --from=builder /app/bin/main .
COPY --from=builder /app/template/ ./template
COPY --from=builder /app/datasources/config/rbac_model.conf ./datasources/config/rbac_model.conf


EXPOSE 8080

# Run executable
CMD ["./main"]