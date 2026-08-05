FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/importer ./cmd/importer

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/importer /importer
USER nonroot:nonroot
EXPOSE 9090
ENTRYPOINT ["/importer"]
