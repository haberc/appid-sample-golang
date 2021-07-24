FROM golang:alpine
WORKDIR /app
COPY go.mod ./
COPY go.sum ./
COPY main.go ./
ADD config ./config
ADD static ./static

RUN go build -o /app/main

# Copy the exe into a smaller base image
FROM alpine
WORKDIR /app
COPY --from=0 /app/main /app/main
COPY --from=0 /app/config /app/config
COPY --from=0 /app/static /app/static

EXPOSE 3000
CMD /app/main
