FROM golang:1.23
WORKDIR /app
COPY . .
RUN go mod tidy
RUN go build -o server .
CMD ["./server"]
EXPOSE 8080
