FROM golang:1.24-alpine

WORKDIR /app

COPY go.mod go.sum ./

# Обновление зависимостей
RUN go mod download

COPY . .

RUN go build -o main ./cmd

EXPOSE 8080

CMD ["./main"]
