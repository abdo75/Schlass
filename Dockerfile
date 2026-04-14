# Stage 1: Build frontend
FROM node:22-alpine AS frontend
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build
# Output is at /build/internal/web/dist

# Stage 2: Build Go binary
FROM golang:1.25-alpine AS backend
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /build/internal/web/dist ./internal/web/dist
RUN CGO_ENABLED=0 go build -o /schlass ./cmd/schlass

# Stage 3: Runtime
FROM alpine:3.21
RUN apk --no-cache add ca-certificates wget
COPY --from=backend /schlass /usr/local/bin/schlass
EXPOSE 3000
CMD ["schlass"]
