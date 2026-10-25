FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    gcc \
    libc6-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY include/ ./include/
COPY src/ ./src/
COPY frontend/ ./frontend/

RUN gcc -std=c11 -O2 \
    -Iinclude/sqlite \
    -c include/sqlite/sqlite3.c \
    -o /tmp/sqlite3.o

RUN g++ -std=c++17 -O2 \
    -Iinclude \
    -Iinclude/sqlite \
    src/server.cpp \
    src/detector.cpp \
    src/db.cpp \
    /tmp/sqlite3.o \
    -pthread \
    -o /app/sentinelx_server

ENV PORT=10000

EXPOSE 10000

CMD ["/app/sentinelx_server"]
