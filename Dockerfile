FROM ubuntu:22.04

# 1. Install dependencies FIRST
RUN apt-get update && apt-get install -y \
    g++ \
    libpcap-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# 2. Set the working directory
WORKDIR /app

# 3. Copy ALL project files (including src and CMakeLists.txt)
COPY . .

# 4. Clean up any local build artifacts copied by accident and build fresh
RUN rm -rf build && mkdir build && cd build && \
    cmake .. && \
    make

# 5. Run the binary
CMD ["./build/mini_ids"]