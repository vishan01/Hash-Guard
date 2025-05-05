# Use an official Ubuntu runtime as a parent image
FROM ubuntu:latest

# Set the maintainer label
LABEL maintainer="neelothpal.12@gmail.com"

# Install required packages
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    gcc \
    make \
    libmbedtls-dev && \
    rm -rf /var/lib/apt/lists/*

# Create a workspace directory
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Compile the C program
RUN gcc -o crypto_app final_engine.c -lmbedtls -lmbedx509 -lmbedcrypto

# Run the compiled binary
CMD ["./crypto_app"]
