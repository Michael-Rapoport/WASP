# Use the official Rust image as a parent image
FROM rust:1.58 as builder

# Set the working directory in the container
WORKDIR /usr/src/wasp

# Copy the current directory contents into the container
COPY . .

# Build the application
RUN cargo build --release

# Use a smaller base image for the runtime
FROM debian:buster-slim

# Copy the binary from the builder stage
COPY --from=builder /usr/src/wasp/target/release/wasp /usr/local/bin/wasp

# Set the working directory
WORKDIR /usr/local/bin

# Run the binary
CMD ["wasp"]