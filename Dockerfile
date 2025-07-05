# Dockerfile for the dpdk-pot application
# This file should be in the root of your 'dpdk-pot' project.

# Use your pre-built DPDK base image
FROM yigithak/dpdk-base:ubuntu24.04-24.03.1

# Arguments for flexibility
ARG APP_HOME=/opt/dpdk-pot
ARG BINARY_NAME=dpdk-pot

# Create application directory 
RUN mkdir -p ${APP_HOME}

# Copy the compiled DPDK application binary from your project's build directory
# into a standard location within the image
COPY build/dpdk-pot /usr/local/bin/dpdk-pot

# Ensure the binary is executable
RUN chmod +x /usr/local/bin/${BINARY_NAME}

# Copy segment list file if it exists
COPY segment_list.txt ${APP_HOME}/segment_list.txt

# Create log directory
RUN mkdir -p /var/log/dpdk-pot

# Set the working directory for the application
WORKDIR ${APP_HOME}

# Define the entrypoint for the container
ENTRYPOINT ["/usr/local/bin/dpdk-pot"]

# Default command if none is provided to 'docker run'
CMD ["--help"]