# Use an Eclipse Temurin JDK 21 JRE image as the base
FROM eclipse-temurin:21-jre-jammy

# Install Python, pip, nginx, and supervisor
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3.10 \
    python3-pip \
    nginx \
    supervisor && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set python3.10 as default
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1

# JAVA_HOME is usually correctly set in temurin images, but explicitly setting for clarity
ENV JAVA_HOME /opt/java/openjdk
ENV PATH $JAVA_HOME/bin:$PATH

# Set the working directory in the container
WORKDIR /app

# Copy all project files to the working directory
COPY . /app

# Install Python dependencies (ensure gunicorn is in requirements.txt)
RUN pip install --no-cache-dir -r requirements.txt

# Copy supervisor and nginx configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY nginx.conf /etc/nginx/sites-available/default

# Create log directory for supervisor
RUN mkdir -p /var/log/supervisor

# Expose the port that Nginx will run on.
# Port 80 is the standard for HTTP. The old Streamlit setup used 7860.
EXPOSE 80

# Command to run supervisor which starts nginx and the backend
CMD ["/usr/bin/supervisord"]
