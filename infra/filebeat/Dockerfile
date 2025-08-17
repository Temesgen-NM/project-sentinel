# infra/filebeat/Dockerfile
FROM docker.elastic.co/beats/filebeat:8.11.1

# Copy the local configuration file into the image
COPY filebeat.yml /usr/share/filebeat/filebeat.yml

# Set the ownership of the configuration to the root user, as required by Filebeat
RUN chown root:root /usr/share/filebeat/filebeat.yml
