# infra/filebeat/Dockerfile
FROM docker.elastic.co/beats/filebeat:8.11.1

# Copy the local configuration file into the image
COPY --chown=root:root --chmod=0640 filebeat.yml /usr/share/filebeat/filebeat.yml

# Ownership and permissions are set at copy time above. No additional chown step needed.
