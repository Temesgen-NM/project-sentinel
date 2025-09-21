# infra/filebeat/Dockerfile
FROM docker.elastic.co/beats/filebeat:8.18.4



# Copy the local configuration file into the image
COPY --chown=filebeat:filebeat --chmod=0640 filebeat.yml /usr/share/filebeat/filebeat.yml

# Switch to the non-root user
USER filebeat