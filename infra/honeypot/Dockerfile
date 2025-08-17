# infra/honeypot/Dockerfile
FROM cowrie/cowrie:latest

# Create a non-root user to run the application
# We use a fixed UID/GID for consistency across all systems
RUN addgroup --gid 1000 cowrie && \
    adduser --system --uid 1000 --gid 1000 --shell /bin/bash cowrie

# Ensure the application directory is owned by the new user
RUN chown -R cowrie:cowrie /cowrie

# Switch to the new non-root user
USER cowrie
