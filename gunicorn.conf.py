# Gunicorn configuration file

# Worker class
worker_class = "uvicorn.workers.UvicornWorker"

# Number of worker processes
workers = 4

# The socket to bind to
bind = "0.0.0.0:8000"

# Log level
loglevel = "info"

# Log to stdout
accesslog = "-"
errorlog = "-"
