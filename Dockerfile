# We will use python:3.11-slim as the base image for building the Flask container
FROM python:3.11-slim

# create a non-root user to run the application for security hardening
RUN groupadd -r --gid 10001 mygroup && useradd -r -g mygroup --uid 10001 -s /bin/bash myuser

# This specifies the working directory where the Docker container will run
WORKDIR /app
# Make sure our new user can run the app
RUN chown -R 10001:10001 /app

# Swap into the new user
USER 10001:10001

# Set up the python virtual env
ENV VIRTUAL_ENV=/app/ENV
RUN python -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Copying the requirements
COPY app/requirements.txt .
# Install all the dependencies required to run the Flask application
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application
COPY --chown=10001:10001 --chmod=0744 app/ app/
COPY --chown=10001:10001 --chmod=0744 app/config.ini .
RUN mv app/static .
RUN mv app/templates .

# Expose the Docker container for the application to run on port 5000
EXPOSE 5000
# The command required to run the Dockerized application
CMD ["python", "-m", "app"]
