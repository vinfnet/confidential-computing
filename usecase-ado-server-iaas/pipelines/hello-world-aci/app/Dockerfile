# Minimal, dependency-free hello-world image for Confidential ACI.
# Uses the Python standard library only (no pip install) so the image is tiny
# and `az confcom acipolicygen` has few layers to hash.
FROM python:3.12-slim-bookworm

# Drop setuid/setgid bits (defence-in-depth; nothing in the image needs them).
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

WORKDIR /app
COPY server.py /app/server.py

# Unprivileged port so the non-root user below can bind it (ACI has no port remap).
EXPOSE 8080
# Run as an unprivileged user.
USER 1000:1000

CMD ["python", "/app/server.py"]
