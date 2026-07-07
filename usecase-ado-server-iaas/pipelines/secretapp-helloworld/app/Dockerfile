# Minimal hello-world container for the SecretApp ADO pipeline.
# Built server-side with `az acr build` (no local/agent Docker daemon required),
# so it runs fine on the dockerless confidential ACI build agents.
FROM nginx:1.27-alpine

# Static hello-world page.
COPY index.html /usr/share/nginx/html/index.html

# nginx:alpine already listens on port 80 and starts nginx in the foreground.
EXPOSE 80
