FROM python:3.13-alpine
WORKDIR /app
COPY konsola.py logo.png logo-desk.webp ./
RUN mkdir /data && chown nobody /data
USER nobody
VOLUME /data
EXPOSE 21114
CMD ["python", "konsola.py", "21114", "/data/konsola.db"]
LABEL org.opencontainers.image.title="AdminDesk Konsola" \
      org.opencontainers.image.vendor="A.D.M.I.N (4dmin.pl)" \
      org.opencontainers.image.source="https://github.com/4dmin-pl/admindesk-serwer"
