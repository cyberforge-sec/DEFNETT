FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/defnett
COPY app.py agent.py collector.py remediator.py /opt/defnett/
COPY dashboard/ /opt/defnett/dashboard/

RUN groupadd --gid 10001 defnett \
    && useradd --uid 10001 --gid defnett --create-home --no-log-init defnett \
    && chmod 0644 /opt/defnett/*.py /opt/defnett/dashboard/* \
    && mkdir -p /data /state /evidence /target /quarantine /master \
    && chown -R 10001:10001 /data /state /evidence /target /quarantine /master

USER 10001:10001
EXPOSE 8080 8090
ENTRYPOINT ["python"]
