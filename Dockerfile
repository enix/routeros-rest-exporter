# Push to docker-registry.enix.io/docker/routeros-rest-exporter

FROM python:3

RUN mkdir /routeros-rest-exporter
WORKDIR /routeros-rest-exporter

COPY ./requirements.txt ./
RUN pip install -r requirements.txt

COPY ./* ./

EXPOSE 9100/tcp

ENTRYPOINT ["python", "/routeros-rest-exporter/routeros-rest-exporter.py", "-e", "/routeros-rest-exporter/api_endpoints.yaml"]
CMD ["-c", "/routeros-rest-exporter/config.yaml"]