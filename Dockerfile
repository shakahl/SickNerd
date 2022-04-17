# dockerfile for sicknerd

# build stage
FROM python:slim AS build
ENV PATH="/opt/venv/bin":$PATH
WORKDIR /opt
RUN apt-get update; apt-get install -y git python3 pip curl; rm -rf /var/lib/apt/lists/*; python3 -m pip install virtualenv; \
    virtualenv -p python venv; PATH="/opt/venv/bin:$PATH";\
    git clone https://github.com/JakeWnuk/SickNerd; pip3 install -r /opt/SickNerd/requirements.txt; \
    mv /opt/SickNerd/sicknerd.py /opt/venv/bin/sicknerd.py; chmod +x /opt/venv/bin/sicknerd.py

# final stage
FROM python:slim
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"


ENTRYPOINT ["/opt/venv/bin/sicknerd.py"]