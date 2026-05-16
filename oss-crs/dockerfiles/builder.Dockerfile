ARG target_base_image
FROM ${target_base_image}

COPY --from=libcrs . /libCRS
RUN /libCRS/install.sh

# CodeQL CLI for database creation during build
ENV CODEQL_VERSION=2.20.4
ENV CODEQL_HOME=/opt/codeql
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends wget unzip ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    cd /tmp; \
    wget -q "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip"; \
    unzip -q codeql-linux64.zip; \
    mv codeql "${CODEQL_HOME}"; \
    rm codeql-linux64.zip; \
    ln -s "${CODEQL_HOME}/codeql" /usr/local/bin/codeql; \
    codeql pack download codeql/java-queries:codeql-java

RUN mkdir -p /out/crs
COPY ./build.py /crs/build.py

CMD ["python3", "/crs/build.py"]
