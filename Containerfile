ARG BASE_IMAGE=docker.io/library/python@sha256:ac25e5afbfdb4a94ff99cc24b0345719210133144481480bcba6085efa36a341
FROM ${BASE_IMAGE}
WORKDIR /app
COPY build.py taskpool.py README.md LICENSE .gitignore ./
COPY pool/*.py ./pool/
COPY pool/taskpool.css pool/workbench.css pool/workbench.js ./pool/
COPY docs/内网任务服务升级操作.md docs/本轮优化操作.md ./docs/
COPY docs/AI客户端操作.md ./docs/
COPY docs/运维与升级.md ./docs/
COPY docs/执行环境与资源映射.md docs/统一任务流程.md docs/常开部署清单.md ./docs/
COPY ops/*.py ops/*.ps1 ops/*.sh ./ops/
COPY ops/*.service ops/*.timer ./ops/
COPY vendor/SHA256SUMS ./vendor/
COPY vendor/ledger/*.py ./vendor/ledger/
RUN python -B build.py && chmod 0644 dist/*.zip && mkdir .state && chown 10001:10001 .state
USER 10001:10001
EXPOSE 18443
STOPSIGNAL SIGINT
ENTRYPOINT ["python", "-B", "-X", "utf8", "/app/taskpool.py"]
