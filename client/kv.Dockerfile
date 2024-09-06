ARG debian_snapshot=sha256:f0b8edb2e4436c556493dce86b941231eead97baebb484d0d5f6ecfe4f7ed193
FROM debian@${debian_snapshot}

COPY prebuilt/kv-server /usr/bin/

RUN mkdir /tmp/realtime
RUN mkdir /tmp/deltas

CMD ["/usr/bin/kv-server", "--port=8080", "--parc_server_address=10.0.2.100", "--parc_server_port=8889"]
