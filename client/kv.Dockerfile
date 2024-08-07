ARG debian_snapshot=sha256:f0b8edb2e4436c556493dce86b941231eead97baebb484d0d5f6ecfe4f7ed193
FROM debian@${debian_snapshot}

COPY prebuilt/kv-server /usr/bin/

RUN mkdir /realtime
RUN mkdir /deltas

CMD ["/usr/bin/kv-server", "--realtime_directory=/realtime", "--delta_directory=/deltas", "--port=50051"]
