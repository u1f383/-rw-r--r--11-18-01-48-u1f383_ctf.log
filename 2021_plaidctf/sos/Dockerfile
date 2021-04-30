FROM ocaml/opam2:4.10
# opam is a source-based package manager for OCaml
# Ocaml is a language named Objective Caml
USER root

# Tini is the simplest init you could think of
# https://zhuanlan.zhihu.com/p/59796137
COPY ./tini /tini
RUN chmod +x /tini

# opam: Opam is a package manager
# opam-config: Display configuration options for packages
# opam-config exec -- COMMAND: Execute COMMAND with the correct environment variables 
ENTRYPOINT ["/tini", "--", "opam", "config", "exec", "--"]

USER opam

# Dune is a build system designed for OCaml/Reason projects only
RUN opam update && opam install -y dune

WORKDIR /home/opam/sos

USER root

COPY --chown=opam:opam ./src/ ./
COPY --chown=opam:opam ./flag /flag

RUN chown opam:opam /home/opam/sos
RUN rm /etc/sudoers.d/opam && chmod 0755 ./main && chmod 0644 /flag

USER opam

CMD [ "./main" ]
