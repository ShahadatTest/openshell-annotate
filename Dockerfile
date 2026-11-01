# syntax=docker/dockerfile:1.7
# Local build (not published):  scripts/docker-build.sh
#
# Cargo.toml pins `openshell-policy-schema` to a git checkout of OpenShell at /path/to/OpenShell
# (file:// URL, tag v0.1.6). The build therefore needs that checkout as the named build context `openshell`.
FROM rust:1.94-bookworm AS build
ARG OPENSHELL_PATH=/path/to/OpenShell
WORKDIR /build
# Tree-sitter grammars are C sources compiled by cargo's build scripts (gcc is in the rust image).
COPY --from=openshell / ${OPENSHELL_PATH}
RUN git config --global --add safe.directory '*'
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked && \
    strip target/release/openshell-annotate && \
    cp target/release/openshell-annotate /openshell-annotate

# distroless/cc: glibc + libgcc only (no shell, no package manager). Runs as root by default so the
# tool can write into a bind-mounted /src; use `docker run -u $(id -u):$(id -g)` to keep file ownership.
FROM gcr.io/distroless/cc-debian12
COPY --from=build /openshell-annotate /usr/local/bin/openshell-annotate
LABEL org.opencontainers.image.title="openshell-annotate" \
      org.opencontainers.image.description="Policy-as-code for OpenShell: @openshell source directives -> policy.yaml" \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/openshell-annotate"]
CMD ["--help"]
