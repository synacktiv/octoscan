FROM alpine:3.20

RUN apk add git curl jq gcompat

ENV SHELLCHEK_VERSION=v0.10.0

RUN set -x; \
  arch="$(uname -m)"; \
  echo "arch is $arch"; \
  if [ "${arch}" = 'armv7l' ]; then \
  arch='armv6hf'; \
  fi; \
  url_base='https://github.com/koalaman/shellcheck/releases/download/'; \
  tar_file="${SHELLCHEK_VERSION}/shellcheck-${SHELLCHEK_VERSION}.linux.${arch}.tar.xz"; \
  wget "${url_base}${tar_file}" -O - | tar xJf -; \
  mv "shellcheck-${SHELLCHEK_VERSION}/shellcheck" /bin/; \
  rm -rf "shellcheck-${SHELLCHEK_VERSION}"; \
  ls -laF /bin/shellcheck

# "latest" or a tag like v1.2.3, the docker workflow passes the tag of the release it is built for
ARG OCTOSCAN_VERSION=latest

RUN set -e ;\
    if [ "$OCTOSCAN_VERSION" = latest ]; then path=latest; else path="tags/$OCTOSCAN_VERSION"; fi ;\
    release=$(curl -sSf "https://api.github.com/repos/synacktiv/octoscan/releases/$path") ;\
    asset_url() { echo "$release" | jq -r --arg name "$1" '.assets[] | select(.name == $name) | .browser_download_url'; } ;\
    curl -sSfL "$(asset_url octoscan)" -o octoscan ;\
    sums_url=$(asset_url SHA256SUMS) ;\
    if [ -n "$sums_url" ]; then \
      curl -sSfL "$sums_url" | grep ' octoscan$' | sha256sum -c - ; \
    else \
      echo "WARNING: this release has no SHA256SUMS, the binary is not verified" >&2 ; \
    fi ;\
    chmod +x octoscan ;\
    mv octoscan /usr/local/bin/

ENTRYPOINT ["octoscan"]
