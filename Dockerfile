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

RUN set -e ;\
    OCTOSCAN_ASSET_URL=$(curl -sS https://api.github.com/repos/synacktiv/octoscan/releases/latest | jq -r '.assets[] | select(.name == "octoscan") | .browser_download_url') ;\
    echo $OCTOSCAN_ASSET_URL ;\
    curl -sSL "$OCTOSCAN_ASSET_URL" -o ./octoscan ;\
    chmod +x ./octoscan ;\
    mv ./octoscan /usr/local/bin/ ;

ENTRYPOINT ["octoscan"]
