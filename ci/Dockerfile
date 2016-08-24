FROM golang:1.7

ENV GLIDE_VERSION v0.12.0
ENV GLIDE_DOWNLOAD_URL https://github.com/Masterminds/glide/releases/download/$GLIDE_VERSION/glide-$GLIDE_VERSION-linux-amd64.tar.gz
ENV GLIDE_DOWNLOAD_SHA256 f155e498e00cfff30a91b198065ba671699a0cd534c90f3975d390247ae568d9

ENV PATH $PATH:/usr/local/glide/linux-amd64

RUN curl -fsSL "$GLIDE_DOWNLOAD_URL" -o glide.tar.gz \
	&& echo "$GLIDE_DOWNLOAD_SHA256  glide.tar.gz" | sha256sum -c - \
	&& mkdir -p /usr/local/glide \
	&& tar -C /usr/local/glide -xzf glide.tar.gz \
	&& rm glide.tar.gz
