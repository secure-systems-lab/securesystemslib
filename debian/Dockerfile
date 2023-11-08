# Build secureystemslib for Debian on any host
#
# Release workflow (with example commands)
# ----------------
#
# 1. Checkout "debian" branch and rebase on upstream release tag
#
#        git switch debian && git rebase v0.28.0
#
# 2. Update debian/* files, most notably add new entry to debian/changelog
#
# 3. Build (requires upstream VERSION as argument)
#
#    - Installs dev tools and build dependencies
#    - Configures gpg + dput to upload to mentors
#    - Fetches source dist from GitHub
#    - Builds Debian package
#
#        docker build --build-arg VERSION=0.28.0 -t deb-build .
#
#    HINT: If the build fails, update debian/* files on host and rebuild.
#    This might include downstream patching with `quilt`, which is also
#    available outside of Debian (e.g. via brew on macOS).
#
# 4. Run to sign and upload (requires signing key as argument)
#
#        docker run --rm -it --name deb-build --entrypoint bash \
#             --env GPG_KEY="$(gpg --armor --export-secret-key lukas.puehringer@nyu.edu)" \
#              deb-build
#
# 5. (on container) Import signing key, sign and upload to mentors
#
#        echo "$GPG_KEY" | gpg --import
#        (cd securesystemslib-0.28.0 && debsign -k lukas.puehringer@nyu.edu)
#        dput mentors python-securesystemslib_0.28.0-1_arm64.changes
#
# 6. (optional) Copy package to host, if needed later as build dependency
#
#        docker cp deb-build:/home/build/python3-securesystemslib_0.28.0-1_all.deb .
#
# 7. Commit changed Debian files, push/pr into "debian" branch
#
FROM debian:sid

# Copy debian files
COPY . /tmp/debian

# Install developer tools and build dependencies
RUN apt-get update \
  && apt-get install --no-install-recommends -yV \
    build-essential \
    devscripts \
    debhelper \
    equivs \
    wget \
    lintian \
    dput

RUN mk-build-deps \
    --install \
    --remove \
    --tool 'apt-get --no-install-recommends -yV' /tmp/debian/control

# Create user (some build tests related to permission fail as root)
RUN useradd build --create-home
USER build
WORKDIR /home/build

# Configure GPG
COPY --chown=build:build <<-"EOT" .gnupg/gpg.conf
use-agent
pinentry-mode loopback
EOT

COPY --chown=build:build <<-"EOT" .gnupg/gpg-agent.conf
allow-loopback-pinentry
EOT


# Configure DPUT
COPY --chown=build:build <<-"EOT" .dput.cf
[mentors]
fqdn = mentors.debian.net
incoming = /upload
method = https
allow_unsigned_uploads = 0
progress_indicator = 2
# Allow uploads for UNRELEASED packages
allowed_distributions = .*
EOT

# Grab source dist and sig for VERSION from GitHub and prepare for building
ARG VERSION
RUN wget https://github.com/secure-systems-lab/securesystemslib/releases/download/v${VERSION}/securesystemslib-${VERSION}.tar.gz \
          -O python-securesystemslib_${VERSION}.orig.tar.gz
RUN wget https://github.com/secure-systems-lab/securesystemslib/releases/download/v${VERSION}/securesystemslib-${VERSION}.tar.gz.asc \
          -O python-securesystemslib_${VERSION}.orig.tar.gz.asc
RUN tar xf python-securesystemslib_${VERSION}.orig.tar.gz
RUN cp -r /tmp/debian securesystemslib-${VERSION}

# Build
RUN cd securesystemslib-${VERSION} && debuild \
  --unsigned-source \
  --unsigned-changes \
  --lintian-opts --display-level ">=pedantic" --display-experimental --tag-display-limit 0

