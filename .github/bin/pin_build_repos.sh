#!/usr/bin/env bash
# Freeze EL9/EL10 to the Rocky vault GA snapshot for the base image's minor, so the
# dynamically linked OpenSSL floor stays at the oldest the major shipped (3.2.2 ->
# OPENSSL_3.2.0). The default UBI repos float to 3.5 (9.7/10.1), whose OPENSSL_3.4.0
# symbols (e.g. EVP_MD_CTX_get_size_ex via the AWS SDK) the older RHEL 9.x/10.0
# libcrypto can't satisfy. Run as a subprocess (not sourced); no-op on other distros.
set -euo pipefail

distro="${1:-${ENV_DISTRO:-}}"
case "$distro" in
  el9)  rel=9.6  ;;   # match the ubi9:9.6 base GA (openssl-libs 3.2.2, no downgrade)
  el10) rel=10.0 ;;   # match the ubi10:10.0 base GA (openssl-libs 3.2.2, no downgrade)
  *)    echo "pin_build_repos: nothing to pin for '${distro:-<unset>}'"; exit 0 ;;
esac

arch="$(uname -m)"
base="https://dl.rockylinux.org/vault/rocky/${rel}"

# Replace the floating UBI repos with the frozen vault snapshot. Keep signature
# verification on: UBI images don't ship Rocky's keyring, so point dnf at the Rocky
# release key over HTTPS and let it import on first use. gpgcheck=1 guards against a
# poisoned mirror/CDN swapping the libcrypto/libssl these binaries link against; HTTPS
# only authenticates the transport to dl.rockylinux.org, not the package contents.
rm -f /etc/yum.repos.d/*.repo
: > /etc/yum.repos.d/rocky-vault.repo
for repo in BaseOS AppStream CRB devel; do
  name="$(printf '%s' "$repo" | tr '[:upper:]' '[:lower:]')"
  {
    printf '[%s]\n' "$name"
    printf 'name=Rocky Linux %s - %s (vault)\n' "$rel" "$repo"
    printf 'baseurl=%s/%s/%s/os/\n' "$base" "$repo" "$arch"
    printf 'gpgcheck=1\n'
    printf 'gpgkey=https://dl.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-%s\n' "${rel%%.*}"
    printf 'enabled=1\n\n'
  } >> /etc/yum.repos.d/rocky-vault.repo
done

# Pull OpenSSL back down to the snapshot in case an earlier "Install prereqs" step
# floated it forward against the still-default UBI repos. This is the only thing that
# re-establishes the GA floor in the test job, so let it fail loudly (no `2>/dev/null
# || true`): a silently swallowed sync would leave a refloated OpenSSL in place and
# turn the regression backstop green against the wrong libcrypto. The post-sync rpm -q
# records the resolved version so the floor is visible in the job log.
dnf -y distro-sync openssl openssl-libs
rpm -q --qf 'pin_build_repos: synced %{NAME} to %{VERSION}-%{RELEASE}\n' openssl-libs

echo "pin_build_repos: ${distro} pinned to Rocky vault ${rel} (${arch})"
