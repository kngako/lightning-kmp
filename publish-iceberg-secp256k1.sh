#!/usr/bin/env bash
# Install the Iceberg-fork secp256k1-kmp JNI artifacts into the local Maven repository under a
# DISTINCT version (0.23.0-iceberg) instead of shadowing upstream's 0.23.0.
#
# Why a distinct version: the eclair side of this benchmark shadows 0.23.0 with the fork, and a
# pristine ~/.m2 then fails LATE (at the first JNI call) instead of at dependency resolution time.
# With 0.23.0-iceberg, a machine that never built the fork fails immediately at resolution.
#
# What this does:
#   1. builds the fork at sources/secp256k1-kmp (unless the artifacts already exist in $SRC_M2)
#      and publishes it to a scratch repository ($SRC_M2) at its own version, 0.23.0;
#   2. copies the three artifacts that carry Iceberg code into ~/.m2 as 0.23.0-iceberg:
#        - secp256k1-kmp-jni-common    (Iceberg, NativeSecp256k1, Secp256k1CFunctions classes)
#        - secp256k1-kmp-jni-jvm-extract (the JVM native-lib loader)
#        - secp256k1-kmp-jni-jvm-linux (the linux native libraries, with the Iceberg C module)
#      rewriting the self- and cross-references between those three artifacts to 0.23.0-iceberg.
#      References to secp256k1-kmp-jvm (the root API artifact, unchanged by the fork) stay at
#      0.23.0 and resolve from Maven Central.
#
# Note: darwin/mingw native libraries are NOT forked here (they cannot be cross-built on this
# host); lightning-kmp keeps depending on upstream's 0.23.0 for those, which means Iceberg calls
# fail loudly with UnsatisfiedLinkError off linux. The port is a JVM/linux benchmark harness.
#
# Usage:  sources/lightning-kmp/publish-iceberg-secp256k1.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FORK_SRC="$REPO_ROOT/sources/secp256k1-kmp"
OLD=0.23.0
NEW=0.23.0-iceberg
SRC_M2="${SRC_M2:-/tmp/iceberg-m2}"
DST_M2="${DST_M2:-$HOME/.m2/repository}"
GROUP_PATH=fr/acinq/secp256k1
ARTIFACTS="secp256k1-kmp-jni-common secp256k1-kmp-jni-jvm-extract secp256k1-kmp-jni-jvm-linux"

# Step 1: build and publish the fork to the scratch repository (skipped if already there).
if [ ! -f "$SRC_M2/$GROUP_PATH/secp256k1-kmp-jni-common/$OLD/secp256k1-kmp-jni-common-$OLD.jar" ]; then
  echo "== building the secp256k1-kmp fork (this compiles the Iceberg C module)"
  cd "$FORK_SRC"
  # local.properties only disables the android build; it is removed again below.
  trap 'rm -f "$FORK_SRC/local.properties"' EXIT
  echo "skip.android=true" > local.properties
  ./gradlew --no-daemon -Dmaven.repo.local="$SRC_M2" \
    :jni:publishToMavenLocal :jni:jvm:publishToMavenLocal :jni:jvm:linux:publishToMavenLocal \
    -x :native:buildSecp256k1Ios
  rm -f local.properties
  trap - EXIT
fi

# Step 2: copy-rename into the real local Maven repository.
for artifact in $ARTIFACTS; do
  src="$SRC_M2/$GROUP_PATH/$artifact/$OLD"
  dst="$DST_M2/$GROUP_PATH/$artifact/$NEW"
  [ -f "$src/$artifact-$OLD.jar" ] || { echo "MISSING: $src/$artifact-$OLD.jar" >&2; exit 1; }
  mkdir -p "$dst"
  for f in "$src/$artifact-$OLD.jar" "$src/$artifact-$OLD.pom"; do
    target="$dst/$(basename "$f" | sed "s/$OLD/$NEW/")"
    cp "$f" "$target"
  done
  # Rewrite self version and inter-artifact references (but NOT secp256k1-kmp-jvm or kotlin-stdlib).
  perl -0777 -pi -e "s/(<artifactId>secp256k1-kmp-jni-(?:common|jvm-extract|jvm-linux)<\/artifactId>\s*<version>)\Q$OLD\E(<\/version>)/\${1}$NEW\$2/g; s/^(  <version>)\Q$OLD\E(<\/version>)$/\${1}$NEW\$2/gm" \
    "$dst/$artifact-$NEW.pom"
done

# Sanity check: the jni-common jar must actually contain the Iceberg class.
python3 - "$DST_M2/$GROUP_PATH/secp256k1-kmp-jni-common/$NEW/secp256k1-kmp-jni-common-$NEW.jar" <<'EOF'
import sys, zipfile
names = zipfile.ZipFile(sys.argv[1]).namelist()
assert any('Iceberg' in n for n in names), "the fork jar has no Iceberg class -- wrong source?"
print("ok: Iceberg class present in", sys.argv[1])
EOF

echo "== installed as $NEW under $DST_M2/$GROUP_PATH"
echo "   lightning-kmp resolves these via mavenLocal(); see gradle/libs.versions.toml (secpjnijvm)"
