#!/usr/bin/env bash
# Build wrapper: sets the portable toolchain env and keeps Android user state inside the project.
#   android/build.sh assembleDebug testDebugUnitTest
set -euo pipefail
cd "$(dirname "$0")"
[ -f ../env.sh ] && source ../env.sh   # dev-laptop toolchain paths (optional)
export ANDROID_USER_HOME="$PWD/.android-user"
mkdir -p "$ANDROID_USER_HOME"
echo "sdk.dir=$ANDROID_HOME" > local.properties
if [ ! -f debug.keystore ]; then
  keytool -genkeypair -keystore debug.keystore -storepass android -alias androiddebugkey \
    -keypass android -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US" >/dev/null 2>&1
fi
exec ./gradlew --console=plain "$@"
