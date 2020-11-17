# Take common name (amd64, arm64, arm) and map to the unames (x86_64, aarch64)

COMMON_NAME="${1}"

if [ "amd64" == "${COMMON_NAME}" ]; then
    echo "x86_64"
elif [ "arm64" == "${COMMON_NAME}" ]; then
    echo "aarch64"
elif [ "arm32" == "${COMMON_NAME}" ]; then
    echo "armv7l"
elif [ "arm" == "${COMMON_NAME}" ]; then
    echo "armv7l"
else
    echo "Unsupported cpu arch ${COMMON_NAME}"
    exit 1
fi
