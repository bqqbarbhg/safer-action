set -e

URL="$1"
TOKEN="$2"
NAME="$3"
PROXY_URL="$4"

cd /home/runner

export http_proxy=${PROXY_URL}
export https_proxy=${PROXY_URL}

echo "== Configuring =="
./config.sh --ephemeral --unattended --url ${URL} --token ${TOKEN} --work work --name ${NAME}

echo "== Running =="
cp -f ./run-helper.sh.template ./run-helper.sh
./run-helper.sh
