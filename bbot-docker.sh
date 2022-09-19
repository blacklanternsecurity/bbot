# build docker image if it doesn't exist already
[[ ! -z `docker images -q bbot` ]] || docker build "$( dirname -- "${BASH_SOURCE[0]}"; )" -t bbot
# run the docker image
docker run --rm -it -v "$HOME/.bbot:/root/.bbot" -v "$HOME/.config/bbot:/root/.config/bbot" bbot "$@"