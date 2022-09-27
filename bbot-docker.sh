# run the docker image
docker run --rm -it -v "$HOME/.bbot:/root/.bbot" -v "$HOME/.config/bbot:/root/.config/bbot" blacklanternsecurity/bbot:stable "$@"
