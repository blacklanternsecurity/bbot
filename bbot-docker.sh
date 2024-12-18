# OUTPUTS SCAN DATA TO ~/.bbot/scans

docker run --rm -it -v "$HOME/.bbot/scans:/root/.bbot/scans" -v "$HOME/.config/bbot:/root/.config/bbot" blacklanternsecurity/bbot:stable "$@"
