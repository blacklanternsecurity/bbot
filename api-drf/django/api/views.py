import logging

log = logging.getLogger(__name__)


def agent_send(request, agent_id):
    log.debug(agent_id)
