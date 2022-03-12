import json
import subprocess

from .base import BaseModule

class httpx(BaseModule):

    watched_events = ['OPEN_TCP_PORT']
    produced_events = ['URL']
    max_threads = 2
    batch_size = 10

    def handle_batch(self, *events):

        stdin = '\n'.join([str(e.data) for e in events])
        command = ['httpx', '-silent', '-json']
        self.debug(' '.join(command))
        proc = subprocess.run(command, input=stdin, text=True, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE)
        for line in proc.stdout.splitlines():
            j = json.loads(line)
            url = j.get('url')
            title = j.get('title', '')

            source_event = None
            for event in events:
                if url in event:
                    source_event = event
                    break

            self.emit_event(url, 'URL', source_event)
            if title:
                self.emit_event(title, 'HTTP_TITLE', source_event)