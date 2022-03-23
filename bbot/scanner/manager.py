import json
import queue
import logging
from time import sleep

log = logging.getLogger("bbot.scanner.manager")


class EventManager:
    def __init__(self, scan):
        self.scan = scan
        self.event_queue = queue.Queue()
        self.event_hashes = set()
        self.word_cloud = dict()

    def init_events(self):
        """
        seed scanner with target events
        """
        for event in self.scan.target.events:
            self.scan.info(f"Target: {event}")
            self.queue_event(event)
        # force submit batches
        for mod in self.scan.modules.values():
            mod._handle_batch(force=True)

    def queue_event(self, event):
        """
        Queue event with manager
        """
        if hash(event) in self.event_hashes:
            self.scan.verbose(f"Duplicate event: {event}")
        else:
            self.absorb_words(event)
            self.event_hashes.add(hash(event))
            self.event_queue.put(event)
        log.stdout(json.dumps(dict(event)))

    def distribute_event(self, event):
        """
        Queue event with modules
        """
        for mod in self.scan.modules.values():
            if event.type in mod.watched_events:
                mod.queue_event(event)

    def loop_until_finished(self):

        counter = 0
        event_counter = 0

        try:
            # watch for newly-generated events
            while 1:

                event = False
                # print status every 2 seconds
                log_status = counter % 20 == 0

                try:
                    event = self.event_queue.get_nowait()
                    event_counter += 1
                except queue.Empty:
                    finished = self.modules_status(_log=log_status).get(
                        "finished", False
                    )
                    # If the scan finished
                    if finished:
                        # If new events were generated in the last iteration
                        if event_counter > 0:
                            # Trigger .finished() on every module and start over
                            self._status = "FINISHING"
                            for mod in self.scan.modules.values():
                                mod.queue_event("FINISHED")
                            event_counter = 0
                        else:
                            # Otherwise stop the scan if no new events were generated in this iteration
                            break
                    else:
                        # save on CPU
                        sleep(0.1)
                    counter += 1

                # distribute event to modules
                for mod in self.scan.modules.values():
                    mod.queue_event(event)

        finally:
            # tell the modules to stop
            for mod in self.scan.modules.values():
                mod._stop = True

    def absorb_words(self, event):
        for word in event.words:
            try:
                self.word_cloud[word] += 1
            except KeyError:
                self.word_cloud[word] = 1

    def modules_status(self, _log=False):

        finished = False
        # If status is determined to be finished, check an additional five times to ensure that it really is
        # There is a very small chance of a race condition, which this helps to avoid
        passes = 5

        while passes > 0:

            queued_events = dict()
            queued_tasks = dict()
            modules_running = []
            modules_errored = []

            for m in self.scan.modules.values():
                try:
                    if m.event_queue:
                        queued_events[m.name] = m.num_queued_events
                    queued_tasks[m.name] = m.num_queued_tasks
                    if m.running:
                        modules_running.append(m.name)
                    if m.errored:
                        modules_errored.append(m.name)
                except Exception as e:
                    log.error(f'Error encountered while polling module "{m.name}": {e}')
                    with suppress(Exception):
                        m.set_error_state()

            queued_events = sorted(
                queued_events.items(), key=lambda x: x[-1], reverse=True
            )
            queued_tasks = sorted(
                queued_tasks.items(), key=lambda x: x[-1], reverse=True
            )
            queues_empty = [qsize == 0 for m, qsize in queued_events]

            for mod in self.scan.modules.values():
                if mod.errored and mod.event_queue not in [None, False]:
                    with suppress(Exception):
                        mod.set_error_state()

            finished = not self.event_queue or (
                not modules_running and all(queues_empty)
            )
            if finished:
                sleep(0.1)
            else:
                break
            passes -= 1

        if _log:
            events_queued = ", ".join(
                [f"{mod}: {qsize:,}" for mod, qsize in queued_events[:5] if qsize > 0]
            )
            if not events_queued:
                events_queued = "None"
            tasks_queued = ", ".join(
                [f"{mod}: {qsize:,}" for mod, qsize in queued_tasks[:5] if qsize > 0]
            )
            if not tasks_queued:
                tasks_queued = "None"
            self.scan.verbose(
                f"Events queued: {sum([m[-1] for m in queued_events]):,} ({events_queued})"
            )
            self.scan.verbose(
                f"Tasks queued: {sum([m[-1] for m in queued_tasks]):,} ({tasks_queued})"
            )
            if modules_running:
                self.scan.verbose(
                    f'Modules running: {len(modules_running):,} ({", ".join(modules_running)})'
                )
            if modules_errored:
                self.scan.verbose(
                    f'Modules errored: {len(modules_errored):,} ({", ".join(modules_errored)})'
                )

        return {
            "running": modules_running,
            "queued_events": queued_events,
            "queued_tasks": queued_tasks,
            "errored": modules_errored,
            "finished": finished,
        }
