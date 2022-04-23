import queue
import logging
from time import sleep
from contextlib import suppress

log = logging.getLogger("bbot.scanner.manager")


class ScanManager:
    """
    Manages modules and events during a scan
    """

    def __init__(self, scan):
        self.scan = scan
        self.event_queue = queue.SimpleQueue()
        # tracks processed events
        self.events_processed = set()
        self.word_cloud = dict()

    def init_events(self):
        """
        seed scanner with target events
        """
        self.queue_event(self.scan.root_event)
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
        self.event_queue.put(event)

    def distribute_event(self, event):
        """
        Queue event with modules
        """
        dup = False
        event_hash = hash(event)
        if event_hash in self.events_processed:
            self.scan.verbose(f"Duplicate event: {event}")
            dup = True
        else:
            self.absorb_words(event)
            self.events_processed.add(event_hash)
        for mod in self.scan.modules.values():
            if not dup or mod.accept_dupes:
                mod.queue_event(event)

    def loop_until_finished(self):

        counter = 0
        event_counter = 0

        try:
            self.scan.dispatcher.on_start(self.scan)

            # watch for newly-generated events
            while 1:

                if self.scan.status == "ABORTING":
                    while 1:
                        try:
                            # Empty event queue
                            self.event_queue.get_nowait()
                        except queue.Empty:
                            break
                    break

                event = False
                # print status every 2 seconds
                log_status = counter % 20 == 0

                try:
                    event = self.event_queue.get_nowait()
                    event_counter += 1
                except queue.Empty:
                    finished = self.modules_status(_log=log_status).get("finished", False)
                    # If the scan finished
                    if finished:
                        # If new events were generated in the last iteration
                        if event_counter > 0:
                            self.scan.status = "FINISHING"
                            # Trigger .finished() on every module and start over
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
                    continue

                # distribute event to modules
                self.distribute_event(event)

        finally:
            # clean up modules
            self.scan.status = "CLEANING_UP"
            for mod in self.scan.modules.values():
                mod._cleanup()

    def absorb_words(self, event):
        for word in event.words:
            try:
                self.word_cloud[word] += 1
            except KeyError:
                self.word_cloud[word] = 1

    def modules_status(self, _log=False, passes=None):

        finished = False
        # If scan looks to be finished, check an additional five times to ensure that it really is
        # There is a tiny chance of a race condition, which this helps to avoid
        if passes is None:
            passes = 5
        else:
            passes = int(passes)

        while passes > 0:

            queued_events = dict()
            running_tasks = dict()
            modules_running = []
            modules_errored = []

            shared_pool_tasks = self.scan.helpers.num_running_tasks + self.scan.helpers.num_queued_tasks

            for m in self.scan.modules.values():
                try:
                    if m.event_queue:
                        queued_events[m.name] = m.num_queued_events
                    running_tasks[m.name] = m.num_running_tasks
                    if m.running:
                        modules_running.append(m)
                    if m.errored:
                        modules_errored.append(m)
                except Exception as e:
                    with suppress(Exception):
                        m.set_error_state(f'Error encountered while polling module "{m.name}": {e}')

            queued_events = sorted(queued_events.items(), key=lambda x: x[-1], reverse=True)
            running_tasks = sorted(running_tasks.items(), key=lambda x: x[-1], reverse=True)
            queues_empty = [qsize == 0 for m, qsize in queued_events]

            for mod in self.scan.modules.values():
                if mod.errored and mod.event_queue not in [None, False]:
                    with suppress(Exception):
                        mod.set_error_state()

            finished = not self.event_queue or (not modules_running and shared_pool_tasks == 0 and all(queues_empty))
            if finished:
                sleep(0.1)
            else:
                break
            passes -= 1

        if _log:
            events_queued = ", ".join([f"{mod}: {qsize:,}" for mod, qsize in queued_events[:5] if qsize > 0])
            if not events_queued:
                events_queued = "None"
            tasks_queued = ", ".join([f"{mod}: {qsize:,}" for mod, qsize in running_tasks[:5] if qsize > 0])
            if not tasks_queued:
                tasks_queued = "None"
            self.scan.verbose(f"Events queued: {sum([m[-1] for m in queued_events]):,} ({events_queued})")
            self.scan.verbose(f"Tasks queued: {sum([m[-1] for m in running_tasks]):,} ({tasks_queued})")
            if modules_running:
                self.scan.verbose(
                    f'Modules running: {len(modules_running):,} ({", ".join([m.name for m in modules_running])})'
                )
            if modules_errored:
                self.scan.verbose(
                    f'Modules errored: {len(modules_errored):,} ({", ".join([m.name for m in modules_errored])})'
                )

        return {
            "modules_running": modules_running,
            "queued_events": queued_events,
            "running_tasks": running_tasks,
            "errored": modules_errored,
            "finished": finished,
        }
