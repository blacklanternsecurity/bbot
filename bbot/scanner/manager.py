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
            self.scan.word_cloud.absorb_event(event)
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
                            sleep(1)
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

        except KeyboardInterrupt:
            self.scan.stop()

        finally:
            # clean up modules
            self.scan.status = "CLEANING_UP"
            for mod in self.scan.modules.values():
                mod._cleanup()
            finished = False
            while 1:
                finished = self.modules_status().get("finished", False)
                if finished:
                    break
                else:
                    sleep(0.1)

    def modules_status(self, _log=False, passes=None):

        # If scan looks to be finished, check an additional five times to ensure that it really is
        # There is a tiny chance of a race condition, which this helps to avoid
        if passes is None:
            passes = 5
        else:
            passes = max(1, int(passes))

        finished = True
        while passes > 0:

            status = {"modules": {}, "scan": self.scan.status_detailed}

            if self.event_queue.qsize() > 0:
                finished = False

            for num_tasks in status["scan"]["queued_tasks"].values():
                if num_tasks > 0:
                    finished = False

            for m in self.scan.modules.values():
                mod_status = m.status
                if mod_status["running"]:
                    finished = False
                status["modules"][m.name] = mod_status

            for mod in self.scan.modules.values():
                if mod.errored and mod.event_queue not in [None, False]:
                    with suppress(Exception):
                        mod.set_error_state()

            if finished:
                sleep(0.1)
            else:
                break
            passes -= 1

        status["finished"] = finished

        modules_running = [m for m, s in status["modules"].items() if s["running"]]
        modules_errored = [m for m, s in status["modules"].items() if s["errored"]]

        if _log:
            events_queued = [(m, s["events"]["queued"]) for m, s in status["modules"].items()]
            events_queued.sort(key=lambda x: x[-1], reverse=True)
            events_queued = [(m, q) for m, q in events_queued if q > 0][:5]
            events_queued_str = ""
            if events_queued:
                events_queued_str = " (" + ", ".join([f"{m}: {q:,}" for m, q in events_queued]) + ")"
            tasks_queued = [(m, s["tasks"]["total"]) for m, s in status["modules"].items()]
            tasks_queued.sort(key=lambda x: x[-1], reverse=True)
            tasks_queued = [(m, q) for m, q in tasks_queued if q > 0][:5]
            tasks_queued_str = ""
            if tasks_queued:
                tasks_queued_str = " (" + ", ".join([f"{m}: {q:,}" for m, q in tasks_queued]) + ")"

            num_events_queued = sum([m[-1] for m in events_queued])
            self.scan.verbose(f"Events queued: {num_events_queued:,}{events_queued_str}")

            num_tasks_queued = sum([m[-1] for m in tasks_queued])
            self.scan.verbose(f"Module tasks queued: {num_tasks_queued:,}{tasks_queued_str}")

            num_scan_tasks = status["scan"]["queued_tasks"]["total"]
            dns_tasks = status["scan"]["queued_tasks"]["dns"]
            event_tasks = status["scan"]["queued_tasks"]["event"]
            main_tasks = status["scan"]["queued_tasks"]["main"]
            internal_tasks = status["scan"]["queued_tasks"]["internal"]
            self.scan.verbose(
                f"Scan tasks queued: {num_scan_tasks:,} (Main: {main_tasks:,}, Event: {event_tasks:,}, DNS: {dns_tasks:,}, Internal: {internal_tasks:,})"
            )

            if modules_running:
                self.scan.verbose(
                    f'Modules running: {len(modules_running):,} ({", ".join([m for m in modules_running])})'
                )
            if modules_errored:
                self.scan.verbose(
                    f'Modules errored: {len(modules_errored):,} ({", ".join([m for m in modules_errored])})'
                )

        status.update({"modules_running": len(modules_running), "modules_errored": len(modules_errored)})

        return status
