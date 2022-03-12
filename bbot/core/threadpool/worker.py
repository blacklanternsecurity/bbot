import queue
import logging
import threading
from time import sleep

class ThreadPoolWorker(threading.Thread):

    def __init__(self, pool, name=None):

        self.log = logging.getLogger(f'bbot.core.threadpool.{name}')
        self.pool = pool
        self.task_name = ''  # which task submitted the callback
        self.busy = False
        self.stop = False

        super().__init__(name=name)

    def run(self):
        # Round-robin through each task's input queue
        while not self.stop:
            ran = False
            with self.pool._lock:
                input_queues = list(self.pool.input_queues.values())
            for q in input_queues:
                if self.stop:
                    break
                try:
                    self.busy = True
                    callback, args, kwargs = q.get_nowait()
                    self.task_name = kwargs.pop('task_name', 'default')
                    save_result = kwargs.pop('save_result', False)
                    try:
                        result = callback(*args, **kwargs)
                        ran = True
                    except Exception:
                        import traceback
                        self.log.error(f'Error in thread worker {self.name}:\n{traceback.format_exc()}')
                        break
                    if save_result:
                        self.pool.outputQueue(self.task_name).put(result)
                except queue.Empty:
                    self.busy = False
                finally:
                    self.busy = False
                    self.task_name = ''
            # sleep briefly to save CPU
            if not ran:
                sleep(.05)