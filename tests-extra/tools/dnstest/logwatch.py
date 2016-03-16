import os
import threading

class LogWatchException(Exception):
    pass

class LogWatch:
    """
    Watching textual log files for events.

    ```
    watch = LogWatch(sys.stdout)
    proc = subprocess.Popen(["binary"], stdout=watch.fd)
    close(watch.fd)
    watch.start()

    event = watch.register("hello")
    if lw.wait(event):
        print("event happened")

    proc.wait()
    watch.stop()
    ```
    """

    def __init__(self, fd_pass=None):
        # pipe for capturing messages
        r, w = os.pipe()
        self._fd_read = r
        self._fd_write = w

        # message pass-through sink
        self._fd_pass = fd_pass

        # events watching
        self._watch = dict()
        self._running = False
        self._thread = None
        self._sync = threading.Condition()

    @property
    def fd(self):
        """Get writable descriptor to pass messages into."""
        return self._fd_write

    def _message_matches(self, line, message):
        if isinstance(message, str):
            return message in line
        if hasattr(message, 'search'):
            return message.search(line) is not None
        return False

    def _check_watches(self, line):
        with self._sync:
            has_match = False
            for message in self._watch:
                if self._message_matches(line, message):
                    self._watch[message] += 1
                    has_match = True
            if has_match:
                self._sync.notify_all()

    def _pass_through(self, line):
        if self._fd_pass:
            print(line, file=self._fd_pass)

    def _process_start(self):
        with self._sync:
            self._running = True

    def _process_end(self):
        with self._sync:
            self._running = False
            self._sync.notify_all()

    def _process(self):
        self._process_start()
        with os.fdopen(self._fd_read) as f:
            for line in (l.rstrip('\n') for l in f):
                self._check_watches(line)
                self._pass_through(line)
        self._process_end()

    def register(self, message):
        """Register new message to watch for.

        The message can be a string for a substring match. Or a compiled RE.

        Use the returned value as the 'event' parameter for 'wait' method.
        """
        with self._sync:
            self._watch.setdefault(message, 0)
            return (message, self._watch[message])

    def _check_wait(self, event):
        message, counter = event
        if self._watch[message] > counter:
            return True
        elif not self._running:
            raise LogWatchException("Descriptor closed while waiting for the event.")
        else:
            return False

    def _check_waits(self, events):
        for event in events:
            message, counter = event
            if self._watch[message] > counter:
                return message

        if not self._running:
            raise LogWatchException("Descriptor closed while waiting for the event.")
        else:
            return False

    def wait_list(self, events_list, timeout):
        import time
        t = time.time()

        with self._sync:
            hit = lambda: self._check_waits(events_list)
            ret = self._sync.wait_for(hit, timeout)
        
        new_event_lists = list([(k, self._watch[k]) for k in self._watch
                                if k in dict(events_list).keys()])
        return ret, new_event_lists

    def wait(self, event, timeout):
        """Wait for a watched event. Return if the event happened."""
        with self._sync:
            hit = lambda: self._check_wait(event)
            return self._sync.wait_for(hit, timeout)

    def start(self):
        """Start background event watching thread."""
        self._thread = threading.Thread(target=self._process)
        self._thread.start()

    def stop(self):
        """Wait till the background watching thread terminates."""
        self._thread.join()
