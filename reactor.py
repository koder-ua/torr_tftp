import time
import heapq
import select
import logging


reactor_logger = logging.getLogger('reactor')


class CB(object):
    def __init__(self, func, evt, fileobj, timeout_at):
        self.func = func
        self.evt = evt
        self.fileobj = fileobj
        self.timeout_at = timeout_at
        self.fd = fileobj.fileno() if fileobj is not None else None


class Reactor(object):
    def_recv_size = 1400

    def __init__(self):
        self.selector = select.epoll()
        self.fd2cb = {}
        self.callbacks_heap = []

    def close(self):
        # TODO(koder): call all callbacks with 'close' exception
        self.selector.close()

    def register(self, fileobj, evt, cb_func, timeout):
        if timeout != -1 and timeout is not None:
            timeout_at = timeout + time.time()
        else:
            timeout_at = None

        cb = self.fd2cb.get(fileobj.fileno())

        if not cb:
            self.selector.register(fileobj, evt)
            cb = CB(cb_func, evt, fileobj, timeout_at)
            self.fd2cb[fileobj.fileno()] = cb
        else:
            assert cb.fileobj is fileobj
            assert cb.evt == evt
            cb.func = cb_func
            cb.timeout_at = timeout_at

        if timeout_at is not None:
            heapq.heappush(self.callbacks_heap, (timeout_at, cb))

    def unregister(self, fileobj):
        self.selector.unregister(fileobj)
        cb = self.fd2cb[fileobj.fileno()]
        del self.fd2cb[fileobj.fileno()]
        assert cb.timeout_at is not None
        cb.evt = cb.func = cb.fd = cb.fileobj = None
        cb.timeout_at = 0

    def call_later(self, tout, func):
        call_at = tout + time.time()
        cb = CB(func, None, None, call_at)
        heapq.heappush(self.callbacks_heap, (call_at, cb))

    def serve_forever(self):
        while True:
            ctime = time.time()
            while len(self.callbacks_heap) > 0 and ctime >= self.callbacks_heap[0][0]:
                _, cb = heapq.heappop(self.callbacks_heap)
                if cb.func is None:
                    continue
                if cb.timeout_at > ctime:
                    heapq.heapush(self.callbacks_heap, (cb.timeout_at, cb))
                else:
                    if cb.fileobj is None:
                        cb.func()
                    else:
                        cb.func(None, None)
                    ctime = time.time()

            if len(self.callbacks_heap) > 0:
                wait_tout = self.callbacks_heap[0][0] - time.time()
            else:
                wait_tout = 1

            for fd, _ in self.selector.poll(wait_tout):
                cb = self.fd2cb[fd]
                data, remote_addr = cb.fileobj.recvfrom(self.def_recv_size)
                new_cb, data = cb.func(remote_addr, data)

                if data is not None:
                    cb.fileobj.sendto(data, remote_addr)

                if new_cb is None:
                    fobj = cb.fileobj
                    self.unregister(cb.fileobj)
                    fobj.close()
                else:
                    cb.func = new_cb
