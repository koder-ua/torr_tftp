import time
import heapq
import select
import logging

from hardcoded_settings import MAX_PACKET_SIZE


reactor_logger = logging.getLogger('reactor')


class CB(object):
    def __init__(self, func, evt, fileobj, timeout_at):
        self.func = func
        self.evt = evt
        self.fileobj = fileobj
        self.timeout_at = timeout_at
        self.fd = None if fileobj is None else fileobj.fileno()


class Reactor(object):
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

        callback = self.fd2cb.get(fileobj.fileno())

        if not callback:
            self.selector.register(fileobj, evt)
            callback = CB(cb_func, evt, fileobj, timeout_at)
            self.fd2cb[fileobj.fileno()] = callback
        else:
            assert callback.fileobj is fileobj
            assert callback.evt == evt
            callback.func = cb_func
            callback.timeout_at = timeout_at

        if timeout_at is not None:
            heapq.heappush(self.callbacks_heap, (timeout_at, callback))

    def unregister(self, fileobj):
        # can't just remove it from list - it can take too long with large lists
        # so make it empty, but don't touch timeout_at - as this will breaks the heap
        # event would be removed upon obtaining from callbacks_heap
        callback = self.fd2cb[fileobj.fileno()]

        # if timeout_at is None - this event will never be removed out of heap on timeout
        # have to remove it manually
        if callback.timeout_at is None:
            reactor_logger.warning("Removing event with no timeout. This can slow down you code")
            self.callbacks_heap = [(tout, cb_obj)
                                   for (tout, cb_obj) in self.callbacks_heap
                                   if cb_obj is not callback]
            heapq.heapify(self.callbacks_heap)
        else:
            callback.evt = callback.func = callback.fd = callback.fileobj = None

        self.selector.unregister(fileobj)
        del self.fd2cb[fileobj.fileno()]

    def call_later(self, tout, func):
        call_at = tout + time.time()
        callback = CB(func, None, None, call_at)
        heapq.heappush(self.callbacks_heap, (call_at, callback))

    def call_shortly(self, func):
        self.call_later(-1, func)

    def serve_forever(self):
        while True:
            ctime = time.time()
            while len(self.callbacks_heap) > 0 and ctime >= self.callbacks_heap[0][0]:
                _, callback = heapq.heappop(self.callbacks_heap)
                if callback.func is None:
                    continue
                if callback.timeout_at > ctime:
                    heapq.heappush(self.callbacks_heap, (callback.timeout_at, callback))
                else:
                    if callback.fileobj is None:
                        callback.func()
                    else:
                        callback.func(None, None)
                    ctime = time.time()

            if len(self.callbacks_heap) > 0:
                wait_tout = self.callbacks_heap[0][0] - time.time()
            else:
                wait_tout = 1

            for fd, _ in self.selector.poll(wait_tout):
                callback = self.fd2cb[fd]
                data, remote_addr = callback.fileobj.recvfrom(MAX_PACKET_SIZE)
                new_cb, data = callback.func(remote_addr, data)

                if data is not None:
                    callback.fileobj.sendto(data, remote_addr)

                if new_cb is None:
                    fobj = callback.fileobj
                    self.unregister(callback.fileobj)
                    fobj.close()
                else:
                    callback.func = new_cb
