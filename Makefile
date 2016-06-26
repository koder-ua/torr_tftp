.PHONY: clean rebuild

tsync: export GOPATH = /home/koder/bin/golib
tsync: export PATH = /home/koder/bin/go/bin:$PATH
tsync: *.go
		go build -o tsync tsync.go tsync_proto.go utils.go main.go

clean:
		rm tsync

rebuild: clean tsync
