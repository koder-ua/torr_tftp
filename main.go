package main

import ("os"
        "github.com/op/go-logging")


var log = logging.MustGetLogger("tsync")

func main() {
    stdout_backend := logging.NewLogBackend(os.Stdout, "", 0)
    stdout_levels := logging.AddModuleLevel(stdout_backend)
    stdout_levels.SetLevel(logging.DEBUG, "")

    // Set the backends to be used.
    var format = logging.MustStringFormatter(
        "%{color} %{time:15:04:05.000} %{shortfunc} - %{level:.8s} %{color:reset} %{message}",
    )

	formatter := logging.NewBackendFormatter(stdout_backend, format)
    logging.SetBackend(stdout_levels, formatter)

    if len(os.Args) != 2 {
        log.Criticalf("Usage: %s ip:port\n", os.Args[0])
        os.Exit(1)
    }

    if MainLoop(os.Args[1]) {
        os.Exit(0)
    }
    os.Exit(1)
}
