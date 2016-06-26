#!/bin/bash

tmux new-session -d -s "tsync" 'exec ./tsync localhost:8999'
tmux rename-window 'tsync'
tmux select-window -t tsync:0
tmux split-window -v -t 0 'exec bash'
tmux split-window -h -t 0 'exec ./tsync localhost:8998'
tmux select-pane -t 1
tmux -2 attach-session -t tsync
