## usage

```shell
sudo ./build/perf-counter \
    -e 'uprobes:do_payload' \
        --pid 17428 \
        --pid 17429 \
            -e syscalls:sys_enter_clock_nanosleep
```
