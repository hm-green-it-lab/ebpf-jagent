The JBPF-Tracer can also run on docker. For that build the image as follows:

`$ docker build -f containerized/Dockerfile -t c-ebpf-jagent .`

and start your container with:

```
$ sudo docker run --rm -it \
  --privileged \
  --pid=host \
  --cap-add SYS_ADMIN \
  --cap-add CAP_BPF \
  --cap-add CAP_PERFMON \
  --network=host \
  --security-opt seccomp=unconfined \
  -v /sys/fs/bpf:/sys/fs/bpf:rw \
  -v /lib/modules:/lib/modules:ro \
  -v /sys/kernel/tracing:/sys/kernel/tracing:rw \
  -v "$(pwd)/logs":/logs:rw  \
  c-ebpf-jagent \
  doWork
```