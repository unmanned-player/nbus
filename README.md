# nBus

nBus or nano-bus is an alternative to OpenWRTs UBus. I've had some troubles using UBus in the past specially with its
poor documentation and general usability issues that eventually led to the development of nBus.

nBus is better or different than UBus in a few ways:

* Messages are just blobs. Serialisation is user-defined and not mandatory
* No centralised daemon to control advertisement and discovery
* Memory usage can be strictly controlled by pre-allocating memory
* Works on Linux and can be ported to other POSIX Operating Systems with ease
* Oh, and by the way, better documented than UBus

## How it works

nBus is meant for remote procedure calls usually within the same device. To achieve that, each process can hold one or
more endpoint contexts which is a glorified Unix domain socket with a few bells and whistles added. Those include a
unique name, a NULL terminated array of hosted methods and a call-back for when an event arrives.

Whenever a method is invoked or an event is raised, a new connection to the remote context is made, I/O occurs and the
connection is closed. It's as simple as that. And because of this, it's usually slower - in fact, Ubus is about 3x
faster than nBus. On a Raspberry Pi 4 B model, UBus can send approx. 3800 msgs/sec, while nBus can do only about 1480
msgs/sec. But then again, the intent of a bus like this is more towards one-off convenience and usability than of
high-performance IPC.

A future version with libev back-end will hopefully not have this bottle-neck. But that's far off in future.

## How to use nBus

See a serving side example below:

First include nBus header file.
```c
#include <nbus/nbus.h>
```

Define your call-back for some method. If the method also produces response, use `nbus_set_output` to set the response
data.
```c
static int say_hello(nbus_context_t *ctx, uint8_t proto, const char *peer, const char *name, const void *data, const size_t n)
{
    /* blah blah */
    nbus_set_output(ctx, "Hello, world!", 13);
    return 0;
}
```

Then register all your call-backs in a `nbus_cb_reg_t` array as shown below:

```c
static nbus_cb_reg_t regs[] = {
    NBUS_DEF_METHOD(NBUS_PROTO_RAW, say_hello),
    NBUS_DEF_END()
};
```

Finally, in the main function of the thread initialise a context and handle any return conditions properly.
```c
    nbus_context_t *ctx;

    if ((err = nbus_init(&ctx, "server", regs, NULL, NULL)) != 0) {
        fprintf(stderr, "nbus_init: %s\n", strerror(err));
        return EXIT_FAILURE;
    }
```
At this point, the context is ready to serve.

Now, use `poll()` or `select()` like function to listen for READ events on the context's file descriptor. It can be read
from `nbus_get_fd()` function.
```c
    struct pollfd fds[1];

    fds[0].fd = nbus_get_fd(ctx);
    fds[0].events = POLLIN | POLLHUP;
```

Whenever a READ even occurs on that file descriptor, call `nbus_handle()` to handle incoming method calls/events.
```c
    while (poll(fds, 1, -1) > 0) {
        if (fds[1].revents & POLLIN) {
            if ((r = nbus_handle(ctx)) != 0) {
                fprintf(stderr, "nbus_handle: %s\n", strerror(r));
                break;
            }
        }
    }
```

If you wish to invoke a remote call on this context, from another context do:
```c
    char *res = NULL;
    size_t res_len = 0;
    int rc = 0;

    err = nbus_invoke(ctx, 0, NBUS_PROTO_RAW, "server", "say_hello", "some data", 9, &rc, (void ** const)&res, &res_len);
```
At this point, `res` will contain the response to the remote method and `res_len` will tell the size of the response
data. Note, `rc` is the return code from the method's call-back on the remote side. In our example, we were
unconditionally returning `0` above, so `rc` will always be 0.

Do not forget to destroy the context when done.
```c
    nbus_exit(ctx);
```

## Building

nBus needs,

* GCC >= 4.9 or clang >= 3.4 for ISO-C 99 support.
* CMake >= 2.8.12

Optionally,
* JSON-C >= 0.15
* TinyCBOR >= 0.5

By default, the build will generate library only. To build examples or documents/manual pages you need to explicitly
enable those switches. The build settings are similar to the ones
[Buildroot](https://buildroot.org/downloads/manual/manual.html#_infrastructure_for_cmake_based_packages) uses.

| Variable             | Type    | Default                      | Description                           |
| -------------------- | --------| ---------------------------- | ------------------------------------- |
| BUILD_CLI            | Boolean | `OFF`                        | Build command-line diagnostic utility |
| BUILD_AGENT          | Boolean | `OFF`                        | Build network agent. Coming soon      |
| BUILD_DOCS           | Boolean | `OFF`                        | Build API docs and manual pages       |
| BUILD_EXAMPLES       | Boolean | `OFF`                        | Build examples                        |
| BUILD_TESTS          | Boolean | `OFF`                        | Build speed-tests                     |
| ENABLE_LUA           | Boolean | `OFF`                        | Build Lua bindings. Coming soon       |
| NBUS_CTX_NAME_PREFIX | String  | `nbus:`  or `/var/run/nbus/` | See details below                     |

### `NBUS_CTX_NAME_PREFIX`

A unique prefix for all nBus contexts. The prefix is usually a directory path (with trailing '/') on most Unix systems.
On Linux, the prefix can also be abstract. See [unix(7)](https://www.mankier.com/7/unix) for details on abstract domain
sockets.

General requirements for path prefix are:
* Must be absolute and real path (no symlinks), must starts with '/' and end '/'.
* Directory must exist before first context is created. Make this directory via some init script.
* Directory must be exclusive to nBus contexts only. Subdirectories can exist, nothing else can be made here.

Abstract prefix on the other hand doesn't have any limitations. But it is usually a good idea for prefix to have a
trailing separator such as `:` or something else.

If `NBUS_CTX_NAME_PREFIX` is not specified during build,
* Path prefix defaults to `/var/run/nbus/`
* On Linux, it defaults to abstract prefix and is set to `nbus:`.

## Diagnostic utility

nBus comes with a command-line diagnostic utility called, `nbuscli`. It can be used to listen for events, raise events
or invoke remote methods. If JSON-C or TinyCBOR library is available, `nbuscli` can also listen for serialised events
on these formats too.

For example (as seen on Raspberry Pi):

```
    # nbuscli --list-peers '*'
        generator

    # nbuscli --listen '*'
    > [R] nbus:generator@hello_raw
      0000  57 6f 72 6c 64 21                                World!

    > [J] nbus:generator@hello_json
    {
      "data": "World!"
    }

    > [C] nbus:generator@hello_cbor
    "World!"
```

Note, the diagnostic utility is still under development. More features will be added in coming releases.

## Agent

Coming soon.

An agent is a daemon that uses HTTP(S) protocol to forward RPCs and events in/out of device.

## Security

nBus works over Unix domain sockets which means data can be only within the device where it's running on. IoT devices
normally have a vetted list of software, so rogue applications DoS'ing legitimate applications would likely not be
possible. For this reason, there's no special security mechanisms implemented for contexts.

Using path based prefix can provide some access control if that is so desired. In that create sub-directories under path
prefix with various users and groups. In the application, set umask() and set effective UID/GID appropriately and create
context. Use diagnostic utility as `root` user to be able to see all contexts.
