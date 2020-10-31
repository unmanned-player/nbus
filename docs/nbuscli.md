## Name

nbuscli - nBus command-line diagnostic utility.

## Synopsis

    nbuscli invoke  [-w] -p <N> -m <N> [-P <P>] [-t <MS>] (-i <FILE> | -n)
    nbuscli list    [-v]
    nbuscli listen  -e <N|W> -p <N|W> [-P <P>]
    nbuscli raise   -e <N> [-P <P>] [-t <MS>] (-i <FILE> | -n)

## Description

`nbuscli` is a command-line diagnostic utility for enumerating and/or interacting with live peers. It is strongly
recommended not to use this in production systems as there are better ways to interact with peers. The tool accepts a
few operation sub-commands:

* `list` - Enumerates all live peers.
* `listen` - Listen for events.
* `invoke` - Invoke a remote method.
* `raise` - Raise an event on one or more remote peers.

These sub-commands may take one or more options.

Note, any place where wild-cards are used, the syntax is as defined in
[`fnmatch`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/fnmatch.html) function by POSIX.

## Options

* **`-h`, `--help`**

    Generic help message printed to stdout.

* **`-v`, `--verbose`**

    Verbose listing. Used in `list` operation to also show methods registered in each peer.

* **`-P`, `--protocol <PROTOCOL>`**

    The argument `<PROTOCOL>` can be one of `raw`, `cbor`, `josn` or a user defined protocol number. It select a
    specific serialisation protocol to listen for. Depending on the operation, if this option is not specified, it
    either defaults to `0` (internally `NBUS_PROTO_ANY`) or `1`/`raw` (internally `NBUS_PROTO_RAW`).

    For `listen` operations, `0` (internally `NBUS_PROTO_ANY`) is acceptable and is default. For all others, it
    defaults to `1`/`raw` (internally `NBUS_PROTO_RAW`).

* **`-p`, `--peer <NAME | WILDCARD>`**

    For `listen` and `raise` operations, this option can take wild-card arguments. If not specified in these operations'
    sub-commands, it defaults to `*`. For `invoke` operation, the argument to this option must be a single valid peer
    name. It is invalid to not specify a peer for `invoke`.

* **`-m`, `--method <NAME>`**

    Used only for `invoke` operation, this specifies the name of the remote method to invoke.

* **`-e`, `--event <NAME | WILDCARD>`**

    For `listen` operation, the argument to this option is either a full event name or a wild-card. If not specified, it
    defaults to `*`. For `raise` operation, the argument must be a valid event name.

* **`-n`, `--no-args`**

    For `raise` and `invoke` operations, this option tells there are no arguments/contents to be sent.

* **`-w`, `--wait-reply`**

    Used with `invoke` only. This options forces the tool to wait for a reply. If not specified the invocation exits
    immediately without waiting for the remote peer to reply.

* **`-i`, `--input <filename>`**

    When raising event or invoking a remote method, this option picks the argument/contents sent. If no input file was
    given and `-n` was also not specified, then argument is picked from STDIN.

* **`-t`, `--timeout <MS>`**

    Time out for `invoke` and `list` operations. If specified in `invoke` operation, `-w`, `--wait-reply` is implied.

## Examples

To list all peers,

    # nbuscli list
        server
        listener

To list also the methods in these peers,

    # nbuscli list -v
      server
          [M.  R] say_hello
      listener
          [.E  *] *

The flag string in box bracket `[]` tell whether this remote method (M), event handler (E) followed by the serialisation
protocol it can handle. For call-backs registered for any kind of protocol ( by `NBUS_PROTO_ANY`) would show as `*`. The
event handler in `listener` context can listen to any event, and therefore the handler shows `*`. In the `server`
context it shows a method `say_hello` and the protocol it expects is raw.

To listen for events, call as `nbuscli listen`. During compilation, if JSON-C and/or TinyCBOR was present in path,
`nbuscli` would be linked against them. By linking against these libraries, `nbuscli` will pretty-print JSON objects in
events and prints the diagnostic representation of CBOR events.

Without any external linking, `nbuscli` output looks like:

    # nbuscli listen
    > [ R] nbus:generator@hello_raw (6)
      0000  57 6f 72 6c 64 21                                World!
    > [ J] nbus:generator@hello_json (22)
      0000  7b 20 22 64 61 74 61 22 3a 20 22 57 6f 72 6c 64 { "data": "World
      0010  21 22 20 7d 00 00                                !" }..
    > [ C] nbus:generator@hello_cbor (7)
      0000  66 57 6f 72 6c 64 21                             fWorld!

With external linking of both JSON-C and TinyCBOR, `nbuscli` output looks like:

    # nbuscli listen
    > [ R] nbus:generator@hello_raw (6)
      0000  57 6f 72 6c 64 21                                World!
    > [ J] nbus:generator@hello_json (22)
    {
      "data": "World!"
    }
    > [ C] nbus:generator@hello_cbor (7)
    "World!"

The title of each event shows the serialisation protocol in box brackets `[]`, then name of the peer that generated the
event (`generator`), followed by the `@` symbol and name of the event. The final number in round braces `()` is the size
of the event message.

To invoke a remote method, use `nbuscli invoke` as:

    # nbuscli invoke -t 1 -p server -m 'say_hello'
    World!^D
    Hello, World!
    #

To raise an event, use `nbuscli raise` as:

    # nbuscli raise -e "if.eth0"
    wire-detached^D
    #

In both, `invoke` and `raise` operations, if `-n` is not specified, it is expected that `-i` be specified or argument
data is picked from <STDIN>.
