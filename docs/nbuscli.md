## Name

nbuscli - nBus command-line diagnostic utility.

## Synopsis

    nbuscli [command] [options]

## Description

`nbuscli` is a command-line diagnostic utility for enumerating and/or interacting with live peers. It is strongly
recommended not to use this in production systems as there are better ways to interact with peers. The tool accepts a
few sub-commands:

* `list` - Enumerates all live peers.
* `listen` - Listen for events.
* `invoke` - Invoke a remote method.
* `raise` - Raise an event on one or more remote peers.

These sub-commands may take one or more options.

Note, any place where wild-cards are used, the syntax is as defined in
[`fnmatch`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/fnmatch.html) function by POSIX.

## Options

* **`-h`, `--help`**

    Generic help message or when passed as option to any sub-command, then a help specific to that sub-command is
    printed to stdout.

* **`-v`, `--verbose`**

  Verbose listing. Used in `list` sub-command to also show methods registered in each peer.

* **`-P`, `--protocol <PROTOCOL>`**

    Select a specific serialisation protocol to listen for. Depending on the sub-command, if this option is not
    specified, it either defaults to `NBUS_PROTO_ANY` or `NBUS_PROTO_RAW`. The argument `<PROTOCOL>` can be one of
    `raw`, `cbor`, `josn` or a user defined protocol number.

    For `listen` sub-command, `0` (internally `NBUS_PROTO_ANY`) is acceptable and is default. For all others, it
    defaults to `1`/`raw` (internally `NBUS_PROTO_RAW`).

* **`-p`, `--peer <NAME | WILDCARD>`**

    In `listen` and `raise` sub-command, this option can take wild-card arguments. If not specified in these sub-
    commands, it defaults to `*`. In `invoke` sub-command, the argument to this option must be a single valid peer name.
    It is invalid to not specify a peer for `invoke`.

* **`-m`, `--method <NAME>`**

    Used only in `invoke` sub-command, this specifies the name of the remote method to invoke.

* **`-e`, `--event <NAME | WILDCARD>`**

    In `listen` mode, the argument to this option is either a full event name or a wild-card. If not specified, it
    defaults to `*`. In `raise` mode, the argument must be a valid event name.

* **`-n`, `--no-args`**

    In `raise` and `invoke` mode, this option tells there are not arguments/contents to be sent.

* **`-w`, `--wait-reply`**

    Used with `invoke` only. This options forces the tool to wait for a reply. If not specified the invocation exits
    immediately without waiting for the remote peer to reply.

* **`-i`, `--file <filename>`**

    When raising event or invoking a remote method, this option picks the argument/contents sent. If no input file was
    given and `-n` was also not specified, then argument is picked from STDIN.