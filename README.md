up (Experimental)
==

`up` short for UDP Pipeline is an experiment in using UDP to transfer data accross unreliable networks.

The problem
--

In an unreliable network where a connection may be lost for a significant amount of time, a TCP connection may fail (time-out) causing the transfer to fail.

One solution to this problem is to use a protocol like `rsync(1)` to resume the file transfer later, however in an environment where the network is faster than the disks (for example when using cheap cloud virtual disks), `rsync` will take as long or longer, working out where to recover from as it will just re-sending the data over the network.

For small files, that's not a big issue, but for multi-gigabyte files it becomes a huge problem because the time to transfer these files extends to days, and because the network is unreliable, may have to be tried multiple times before being successful.

The Experimental Solution
--
Increase the timeouts on the network, or better still, never time out.

The idea is that the receiver will only exit when the sender tells the receiver it has finished. Neither end will ever give up because nothing is being received on the network.

`up` is a simple end to end data transfer. The `up` client reads standard input, and sends it to the server accorss the network. The `up` server receives packets and writes to standard output.

up direction?
--

Eventually the `up` logic could be exposed as an API, so that something akin to `scp` could be developed on top of `up`.

