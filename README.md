chan_openbsc
============

Proof Of Concept.
You should not depend on it for anything other than testing.
------------------------------------------------------------

chan_openbsc: it does creates a module that bridge OpenBSC and Asterisk.

There is 3 paths to apply:
libosmo-abis/0001-chan_openbsc.path
libosmocore/0001-chan_openbsc.patch
openbsc/0001-chan_openbsc.path

Copy each patch, into the directory of each project (libosmocore, libosmo-abis, openbsc)
To apply a patch do: patch -p1 < 0001-chan_openbsc.path

The content of chan_openbsc must be copied to the openbsc directory:
openbsc/openbsc/src/chan_openbsc/


BUG:

 The sound becomes garbage after 35seconds... and osmo-bts stats complaining
 
<0011> trau/osmo_ortp.c:0 Cannot use the scheduled mode: the scheduler is not started.
  Call ortp_scheduler_init() at the begginning of the application.<0011> trau/osmo_ortp.c:0
  can't guess current timestamp because session is not scheduled.<0011> trau/osmo_ortp.c:141
  osmo-ortp(25126): timestamp_jump, new TS 0
