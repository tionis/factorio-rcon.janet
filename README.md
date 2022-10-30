# factorio-rcon
A simple rcon client for factorio game servers.
This rcon implementation is only designed to work with factorio and as such also follows Factorio's rejection of sending `SERVERDATA_RESPONSE_VALUE` packets to check for multi-packet responses (details are described in [the valvesoftware developer wiki](https://developer.valvesoftware.com/wiki/Source_RCON_Protocol#Multiple-packet_Responses)).
