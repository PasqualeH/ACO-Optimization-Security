//
// Ant2KeyAuthority: autorita' centrale "in-simulazione" per il provisioning
// delle chiavi (approccio alternativo al provisioning offline via file, vedi
// Ant2Crypto). Nessuna porta: e' un modulo di utilita', interrogato dagli
// altri moduli Ant2 con una chiamata C++ diretta, non con messaggi di rete.

package inet.routing.ant2;

simple Ant2KeyAuthority
{
    parameters:
        @class("ant2::Ant2KeyAuthority");
        @display("i=block/table");
}
