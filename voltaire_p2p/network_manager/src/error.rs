// generates error types
use error_chain::error_chain;

error_chain! {
   links  {
       Libp2p(p2p_voltaire_network::error::Error, p2p_voltaire_network::error::ErrorKind);
   }
}
