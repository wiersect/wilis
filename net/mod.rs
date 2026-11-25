//! `WilisNet` — Zero-dependency Post-Quantum Encrypted TCP Transport & P2P File Transfer.
//!
//! Built strictly on `std::net::{TcpListener, TcpStream}`, `WilisKEM`, `WilisSign`,
//! `WilisPAKE`, and `PqRatchetSession` with automatic Post-Compromise Security (`WPRK`) rekeying.

pub mod channel;

pub use channel::{
    recv_file_over_tcp, recv_file_pake, send_file_over_tcp, send_file_pake, PqTcpChannel,
    ReceivedFileSummary, SentFileSummary,
};
