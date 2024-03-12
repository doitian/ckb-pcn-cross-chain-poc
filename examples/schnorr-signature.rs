fn main() {
    use bitcoind::bitcoincore_rpc::RpcApi;
    let bitcoind = bitcoind::BitcoinD::from_downloaded().unwrap();
    assert_eq!(0, bitcoind.client.get_blockchain_info().unwrap().blocks)
}
