import pytest
import requests
import web3


@pytest.fixture(scope="module", autouse=True)
def tenderly_fork():
    fork_base_url = "https://simulate.yearn.network/fork"
    payload = {"network_id": "1"}
    resp = requests.post(fork_base_url, headers={}, json=payload)
    fork_id = resp.json()["simulation_fork"]["id"]
    fork_rpc_url = f"https://rpc.tenderly.co/fork/{fork_id}"
    print(fork_rpc_url)
    tenderly_provider = web3.HTTPProvider(fork_rpc_url, {"timeout": 600})
    web3.provider = tenderly_provider
    print(f"https://dashboard.tenderly.co/yearn/yearn-web/fork/{fork_id}")
