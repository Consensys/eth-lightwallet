from ethereum import tester
from ethereum import utils
from bitcoin import ecdsa_sign, ecdsa_raw_sign, ecdsa_raw_recover, decode_sig
import json

s = tester.state()

init_seed = 'some_random_initial_seed_'

indices = range(10000)

result_vector = []

for i in indices:
    seed = init_seed + str(i)
    key = utils.sha3(seed)
    addr = utils.privtoaddr(key)
    s.send(to=addr, sender=tester.k0, value=10**18)
    assert (s.block.get_balance(addr) == 10**18)
    s.send(to=tester.a0, sender=key, value=6*10**17)
    assert (s.block.get_balance(addr) < 4*10**17 and s.block.get_balance > 3*10**17)
    result_vector.append({'seed': seed,
                          'key' : utils.encode_hex(key),
                          'addr' : utils.encode_hex(addr)})
    
output = json.dumps(result_vector)
outfile = file('testvector.json', 'w')
outfile.write(output)
