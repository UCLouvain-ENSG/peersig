"""Compares `peersig-probe read` with tshark's JA4 and JA4_r, flow by flow.

    python3 tests/compare_tshark.py tests/data/traces/*.pcap*

Needs tshark >= 4.2 and a release build. DTLS on a non-standard port needs
a decode-as rule, e.g. TSHARK_ARGS="-d udp.port==4433,dtls"; out-of-order
TCP segments need TSHARK_ARGS="-o tcp.reassemble_out_of_order:TRUE".
"""
import json, os, subprocess, sys
BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'target', 'release', 'peersig-probe')
EXTRA = os.environ.get('TSHARK_ARGS', '').split()
tot_ok=tot=0
for f in sys.argv[1:]:
    out = subprocess.run([BIN,'read',f], capture_output=True, text=True).stdout
    mine = {}
    for l in out.splitlines():
        r = json.loads(l)
        if r['type']=='hello':
            k=(r['src'].rsplit(':',1)[1], r['dst'].rsplit(':',1)[1])
            mine.setdefault(k,set()).add((r['ja4'], r['ja4_r']))
        if r['type']=='stats': stats=r['flows']
    ref = {}
    for proto, fld in (('tls','tls.handshake'),('dtls','dtls.handshake')):
        t = subprocess.run(['tshark','-r',f,*EXTRA,'-Y',f'{fld}.type==1','-T','fields','-e','tcp.srcport','-e','udp.srcport','-e','tcp.dstport','-e','udp.dstport','-e',f'{fld}.ja4','-e',f'{fld}.ja4_r'], capture_output=True, text=True).stdout
        for l in t.splitlines():
            a = l.split('\t')
            sp = a[0] or a[1]; dp = a[2] or a[3]
            if a[4]: ref.setdefault((sp,dp),set()).add((a[4], a[5]))
    ok = sum(1 for k in ref if mine.get(k)==ref[k])
    missing = [k for k in ref if k not in mine]
    wrong = [(k, ref[k], mine[k]) for k in ref if k in mine and mine[k]!=ref[k]]
    extra = [k for k in mine if k not in ref]
    tot_ok+=ok; tot+=len(ref)
    print(f"{f.split('/')[-1]}: flows ref={len(ref)} ok={ok} missing={len(missing)} wrong={len(wrong)} extra={len(extra)}  stats={stats}")
    for w in wrong[:3]: print('   WRONG', w)
    for m in missing[:3]: print('   MISSING', m, ref[m])
print('TOTAL', tot_ok, '/', tot)
sys.exit(0 if tot_ok == tot else 1)
