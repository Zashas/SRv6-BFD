#!/usr/bin/python3

from bcc import BPF, libbcc
from pyroute2 import IPRoute
import sys, ctypes, os, socket, json, functools

BPF_FS_PATH = "/sys/fs/bpf/"

FRR_PROGRAM_TPL = """
BPF_TABLE("array", uint32_t, uint32_t, frr_map, 1);

int frr(struct __sk_buff *skb) {{
    uint32_t key = 0;
    uint32_t *link_up = frr_map.lookup(&key);
    if (!link_up || *link_up)
        return BPF_OK;

    char srh[] = {{ 0, {hdrlen}, 4, {nseg},
                    {nseg}, 0, 0, 0,
                    {segments}
                 }};

    int ret = bpf_lwt_push_encap(skb, 0, (void *)srh, sizeof(srh));
    if (ret != 0) {{
            bpf_trace_printk("SRv6 FRR: incorrect SRH\\n");
            return BPF_DROP;
    }}
    return BPF_OK;
}}
"""

def prepare_pin(dst):
    path = os.path.join(BPF_FS_PATH, 'frr_map_'+dst.replace('/','-').replace(':','_'))
    if os.path.isfile(path):
        os.remove(path)

    return path

def install_route(dst, ifname, gw, lfa_segs):
    segs = map(lambda x: socket.inet_pton(socket.AF_INET6, x), lfa_segs)
    segs = functools.reduce(lambda x,y: x+y, segs)
    segs = ', '.join(map(str, list(segs)))
    
    prog = FRR_PROGRAM_TPL.format(hdrlen=2*len(lfa_segs), nseg=len(lfa_segs)-1, segments=segs)
    bpf = BPF(text=prog)
    fn = bpf.load_func("frr", BPF.LWT_IN)

    pin_path = prepare_pin(dst)
    frr_map = bpf.get_table("frr_map")
    ret = libbcc.lib.bpf_obj_pin(frr_map.map_fd, ctypes.c_char_p(pin_path.encode('ascii')))
    if ret != 0:
        raise Exception("Failed to pin map: {}".format(ret))

    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=ifname)[0]
           
    encap = {'type':'bpf', 'in':{'fd':fn.fd, 'name':fn.name}}
    ipr = IPRoute()
    ipr.route("add", dst=dst, oif=idx, encap=encap, gateway=gw)

    return pin_path

def start_bfd_daemon(conf):
    args_order = ('bindaddr', 'port', 'session', 'threshold', 'interval', 'bpf_map', 'segments')
    args = [' '.join(conf[x]) if isinstance(conf[x], list) else str(conf[x]) for x in args_order]

    daemon_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'bfd-daemon')
    args.insert(0, daemon_path)
    os.execve(daemon_path, args, {})

if len(sys.argv) != 2:
    print("Format: ./frr-master.py CONFIG-FILE")
    sys.exit(1)

config_file = open(sys.argv[1])
config = json.load(config_file)
config_file.close()

config["bfd"]["bpf_map"] = install_route(config["route"]["prefix"], config["route"]["ifname"],
                                         config["route"]["gateway"],config["route"]["frr-segs"])
start_bfd_daemon(config["bfd"])
