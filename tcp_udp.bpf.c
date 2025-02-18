//go:build ignore
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL v2";

volatile pid_t self_pid;

#define TASK_COMM_LONG_LEN 32
#define TASK_COMM_LEN 16

#define ETH_HLEN 14
#define ETH_P_IP 0x0800 /* Internet Protocol packet        */
#define ETH_P_IPV6 0x86DD

/* define ip fragmentation flags */
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff

/* define ipv6 next header types */
#define IPV6_NH_HOP 0
#define IPV6_NH_TCP 6
#define IPV6_NH_UDP 17
#define IPV6_NH_IPV6 41
#define IPV6_NH_ROUTING 43
#define IPV6_NH_FRAGMENT 44
#define IPV6_NH_GRE 47
#define IPV6_NH_ESP 50
#define IPV6_NH_AUTH 51
#define IPV6_NH_ICMP 58
#define IPV6_NH_NONE 59
#define IPV6_NH_DEST 60
#define IPV6_NH_SCTP 132
#define IPV6_NH_MOBILITY 135

#define AF_INET 2
#define AF_INET6 10

#define APP_MSG_MAX 4
#define APP_MSG_LEN_MAX 1400
#define APP_MSG_LEN_MIN 16

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define SOCK_FLAGS_MAX 64
#define SOCK_EXP_MAX 4
#define SOCK_BINDADDR_LOCK 4
#define SOCK_BINDPORT_LOCK 8
#define KEY_SOCK(h) ((__u64)h)

#define SKB_DST_NOREF 1UL
#define SKB_DST_PTRMASK ~(SKB_DST_NOREF)

#define TCP_NONE 0
#define TCP_FIN 1
#define TCP_SYN 2
#define TCP_RST 4
#define TCP_PSH 8
#define TCP_ACK 16
#define TCP_URG 32

#define UDP_NEW 0
#define UDP_ESTABLISHED 1
#define UDP_CLOSE 2

#define SOCK_IDLE_TIMEOUT 15
#define SOCK_ACTIVE_TIMEOUT 1800
enum ROLE
{
    ROLE_NONE,
    ROLE_TCP_CLIENT,
    ROLE_TCP_SERVER,
    ROLE_UDP_CLIENT,
    ROLE_UDP_SERVER,
    ROLE_UNIX_CLIENT,
    ROLE_UNIX_SERVER
};
#define GET_ROLE_STR(role)                      \
    (role == ROLE_TCP_CLIENT    ? "tcp client"  \
     : role == ROLE_TCP_SERVER  ? "tcp server"  \
     : role == ROLE_UDP_CLIENT  ? "udp client"  \
     : role == ROLE_UDP_SERVER  ? "udp server"  \
     : role == ROLE_UNIX_CLIENT ? "unix client" \
     : role == ROLE_UNIX_SERVER ? "unix server" \
                                : "unknown")

/* define ringbuffer stats collected on records */
struct stats
{
    uint64_t q_push_added;
    uint64_t q_push_updated;
    uint64_t q_push_readded;
    uint64_t q_pop_expired;
    uint64_t q_pop_ignored;
    uint64_t q_pop_missed;
};

struct sock_queue
{
    uint64_t key;
    uint64_t ts;
};

struct app_msg
{
    uint8_t cnt;
    uint64_t ts[APP_MSG_MAX];
    uint32_t seq[APP_MSG_MAX];
    uint32_t len[APP_MSG_MAX];
    uint8_t isrx[APP_MSG_MAX];
    uint8_t data[APP_MSG_MAX][APP_MSG_LEN_MAX];
};

struct sock_tuple
{
    char laddr[16];
    char raddr[16];
    uint16_t lport;
    uint16_t rport;
    uint8_t proto;
};

struct sock_info
{
    uint32_t pid;
    uint32_t tid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    uint64_t ts_proc;
    char proc[TASK_COMM_LEN];
    char comm[TASK_COMM_LONG_LEN];
    char comm_parent[TASK_COMM_LONG_LEN];
    uint16_t tx_ifindex;
    uint64_t ts_first;
    uint64_t tx_ts_first;
    uint64_t tx_ts;
    uint64_t rx_ts_first;
    uint64_t rx_ts;
    uint16_t family;
    uint8_t proto;
    uint8_t state;
    uint8_t role;
    char laddr[16];
    char raddr[16];
    uint16_t lport;
    uint16_t rport;
    uint32_t tx_data_packets;
    uint32_t tx_packets;
    uint32_t tx_packets_retrans[2];
    uint32_t tx_packets_dups[2];
    uint64_t tx_bytes;
    uint64_t tx_bytes_acked[2];
    uint64_t tx_bytes_retrans[2];
    uint32_t tx_rto;
    uint16_t rx_ifindex;
    uint32_t rx_data_packets;
    uint32_t rx_packets;
    uint32_t rx_packets_queued;
    uint32_t rx_packets_drop[2];
    uint32_t rx_packets_recorder[2];
    uint32_t rx_packets_frag;
    uint64_t rx_bytes;
    uint32_t rx_ttl;
    uint32_t rtt;
    struct app_msg app_msg;
};

struct sock_event_info
{
    struct sock *sock;
    struct sk_buff *skb;
    uint16_t family;
    uint16_t lport; /* local port */
    uint16_t rport; /* remote port */
    void *args;
    char isrx;
    char *func;
};

struct record
{
    uint32_t pid;
    uint32_t tid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    uint64_t age;
    char proc[TASK_COMM_LEN];
    char comm[TASK_COMM_LONG_LEN];
    char comm_parent[TASK_COMM_LONG_LEN];
    uint64_t ts_first;
    uint64_t ts;
};

struct record_sock
{
    struct record rec;
    uint64_t tx_ts_first;
    uint64_t tx_ts;
    uint64_t rx_ts_first;
    uint64_t rx_ts;
    uint16_t family;
    uint8_t proto;
    uint8_t state;
    uint8_t role;
    char laddr[16];
    char raddr[16];
    uint16_t lport;
    uint16_t rport;
    uint16_t tx_ifindex;
    uint32_t tx_data_packets;
    uint32_t tx_packets;
    uint32_t tx_packets_retrans;
    uint32_t tx_packets_dups;
    uint64_t tx_bytes;
    uint64_t tx_bytes_acked;
    uint64_t tx_bytes_retrans;
    uint32_t tx_rto;
    uint16_t rx_ifindex;
    uint32_t rx_data_packets;
    uint32_t rx_packets;
    uint32_t rx_packets_queued;
    uint32_t rx_packets_drop;
    uint32_t rx_packets_recorder;
    uint32_t rx_packets_frag;
    uint64_t rx_bytes;
    uint32_t rx_ttl;
    uint32_t rtt;
    struct app_msg app_msg;
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4194304);
} ringbuf_records SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct record_sock);
} heap_record_sock SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, __u64);
    __type(value, struct sock_info);
} hash_socks SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct sock_info);
} heap_sock SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct sock_tuple);
} heap_tuple SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct sock_tuple);
    __type(value, __u64);
} hash_tuples SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 262144);
    __type(value, __u64[2]);
} queue_socks SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct stats);
} stats SEC(".maps");

const uint64_t crc64_tab[256] = {
    0x0000000000000000UL, 0x7ad870c830358979UL, 0xf5b0e190606b12f2UL, 0x8f689158505e9b8bUL, 0xc038e5739841b68fUL,
    0xbae095bba8743ff6UL, 0x358804e3f82aa47dUL, 0x4f50742bc81f2d04UL, 0xab28ecb46814fe75UL, 0xd1f09c7c5821770cUL,
    0x5e980d24087fec87UL, 0x24407dec384a65feUL, 0x6b1009c7f05548faUL, 0x11c8790fc060c183UL, 0x9ea0e857903e5a08UL,
    0xe478989fa00bd371UL, 0x7d08ff3b88be6f81UL, 0x07d08ff3b88be6f8UL, 0x88b81eabe8d57d73UL, 0xf2606e63d8e0f40aUL,
    0xbd301a4810ffd90eUL, 0xc7e86a8020ca5077UL, 0x4880fbd87094cbfcUL, 0x32588b1040a14285UL, 0xd620138fe0aa91f4UL,
    0xacf86347d09f188dUL, 0x2390f21f80c18306UL, 0x594882d7b0f40a7fUL, 0x1618f6fc78eb277bUL, 0x6cc0863448deae02UL,
    0xe3a8176c18803589UL, 0x997067a428b5bcf0UL, 0xfa11fe77117cdf02UL, 0x80c98ebf2149567bUL, 0x0fa11fe77117cdf0UL,
    0x75796f2f41224489UL, 0x3a291b04893d698dUL, 0x40f16bccb908e0f4UL, 0xcf99fa94e9567b7fUL, 0xb5418a5cd963f206UL,
    0x513912c379682177UL, 0x2be1620b495da80eUL, 0xa489f35319033385UL, 0xde51839b2936bafcUL, 0x9101f7b0e12997f8UL,
    0xebd98778d11c1e81UL, 0x64b116208142850aUL, 0x1e6966e8b1770c73UL, 0x8719014c99c2b083UL, 0xfdc17184a9f739faUL,
    0x72a9e0dcf9a9a271UL, 0x08719014c99c2b08UL, 0x4721e43f0183060cUL, 0x3df994f731b68f75UL, 0xb29105af61e814feUL,
    0xc849756751dd9d87UL, 0x2c31edf8f1d64ef6UL, 0x56e99d30c1e3c78fUL, 0xd9810c6891bd5c04UL, 0xa3597ca0a188d57dUL,
    0xec09088b6997f879UL, 0x96d1784359a27100UL, 0x19b9e91b09fcea8bUL, 0x636199d339c963f2UL, 0xdf7adabd7a6e2d6fUL,
    0xa5a2aa754a5ba416UL, 0x2aca3b2d1a053f9dUL, 0x50124be52a30b6e4UL, 0x1f423fcee22f9be0UL, 0x659a4f06d21a1299UL,
    0xeaf2de5e82448912UL, 0x902aae96b271006bUL, 0x74523609127ad31aUL, 0x0e8a46c1224f5a63UL, 0x81e2d7997211c1e8UL,
    0xfb3aa75142244891UL, 0xb46ad37a8a3b6595UL, 0xceb2a3b2ba0eececUL, 0x41da32eaea507767UL, 0x3b024222da65fe1eUL,
    0xa2722586f2d042eeUL, 0xd8aa554ec2e5cb97UL, 0x57c2c41692bb501cUL, 0x2d1ab4dea28ed965UL, 0x624ac0f56a91f461UL,
    0x1892b03d5aa47d18UL, 0x97fa21650afae693UL, 0xed2251ad3acf6feaUL, 0x095ac9329ac4bc9bUL, 0x7382b9faaaf135e2UL,
    0xfcea28a2faafae69UL, 0x8632586aca9a2710UL, 0xc9622c4102850a14UL, 0xb3ba5c8932b0836dUL, 0x3cd2cdd162ee18e6UL,
    0x460abd1952db919fUL, 0x256b24ca6b12f26dUL, 0x5fb354025b277b14UL, 0xd0dbc55a0b79e09fUL, 0xaa03b5923b4c69e6UL,
    0xe553c1b9f35344e2UL, 0x9f8bb171c366cd9bUL, 0x10e3202993385610UL, 0x6a3b50e1a30ddf69UL, 0x8e43c87e03060c18UL,
    0xf49bb8b633338561UL, 0x7bf329ee636d1eeaUL, 0x012b592653589793UL, 0x4e7b2d0d9b47ba97UL, 0x34a35dc5ab7233eeUL,
    0xbbcbcc9dfb2ca865UL, 0xc113bc55cb19211cUL, 0x5863dbf1e3ac9decUL, 0x22bbab39d3991495UL, 0xadd33a6183c78f1eUL,
    0xd70b4aa9b3f20667UL, 0x985b3e827bed2b63UL, 0xe2834e4a4bd8a21aUL, 0x6debdf121b863991UL, 0x1733afda2bb3b0e8UL,
    0xf34b37458bb86399UL, 0x8993478dbb8deae0UL, 0x06fbd6d5ebd3716bUL, 0x7c23a61ddbe6f812UL, 0x3373d23613f9d516UL,
    0x49aba2fe23cc5c6fUL, 0xc6c333a67392c7e4UL, 0xbc1b436e43a74e9dUL, 0x95ac9329ac4bc9b5UL, 0xef74e3e19c7e40ccUL,
    0x601c72b9cc20db47UL, 0x1ac40271fc15523eUL, 0x5594765a340a7f3aUL, 0x2f4c0692043ff643UL, 0xa02497ca54616dc8UL,
    0xdafce7026454e4b1UL, 0x3e847f9dc45f37c0UL, 0x445c0f55f46abeb9UL, 0xcb349e0da4342532UL, 0xb1eceec59401ac4bUL,
    0xfebc9aee5c1e814fUL, 0x8464ea266c2b0836UL, 0x0b0c7b7e3c7593bdUL, 0x71d40bb60c401ac4UL, 0xe8a46c1224f5a634UL,
    0x927c1cda14c02f4dUL, 0x1d148d82449eb4c6UL, 0x67ccfd4a74ab3dbfUL, 0x289c8961bcb410bbUL, 0x5244f9a98c8199c2UL,
    0xdd2c68f1dcdf0249UL, 0xa7f41839ecea8b30UL, 0x438c80a64ce15841UL, 0x3954f06e7cd4d138UL, 0xb63c61362c8a4ab3UL,
    0xcce411fe1cbfc3caUL, 0x83b465d5d4a0eeceUL, 0xf96c151de49567b7UL, 0x76048445b4cbfc3cUL, 0x0cdcf48d84fe7545UL,
    0x6fbd6d5ebd3716b7UL, 0x15651d968d029fceUL, 0x9a0d8ccedd5c0445UL, 0xe0d5fc06ed698d3cUL, 0xaf85882d2576a038UL,
    0xd55df8e515432941UL, 0x5a3569bd451db2caUL, 0x20ed197575283bb3UL, 0xc49581ead523e8c2UL, 0xbe4df122e51661bbUL,
    0x3125607ab548fa30UL, 0x4bfd10b2857d7349UL, 0x04ad64994d625e4dUL, 0x7e7514517d57d734UL, 0xf11d85092d094cbfUL,
    0x8bc5f5c11d3cc5c6UL, 0x12b5926535897936UL, 0x686de2ad05bcf04fUL, 0xe70573f555e26bc4UL, 0x9ddd033d65d7e2bdUL,
    0xd28d7716adc8cfb9UL, 0xa85507de9dfd46c0UL, 0x273d9686cda3dd4bUL, 0x5de5e64efd965432UL, 0xb99d7ed15d9d8743UL,
    0xc3450e196da80e3aUL, 0x4c2d9f413df695b1UL, 0x36f5ef890dc31cc8UL, 0x79a59ba2c5dc31ccUL, 0x037deb6af5e9b8b5UL,
    0x8c157a32a5b7233eUL, 0xf6cd0afa9582aa47UL, 0x4ad64994d625e4daUL, 0x300e395ce6106da3UL, 0xbf66a804b64ef628UL,
    0xc5bed8cc867b7f51UL, 0x8aeeace74e645255UL, 0xf036dc2f7e51db2cUL, 0x7f5e4d772e0f40a7UL, 0x05863dbf1e3ac9deUL,
    0xe1fea520be311aafUL, 0x9b26d5e88e0493d6UL, 0x144e44b0de5a085dUL, 0x6e963478ee6f8124UL, 0x21c640532670ac20UL,
    0x5b1e309b16452559UL, 0xd476a1c3461bbed2UL, 0xaeaed10b762e37abUL, 0x37deb6af5e9b8b5bUL, 0x4d06c6676eae0222UL,
    0xc26e573f3ef099a9UL, 0xb8b627f70ec510d0UL, 0xf7e653dcc6da3dd4UL, 0x8d3e2314f6efb4adUL, 0x0256b24ca6b12f26UL,
    0x788ec2849684a65fUL, 0x9cf65a1b368f752eUL, 0xe62e2ad306bafc57UL, 0x6946bb8b56e467dcUL, 0x139ecb4366d1eea5UL,
    0x5ccebf68aecec3a1UL, 0x2616cfa09efb4ad8UL, 0xa97e5ef8cea5d153UL, 0xd3a62e30fe90582aUL, 0xb0c7b7e3c7593bd8UL,
    0xca1fc72bf76cb2a1UL, 0x45775673a732292aUL, 0x3faf26bb9707a053UL, 0x70ff52905f188d57UL, 0x0a2722586f2d042eUL,
    0x854fb3003f739fa5UL, 0xff97c3c80f4616dcUL, 0x1bef5b57af4dc5adUL, 0x61372b9f9f784cd4UL, 0xee5fbac7cf26d75fUL,
    0x9487ca0fff135e26UL, 0xdbd7be24370c7322UL, 0xa10fceec0739fa5bUL, 0x2e675fb4576761d0UL, 0x54bf2f7c6752e8a9UL,
    0xcdcf48d84fe75459UL, 0xb71738107fd2dd20UL, 0x387fa9482f8c46abUL, 0x42a7d9801fb9cfd2UL, 0x0df7adabd7a6e2d6UL,
    0x772fdd63e7936bafUL, 0xf8474c3bb7cdf024UL, 0x829f3cf387f8795dUL, 0x66e7a46c27f3aa2cUL, 0x1c3fd4a417c62355UL,
    0x935745fc4798b8deUL, 0xe98f353477ad31a7UL, 0xa6df411fbfb21ca3UL, 0xdc0731d78f8795daUL, 0x536fa08fdfd90e51UL,
    0x29b7d047efec8728UL};

static inline uint64_t crc64(uint64_t crc, const unsigned char *s, uint64_t l)
{
    uint64_t j;
    for (j = 0; j < l; j++)
    {
        uint8_t byte = s[j];
        uint8_t i = (uint8_t)crc ^ byte;
        crc = crc64_tab[i] ^ (crc >> 8);
    }
    return crc;
}

static __always_inline int submit_sock_record(struct sock_info *sinfo)
{
    struct record_sock *r;
    __u32 cnt;
    __u32 zero = 0;

    r = bpf_map_lookup_elem(&heap_record_sock, &zero);
    if (!r)
    {
        bpf_printk("WARNING: Failed to allocate new socket record for pid %u\n", sinfo->pid);
        return 0;
    }

    __u32 output_len = sizeof(*r);
    r->rec.pid = sinfo->pid;
    r->rec.tid = sinfo->tid;
    r->rec.ppid = sinfo->ppid;
    r->rec.uid = sinfo->uid;
    r->rec.gid = sinfo->gid;
    r->rec.age = bpf_ktime_get_ns() - sinfo->ts_proc;
    __builtin_memset(r->rec.proc, 0, sizeof(r->rec.proc));
    bpf_probe_read_kernel_str(r->rec.proc, sizeof(r->rec.proc), sinfo->proc);
    __builtin_memset(r->rec.comm, 0, sizeof(r->rec.comm));
    bpf_probe_read_kernel_str(r->rec.comm, sizeof(r->rec.comm), sinfo->comm);
    __builtin_memset(r->rec.comm_parent, 0, sizeof(r->rec.comm_parent));
    bpf_probe_read_kernel_str(r->rec.comm_parent, sizeof(r->rec.comm_parent), sinfo->comm_parent);

    r->rec.ts_first = sinfo->ts_first;
    r->rec.ts = bpf_ktime_get_ns();
    r->family = sinfo->family;
    r->role = sinfo->role;
    r->proto = sinfo->proto;
    r->state = sinfo->state;
    r->rx_ts_first = sinfo->rx_ts_first;
    r->rx_ts = sinfo->rx_ts;
    r->tx_ts_first = sinfo->tx_ts_first;
    r->tx_ts = sinfo->tx_ts;
    if (sinfo->proto == IPPROTO_TCP)
    {
        bpf_probe_read_kernel(r->laddr, 16, sinfo->laddr);
        bpf_probe_read_kernel(r->raddr, 16, sinfo->raddr);
        r->lport = sinfo->lport;
        r->rport = sinfo->rport;
        r->tx_ifindex = sinfo->tx_ifindex;
        r->rx_ifindex = sinfo->rx_ifindex;
        r->rx_data_packets = sinfo->rx_data_packets;
        r->rx_packets = sinfo->rx_packets;
        r->rx_packets_queued = sinfo->rx_packets_queued;
        r->rx_packets_drop = sinfo->rx_packets_drop[1];
        r->rx_packets_recorder = sinfo->rx_packets_recorder[1];
        r->rx_packets_frag = sinfo->rx_packets_frag;
        r->rx_bytes = sinfo->rx_bytes;
        r->rx_ttl = r->rx_packets ? sinfo->rx_ttl / r->rx_packets : 0;
        r->tx_data_packets = sinfo->tx_data_packets;
        r->tx_packets = sinfo->tx_packets;
        r->tx_packets_retrans = sinfo->tx_packets_retrans[1];
        r->tx_packets_dups = sinfo->tx_packets_dups[1];
        r->tx_bytes = sinfo->tx_bytes;
        r->tx_bytes_acked = sinfo->tx_bytes_acked[1];
        r->tx_bytes_retrans = sinfo->tx_bytes_retrans[1];
        r->tx_rto = sinfo->tx_rto;
        r->rtt = sinfo->rtt;
        if (sinfo->app_msg.cnt) {
            bpf_probe_read_kernel(&r->app_msg, sizeof(r->app_msg), &sinfo->app_msg);
        }

        /* update intermediate counters needed after tcp timeouts */
        sinfo->rx_data_packets = 0;
        sinfo->rx_packets = 0;
        sinfo->rx_packets_frag = 0;
        sinfo->rx_packets_drop[0] += r->rx_packets_drop;
        sinfo->rx_packets_recorder[0] += r->rx_packets_recorder;
        sinfo->rx_bytes = 0;
        sinfo->rx_ttl = 0;
        sinfo->rx_ts_first = sinfo->rx_ts = 0;
        sinfo->tx_data_packets = 0;
        sinfo->tx_packets = 0;
        sinfo->tx_packets_retrans[0] += r->tx_packets_retrans;
        sinfo->tx_packets_dups[0] += r->tx_packets_dups;
        sinfo->tx_bytes = 0;
        sinfo->tx_bytes_acked[0] += r->tx_bytes_acked;
        sinfo->tx_bytes_retrans[0] += r->tx_bytes_retrans;
        sinfo->tx_rto = 0;
        sinfo->rtt = 0;
        sinfo->tx_ts_first = sinfo->tx_ts = 0;
        sinfo->app_msg.cnt = 0;
    }
    else if (sinfo->proto == IPPROTO_UDP)
    {
        bpf_probe_read_kernel(r->laddr, 16, sinfo->laddr);
        bpf_probe_read_kernel(r->raddr, 16, sinfo->raddr);
        r->lport = sinfo->lport;
        r->rport = sinfo->rport;
        r->tx_ifindex = sinfo->tx_ifindex;
        r->rx_ifindex = sinfo->rx_ifindex;
        r->rx_packets = sinfo->rx_packets;
        r->rx_packets_queued = sinfo->rx_packets_queued;
        r->rx_packets_drop = sinfo->rx_packets_drop[1];
        r->rx_packets_recorder = sinfo->rx_packets_recorder[1];
        r->rx_bytes = sinfo->rx_bytes;
        r->rx_ttl = r->rx_packets ? sinfo->rx_ttl / r->rx_packets : 0;
        r->tx_data_packets = sinfo->tx_data_packets;
        r->tx_packets = sinfo->tx_packets;
        r->tx_bytes = sinfo->tx_bytes;
        r->app_msg.cnt = sinfo->app_msg.cnt;
        if (sinfo->app_msg.cnt) {
            bpf_probe_read_kernel(&r->app_msg, sizeof(r->app_msg), &sinfo->app_msg);
        }
        sinfo->app_msg.cnt = 0;
    }
    else
    {
        r->rx_packets = sinfo->rx_packets;
        r->rx_bytes = sinfo->rx_bytes;
        r->tx_packets = sinfo->tx_packets;
        r->tx_bytes = sinfo->tx_bytes;

        /* reset counters */
        sinfo->rx_packets = 0;
        sinfo->rx_bytes = 0;
        sinfo->tx_packets = 0;
        sinfo->tx_bytes = 0;
        sinfo->app_msg.cnt = 0;
    }

    if (bpf_ringbuf_output(&ringbuf_records, r, output_len, 0))
        bpf_printk("WARNING: Failed to submit %s socket record to ringbuffer for sock %u", GET_ROLE_STR(sinfo->role), sinfo->pid);

    return 0;
}

static __always_inline void expire_sock_records()
{
    struct sock_info *sq_sinfo;
    struct sock_queue sq = {0};
    struct stats *s;
    __u64 qlen = 0;
    __u64 ts_now;
    __u32 zero = 0;
    int cnt;

    s = bpf_map_lookup_elem(&stats, &zero);
    if (s)
    {
        qlen = s->q_push_added + s->q_push_updated - s->q_pop_expired - s->q_pop_ignored - s->q_pop_missed;
        if (!qlen)
            return;
    }
    ts_now = bpf_ktime_get_ns();
    for (cnt = 0; cnt < SOCK_EXP_MAX; cnt++)
    {
        if (s && cnt >= qlen)
            break;
        if (!bpf_map_pop_elem(&queue_socks, &sq))
        {
            sq_sinfo = bpf_map_lookup_elem(&hash_socks, &sq.key);
            if (sq_sinfo)
            {
                __u64 ts_last = MAX(sq_sinfo->rx_ts, sq_sinfo->tx_ts);
                if (sq.ts < ts_last)
                {
                    if (s)
                        s->q_pop_ignored++;
                }
                else if (sq.ts > ts_last)
                {
                    if (s)
                        s->q_pop_missed++;
                }
                else if (ts_now - sq.ts > SOCK_IDLE_TIMEOUT * (u64)1e9 ||
                         ts_now - sq_sinfo->ts_first > SOCK_ACTIVE_TIMEOUT * (u64)1e9)
                {
                    if (sq_sinfo->proto == IPPROTO_UDP && ts_now - sq.ts > SOCK_IDLE_TIMEOUT * (u64)1e9)
                        sq_sinfo->state = UDP_CLOSE;
                    submit_sock_record(sq_sinfo);
                    if (s)
                        s->q_pop_expired++;
                    /* tcp will be deleted by tcp_close */
                    if (sq_sinfo->proto == IPPROTO_UDP)
                    {
                        if (bpf_map_delete_elem(&hash_socks, &sq.key))
                            bpf_printk("WARNING: Failed to delete udp socket %u for pid %u\n", sq.key, sq_sinfo->pid);
                    }
                }
                else
                {
                    if (!bpf_map_push_elem(&queue_socks, &sq, BPF_EXIST))
                    {
                        if (s)
                            s->q_push_readded++;
                    }
                }
            }
        }
    }
}

static __always_inline int handle_udp_event(void *ctx, struct sock_event_info *event)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct sk_buff *skb;
    struct skb_shared_info *skbinfo;
    struct sock *sock;
    struct iphdr *iphdr = NULL;
    struct ipv6hdr *ipv6hdr = NULL;
    struct udphdr *udphdr = NULL;
    u8 *data = NULL;
    struct sock_info *sinfo;
    struct sock_queue sq = {0};
    struct stats *s;
    __u16 gso_segs;
    char comm[TASK_COMM_LONG_LEN] = {0};
    __u32 bindlock;
    __u32 data_len;
    __u16 family;
    char *func;
    bool isrx;
    __u16 lport;
    __u16 rport;
    __u64 key;
    __u64 ts_now;
    __u32 zero = 0;
    __u16 num = 0;
    int cnt;
    int cntp;
    int cnts;

    sock = event->sock;
    skb = event->skb;
    family = event->family;
    isrx = event->isrx;
    func = event->func;

    if (pid == self_pid)
        return 0;

    if (family == AF_INET)
        iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header));
    else if (family == AF_INET6)
        ipv6hdr = (struct ipv6hdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header));
    else
        return 0;
    udphdr = (struct udphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, transport_header));
    data_len = isrx ? bpf_ntohs(BPF_CORE_READ(udphdr, len)) - sizeof(udphdr)
                    : BPF_CORE_READ(skb, len) -
                          (BPF_CORE_READ(skb, transport_header) - BPF_CORE_READ(skb, network_header)) - sizeof(udphdr);
    data = (u8 *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, transport_header) + sizeof(*udphdr));

    if (isrx)
    {
        lport = bpf_ntohs(BPF_CORE_READ(udphdr, source));
        rport = bpf_ntohs(BPF_CORE_READ(udphdr, dest));
    }
    else
    {
        lport = event->lport;
        rport = event->rport;
    }

    if (lport == 0 || rport == 0)
        return 0;

    skbinfo = (struct skb_shared_info *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, end));
    gso_segs = BPF_CORE_READ(skbinfo, gso_segs);

    bpf_probe_read_kernel_str(comm, sizeof(comm), BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name));

    /* clean expired records */
    expire_sock_records();

    /* lookup and update socket */
    key = KEY_SOCK(BPF_CORE_READ(sock, __sk_common.skc_hash));
    sinfo = bpf_map_lookup_elem(&hash_socks, &key);
    s = bpf_map_lookup_elem(&stats, &zero);
    ts_now = bpf_ktime_get_ns();
    if (sinfo)
    {
        if (sinfo->state == UDP_NEW)
        {
            sinfo->state = UDP_ESTABLISHED;
        }
        /* update existing udp socket */
        if (isrx)
        {
            sinfo->rx_ts = ts_now;
            if (!sinfo->rx_ts_first)
            {
                sinfo->rx_ts_first = sinfo->rx_ts;
                sinfo->rx_packets_drop[0] = BPF_CORE_READ(sock, sk_drops.counter);
            }
            else
                sinfo->rx_packets_drop[1] = BPF_CORE_READ(sock, sk_drops.counter) - sinfo->rx_packets_drop[0];
            if (gso_segs > 1)
                sinfo->rx_packets += gso_segs;
            else
                sinfo->rx_packets++;
            sinfo->rx_bytes += data_len;
            sinfo->rx_packets_queued = BPF_CORE_READ(sock, sk_backlog.rmem_alloc.counter) -
                                       BPF_CORE_READ((struct udp_sock *)sock, forward_deficit);
            sinfo->rx_packets_frag += BPF_CORE_READ(skbinfo, nr_frags);
            if (!sinfo->rx_ifindex)
                sinfo->rx_ifindex = BPF_CORE_READ(skb, skb_iif);
            if (sinfo->family == AF_INET)
                sinfo->rx_ttl += BPF_CORE_READ(iphdr, ttl);
            else
                sinfo->rx_ttl += BPF_CORE_READ(ipv6hdr, hop_limit);
        }
        else
        {
            sinfo->tx_ts = ts_now;
            if (!sinfo->tx_ts_first)
                sinfo->tx_ts_first = sinfo->tx_ts;
            if (gso_segs > 1)
                sinfo->tx_packets += gso_segs;
            else
                sinfo->tx_packets++;
            sinfo->tx_bytes += data_len;
            if (!sinfo->tx_ifindex)
            {
                struct dst_entry *dst = (struct dst_entry *)(BPF_CORE_READ(skb, _skb_refdst) & SKB_DST_PTRMASK);
                sinfo->tx_ifindex = BPF_CORE_READ(dst, dev, ifindex);
            }
        }
        sinfo->state = BPF_CORE_READ(sock, __sk_common.skc_state);

        if (sinfo->app_msg.cnt < APP_MSG_MAX)
        {
            num = sinfo->app_msg.cnt++;
            sinfo->app_msg.ts[num] = ts_now;
            sinfo->app_msg.len[num] = data_len;
            sinfo->app_msg.isrx[num] = isrx;
            bpf_probe_read_kernel(sinfo->app_msg.data[num], MIN((__u16)data_len, sizeof(sinfo->app_msg.data[num])), data);

            if (sinfo->app_msg.cnt >= APP_MSG_MAX)
            {
                submit_sock_record(sinfo);
                if (bpf_map_delete_elem(&hash_socks, &key))
                    bpf_printk("WARNING: Failed to delete udp socket %u for pid %u\n", key, sinfo->pid);
            }
        }

        if (!bpf_map_update_elem(&hash_socks, &key, sinfo, BPF_ANY))
        {
            sq.key = key;
            sq.ts = ts_now;
            if (!bpf_map_push_elem(&queue_socks, &sq, BPF_EXIST))
            {
                if (s)
                    s->q_push_updated++;
            }
        }
        else
            bpf_printk("WARNING: Failed to update udp socket %u for pid %u\n", key, sinfo->pid);
    }
    else
    {
        sinfo = bpf_map_lookup_elem(&heap_sock, &zero);
        if (!sinfo)
        {
            bpf_printk("WARNING: Failed to allocate heap for udp socket %u for pid %u\n", key, pid);
            return 0;
        }
        sinfo->pid = pid;
        sinfo->tid = bpf_get_current_pid_tgid();
        sinfo->ppid = BPF_CORE_READ(task, real_parent, tgid);
        sinfo->uid = bpf_get_current_uid_gid();
        sinfo->gid = bpf_get_current_uid_gid() >> 32;
        bpf_get_current_comm(&sinfo->proc, sizeof(sinfo->proc));
        bpf_probe_read_kernel_str(&sinfo->comm, sizeof(sinfo->comm), BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name));
        bpf_probe_read_kernel_str(&sinfo->comm_parent, sizeof(sinfo->comm_parent), BPF_CORE_READ(task, real_parent, mm, exe_file, f_path.dentry, d_name.name));
        sinfo->ts_proc = BPF_CORE_READ(task, start_time);
        sinfo->family = family;
        sinfo->proto = IPPROTO_UDP;
        sinfo->state = UDP_NEW;
        if (family == AF_INET)
        {
            __u32 laddr = isrx ? BPF_CORE_READ(iphdr, daddr) : BPF_CORE_READ(iphdr, saddr);
            __u32 raddr = isrx ? BPF_CORE_READ(iphdr, saddr) : BPF_CORE_READ(iphdr, daddr);
            bpf_probe_read_kernel(sinfo->laddr, sizeof(laddr), &laddr);

            bpf_probe_read_kernel(sinfo->raddr, sizeof(raddr), &raddr);
        }
        else
        {
            bpf_probe_read_kernel(sinfo->laddr, sizeof(sinfo->laddr), BPF_CORE_READ(ipv6hdr, saddr.in6_u.u6_addr8));
            bpf_probe_read_kernel(sinfo->raddr, sizeof(sinfo->raddr), BPF_CORE_READ(ipv6hdr, daddr.in6_u.u6_addr8));
        }
        sinfo->lport = lport;
        sinfo->rport = rport;
        sinfo->ts_first = ts_now;
        if (isrx)
        {
            struct skb_shared_info *skbinfo = (struct skb_shared_info *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, end));
            sinfo->rx_ifindex = BPF_CORE_READ(skb, skb_iif);
            sinfo->rx_ts = sinfo->rx_ts_first = sinfo->ts_first;
            if (gso_segs > 1)
                sinfo->rx_packets = gso_segs;
            else
                sinfo->rx_packets = 1;
            sinfo->rx_bytes = data_len;
            sinfo->rx_packets_queued = BPF_CORE_READ(sock, sk_backlog.rmem_alloc.counter) -
                                       BPF_CORE_READ((struct udp_sock *)sock, forward_deficit);
            sinfo->rx_packets_frag = BPF_CORE_READ(skbinfo, nr_frags);
            if (sinfo->family == AF_INET)
                sinfo->rx_ttl = BPF_CORE_READ(iphdr, ttl);
            else
                sinfo->rx_ttl = BPF_CORE_READ(ipv6hdr, hop_limit);
            sinfo->tx_packets = 0;
            sinfo->tx_bytes = 0;
        }
        else
        {
            struct dst_entry *dst = (struct dst_entry *)(BPF_CORE_READ(skb, _skb_refdst) & SKB_DST_PTRMASK);
            sinfo->tx_ifindex = BPF_CORE_READ(dst, dev, ifindex);
            sinfo->tx_ts = sinfo->tx_ts_first = sinfo->ts_first;
            if (gso_segs > 1)
                sinfo->tx_packets = gso_segs;
            else
                sinfo->tx_packets = 1;
            sinfo->tx_bytes = data_len;
            sinfo->rx_packets = 0;
            sinfo->rx_bytes = 0;
            sinfo->rx_packets_frag = 0;
            sinfo->rx_ttl = 0;
        }
        sinfo->app_msg.cnt = 0;
        if (sinfo->app_msg.cnt < APP_MSG_MAX)
        {
            num = sinfo->app_msg.cnt++;
            sinfo->app_msg.ts[num] = ts_now;
            sinfo->app_msg.len[num] = data_len;
            sinfo->app_msg.isrx[num] = isrx;
            bpf_probe_read_kernel(sinfo->app_msg.data[num], MIN((__u16)data_len, sizeof(sinfo->app_msg.data[num])), data);
        }
        else
        {
        }

        sinfo->role = ROLE_UDP_CLIENT;
        if (isrx)
        {
            bindlock = BPF_CORE_READ_BITFIELD_PROBED(sock, sk_userlocks) & SOCK_BINDPORT_LOCK;
            if (bindlock || (family == AF_INET && !BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr)))
                sinfo->role = ROLE_UDP_SERVER;
        }

        if (!bpf_map_update_elem(&hash_socks, &key, sinfo, BPF_ANY))
        {
            sq.key = key;
            sq.ts = ts_now;
            if (!bpf_map_push_elem(&queue_socks, &sq, BPF_EXIST))
            {
                if (s)
                    s->q_push_added++;
            }
        }
        else
        {
            bpf_printk("WARNING: Failed to update udp socket %u for pid %u\n", key, sinfo->pid);
        }
    }
    return 0;
}

SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(skb_consume_udp, struct sock *sock, struct sk_buff *skb, int len)
{
    u16 family;
    if (BPF_CORE_READ(skb, protocol) == bpf_htons(ETH_P_IP))
        family = AF_INET;
    else if (BPF_CORE_READ(skb, protocol) == bpf_htons(ETH_P_IPV6))
        family = AF_INET6;

    if (!sock)
        sock = BPF_CORE_READ(skb, sk);

    if (len < 0 || !(family == AF_INET || family == AF_INET6))
        return 0;

    struct sock_event_info event = {sock, skb, family, 0, 0, NULL, true, "skb_consume_udp"};
    handle_udp_event(ctx, &event);

    return 0;
}

SEC("kprobe/udp_send_skb")
int BPF_KPROBE(udp_send_skb, struct sk_buff *skb, struct flowi4 *fl4, struct inet_cork *cork)
{
    __u16 family = BPF_CORE_READ(skb, sk, __sk_common.skc_family);
    struct sock *sock = BPF_CORE_READ(skb, sk);
    __u16 sport = bpf_ntohs(BPF_CORE_READ(fl4, uli.ports.sport));
    __u16 dport = bpf_ntohs(BPF_CORE_READ(fl4, uli.ports.dport));

    if (!sock || family != AF_INET)
        return 0;

    struct sock_event_info event = {sock, skb, family, sport, dport, NULL, false, "udp_send_skb"};
    handle_udp_event(ctx, &event);
    return 0;
}

SEC("kprobe/udp_v6_send_skb")
int BPF_KPROBE(udp_v6_send_skb, struct sk_buff *skb, struct flowi6 *fl6, struct inet_cork *cork)
{
    __u16 family = BPF_CORE_READ(skb, sk, __sk_common.skc_family);
    struct sock *sock = BPF_CORE_READ(skb, sk);
    __u16 sport = bpf_ntohs(BPF_CORE_READ(fl6, uli.ports.sport));
    __u16 dport = bpf_ntohs(BPF_CORE_READ(fl6, uli.ports.dport));

    if (!sock || family != AF_INET6)
        return 0;

    struct sock_event_info event = {sock, skb, family, sport, dport, NULL, false, "udp_v6_send_skb"};
    handle_udp_event(ctx, &event);

    return 0;
}

static __always_inline int handle_tcp_event(void *ctx, struct sock_event_info *event)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct sock_info *sinfo;
    struct sock_tuple *stuple;
    struct sock *sock;
    char comm[TASK_COMM_LONG_LEN] = {0};
    __u16 family;
    __u8 tcp_state_old;
    __u8 tcp_state;
    char *func;
    __u64 key;
    __u64 key_alt;
    __u32 zero = 0;
    __u32 cnt;

    if (pid == self_pid)
        return 0;

    bpf_probe_read_kernel_str(comm, sizeof(comm), BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name));
    sock = event->sock;
    family = event->family;
    func = event->func;

    if (event->args && !sock)
    {
        struct trace_event_raw_inet_sock_set_state *args = event->args;

        /* get socket and ports */
        sock = (struct sock *)BPF_CORE_READ(args, skaddr);
        key = KEY_SOCK(BPF_CORE_READ(sock, __sk_common.skc_hash));
        stuple = bpf_map_lookup_elem(&heap_tuple, &zero);
        if (!stuple)
        {
            bpf_printk("WARNING: Failed to allocate heap for tcp socket %u for pid %u\n", key, pid);
            return 0;
        }

        if (family == AF_INET)
        {
            bpf_probe_read_kernel(stuple->laddr, sizeof(args->saddr), BPF_CORE_READ(args, saddr));
            bpf_probe_read_kernel(stuple->raddr, sizeof(args->daddr), BPF_CORE_READ(args, daddr));
        }
        else
        {
            bpf_probe_read_kernel(stuple->laddr, sizeof(args->saddr_v6), BPF_CORE_READ(args, saddr_v6));
            bpf_probe_read_kernel(stuple->raddr, sizeof(args->daddr_v6), BPF_CORE_READ(args, daddr_v6));
        }
        stuple->lport = BPF_CORE_READ(args, sport);
        stuple->rport = BPF_CORE_READ(args, dport);
        stuple->proto = IPPROTO_TCP;
        if (bpf_map_update_elem(&hash_tuples, stuple, &key, BPF_ANY))
            bpf_printk("WARNING: Failed to update tcp server stuple for key %lx and pid %u\n", key, pid);

        tcp_state_old = BPF_CORE_READ(args, oldstate);
        tcp_state = BPF_CORE_READ(args, newstate);

        if (tcp_state_old == TCP_SYN_RECV && tcp_state == TCP_ESTABLISHED)
        {
            key_alt = crc64(0, (const u8 *)stuple, sizeof(*stuple));
            sinfo = bpf_map_lookup_elem(&hash_socks, &key_alt);
            if (!sinfo)
            {
                sinfo = bpf_map_lookup_elem(&heap_sock, &zero);
                if (!sinfo)
                {
                    bpf_printk("WARNING: Failed to allocate new tcp server socket %u for pid %u\n", key_alt, pid);
                    return 0;
                }
                sinfo->app_msg.cnt = 0;
            }
            sinfo->pid = 0;
            sinfo->tid = 0;
            sinfo->ppid = 0;
            sinfo->uid = 0;
            sinfo->gid = 0;
            sinfo->proc[0] = 0;
            sinfo->comm[0] = 0;
            sinfo->comm_parent[0] = 0;
            sinfo->ts_proc = 0;
            sinfo->family = family;
            sinfo->proto = IPPROTO_TCP;
            sinfo->role = ROLE_TCP_SERVER;
            sinfo->state = tcp_state;
            bpf_probe_read_kernel(sinfo->laddr, sizeof(sinfo->laddr), stuple->laddr);
            bpf_probe_read_kernel(sinfo->raddr, sizeof(sinfo->raddr), stuple->raddr);
            sinfo->lport = stuple->lport;
            sinfo->rport = stuple->rport;
            sinfo->rx_ts = bpf_ktime_get_ns();
            sinfo->rx_ts_first = sinfo->rx_ts;
            sinfo->ts_first = sinfo->rx_ts;
            sinfo->tx_ts = bpf_ktime_get_ns();
            sinfo->tx_ts_first = sinfo->tx_ts;
            if (bpf_map_update_elem(&hash_socks, &key, sinfo, BPF_ANY))
            {
                bpf_printk("WARNING: Failed to prepare new tcp server socket %u for pid %u\n", key_alt, pid);
            }
        }
        else if (tcp_state_old == TCP_CLOSE && tcp_state == TCP_SYN_SENT)
        {
            sinfo = bpf_map_lookup_elem(&heap_sock, &zero);
            if (!sinfo)
            {
                bpf_printk("WARNING: Failed to allocate new tcp client socket %u for pid %u\n", key, pid);
                return 0;
            }
            sinfo->family = family;
            sinfo->proto = IPPROTO_TCP;
            sinfo->role = ROLE_TCP_CLIENT;
            sinfo->state = tcp_state;
            bpf_probe_read_kernel(sinfo->laddr, sizeof(sinfo->laddr), stuple->laddr);
            bpf_probe_read_kernel(sinfo->raddr, sizeof(sinfo->raddr), stuple->raddr);
            sinfo->lport = stuple->lport;
            sinfo->rport = stuple->rport;
            sinfo->rx_ts = bpf_ktime_get_ns();
            sinfo->rx_ts_first = sinfo->rx_ts;
            sinfo->ts_first = sinfo->rx_ts;
            sinfo->rx_ts = bpf_ktime_get_ns();
            sinfo->rx_ts_first = sinfo->rx_ts;
            sinfo->pid = pid;
            sinfo->tid = bpf_get_current_pid_tgid();
            sinfo->ppid = BPF_CORE_READ(task, real_parent, tgid);
            sinfo->uid = bpf_get_current_uid_gid();
            sinfo->gid = bpf_get_current_uid_gid() >> 32;
            bpf_get_current_comm(&sinfo->proc, sizeof(sinfo->proc));
            bpf_probe_read_kernel_str(&sinfo->comm, sizeof(sinfo->comm), BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name));
            bpf_probe_read_kernel_str(&sinfo->comm_parent, sizeof(sinfo->comm_parent), BPF_CORE_READ(task, real_parent, mm, exe_file, f_path.dentry, d_name.name));
            sinfo->ts_proc = BPF_CORE_READ(task, start_time);
            sinfo->app_msg.cnt = 0;
            key_alt = crc64(0, (const u8 *)stuple, sizeof(*stuple));
            if (bpf_map_update_elem(&hash_socks, &key_alt, sinfo, BPF_ANY))
                bpf_printk("WARNING: Failed to prepare new tcp client socket for alt key %lx for pid %u\n", key_alt, pid);
        }
        else if (tcp_state_old == TCP_SYN_SENT && tcp_state == TCP_ESTABLISHED)
        {
            key_alt = crc64(0, (const u8 *)stuple, sizeof(*stuple));
            sinfo = bpf_map_lookup_elem(&hash_socks, &key_alt);
            if (!sinfo)
            {
                /* try again with rport */
                u16 rport = stuple->rport;
                stuple->rport = 0;
                key_alt = crc64(0, (const u8 *)stuple, sizeof(*stuple));
                stuple->rport = rport;
                sinfo = bpf_map_lookup_elem(&hash_socks, &key_alt);
                if (!sinfo)
                {
                    // bpf_printk("WARNING: Failed to find tcp client socket for alt key %lx for pid %u\n", key_alt, pid);
                    return 0;
                }
            }
            sinfo->state = tcp_state;
            if (bpf_map_update_elem(&hash_socks, &key, sinfo, BPF_ANY))
            {
                bpf_printk("WARNING: Failed to update tcp client socket for alt key %lx for pid %u\n", key_alt, pid);
            }
        }
        else if ((tcp_state_old == TCP_LAST_ACK && tcp_state == TCP_CLOSE) ||
                 (tcp_state_old == TCP_FIN_WAIT2 && tcp_state == TCP_CLOSE))
        {
            sinfo = bpf_map_lookup_elem(&hash_socks, &key);
            if (!sinfo)
            {
                // bpf_printk("WARNING: Failed lookup to delete tcp socket for key %lx, lport %u for pid %u\n", key, stuple->lport, pid);
                return 0;
            }
            sinfo->state = tcp_state;
            submit_sock_record(sinfo);
            if (bpf_map_delete_elem(&hash_socks, &key))
            {
                bpf_printk("WARNING: Failed to delete tcp socket for key %lx, lport %u for pid %u\n", key, stuple->lport, pid);
            }
        }
    }
    else
    {
        key = KEY_SOCK(BPF_CORE_READ(sock, __sk_common.skc_hash));
        sinfo = bpf_map_lookup_elem(&hash_socks, &key);
        if (!sinfo)
        {
            return 0;
        }
        sinfo->pid = pid;
        sinfo->tid = bpf_get_current_pid_tgid();
        sinfo->ppid = BPF_CORE_READ(task, real_parent, tgid);
        sinfo->uid = bpf_get_current_uid_gid();
        sinfo->gid = bpf_get_current_uid_gid() >> 32;
        bpf_get_current_comm(&sinfo->proc, sizeof(sinfo->proc));
        bpf_probe_read_kernel_str(&sinfo->comm, sizeof(sinfo->comm), BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name));
        bpf_probe_read_kernel_str(&sinfo->comm_parent, sizeof(sinfo->comm_parent), BPF_CORE_READ(task, real_parent, mm, exe_file, f_path.dentry, d_name.name));
        sinfo->ts_proc = BPF_CORE_READ(task, start_time);

        stuple = bpf_map_lookup_elem(&heap_tuple, &zero);
        if (!stuple)
        {
            bpf_printk("WARNING: Failed to allocate new tuple for pid %u\n", pid);
            return 0;
        }
        bpf_probe_read_kernel(stuple->laddr, sizeof(stuple->laddr), sinfo->laddr);
        bpf_probe_read_kernel(stuple->raddr, sizeof(stuple->raddr), sinfo->raddr);
        stuple->lport = sinfo->lport;
        stuple->rport = sinfo->rport;
        stuple->proto = IPPROTO_TCP;
        if (bpf_map_update_elem(&hash_tuples, stuple, &key, BPF_ANY))
            bpf_printk("WARNING: Failed to update tcp server stuple for key %lx and pid %u\n", key, pid);
        if (bpf_map_update_elem(&hash_socks, &key, sinfo, BPF_ANY))
            bpf_printk("WARNING: Failed to add tcp server socket for key %lx for pid %u\n", key, pid);
    }
    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *args)
{
    __u16 family = BPF_CORE_READ(args, family);

    if (!(family == AF_INET || family == AF_INET6))
        return 0;

    struct sock_event_info event = {NULL, NULL, family, 0, 0, args, 0, "inet_sock_set_state"};
    handle_tcp_event(NULL, &event);

    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept, struct sock *sk)
{
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (!(family == AF_INET || family == AF_INET6))
        return 0;

    struct sock_event_info event = {sk, NULL, family, 0, 0, NULL, false, "inet_csk_accept"};
    handle_tcp_event(NULL, &event);

    return 0;
}

static __always_inline int handle_tcp_packet(struct sock *sock, struct sk_buff *skb, bool isrx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct sock_info *sinfo;
    struct sock_queue sq = {0};
    struct stats *s = NULL;
    __u8 tcp_flags = 0;
    __u64 key;
    __u32 cnt;
    __u32 cntf;
    __u32 zero = 0;

    expire_sock_records();

    if (!sock)
    {
        sock = BPF_CORE_READ(skb, sk);
        if (!sock)
            return 0;
    }

    key = KEY_SOCK(BPF_CORE_READ(sock, __sk_common.skc_hash));
    sinfo = bpf_map_lookup_elem(&hash_socks, &key);
    if (sinfo)
    {
        struct skb_shared_info *skbinfo = (struct skb_shared_info *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, end));
        struct tcp_sock *tcp_sock = (struct tcp_sock *)sock;
        struct tcphdr *tcphdr = (struct tcphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, transport_header));
        struct iphdr *iphdr = NULL;
        struct ipv6hdr *ipv6hdr = NULL;
        __u32 data_len = 0;

        if (sinfo->family == AF_INET)
        {
            iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header));
            data_len = isrx ? bpf_ntohs(BPF_CORE_READ(iphdr, tot_len)) - BPF_CORE_READ_BITFIELD_PROBED(iphdr, ihl) * 4 -
                                  BPF_CORE_READ_BITFIELD_PROBED(tcphdr, doff) * 4
                            : BPF_CORE_READ(skb, len) -
                                  (BPF_CORE_READ(skb, transport_header) - BPF_CORE_READ(skb, network_header)) -
                                  BPF_CORE_READ_BITFIELD_PROBED(tcphdr, doff) * 4;
        }
        else
        {
            ipv6hdr = (struct ipv6hdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header));
            data_len =
                isrx ? bpf_ntohs(BPF_CORE_READ(ipv6hdr, payload_len)) - BPF_CORE_READ_BITFIELD_PROBED(tcphdr, doff) * 4
                     : BPF_CORE_READ(skb, len) - BPF_CORE_READ_BITFIELD_PROBED(tcphdr, doff) * 4;
        }

        __u16 gso_segs = BPF_CORE_READ(skbinfo, gso_segs);
        __u64 ts_now = bpf_ktime_get_ns();
        if (isrx)
        {
            sinfo->rx_ts = ts_now;
            if (!sinfo->ts_first)
                sinfo->ts_first = sinfo->rx_ts;
            if (!sinfo->rx_ifindex)
                sinfo->rx_ifindex = BPF_CORE_READ(skb, skb_iif);

            if (gso_segs > 1)
            {
                if (data_len)
                    sinfo->rx_data_packets += gso_segs;
                sinfo->rx_packets += gso_segs;
            }
            else
            {
                if (data_len)
                    sinfo->rx_data_packets++;
                sinfo->rx_packets++;
            }

            if (BPF_CORE_READ(sock, __sk_common.skc_state) == TCP_LISTEN)
                sinfo->rx_packets_queued = BPF_CORE_READ(sock, sk_ack_backlog);
            else if (BPF_CORE_READ(tcp_sock, rcv_nxt) > BPF_CORE_READ(tcp_sock, copied_seq))
                sinfo->rx_packets_queued = BPF_CORE_READ(tcp_sock, rcv_nxt) - BPF_CORE_READ(tcp_sock, copied_seq);
            __u32 drop = BPF_CORE_READ(sock, sk_drops.counter);
            if (drop > sinfo->rx_packets_drop[0])
                sinfo->rx_packets_drop[1] = drop - sinfo->rx_packets_drop[0];
            sinfo->rx_packets_frag += BPF_CORE_READ(skbinfo, nr_frags);
            if (data_len)
                sinfo->rx_bytes += data_len;
            if (sinfo->family == AF_INET)
                sinfo->rx_ttl = BPF_CORE_READ(iphdr, ttl);
            else
                sinfo->rx_ttl = BPF_CORE_READ(ipv6hdr, hop_limit);
        }
        else
        {
            sinfo->tx_ts = ts_now;
            if (!sinfo->tx_ts_first)
                sinfo->tx_ts_first = sinfo->tx_ts;
            if (!sinfo->tx_ifindex)
            {
                struct dst_entry *dst = (struct dst_entry *)(BPF_CORE_READ(skb, _skb_refdst) & SKB_DST_PTRMASK);
                sinfo->tx_ifindex = BPF_CORE_READ(dst, dev, ifindex);
            }
            if (gso_segs > 1)
            {
                if (data_len)
                    sinfo->tx_data_packets += gso_segs;
                sinfo->tx_packets += gso_segs;
            }
            else
            {
                if (data_len)
                    sinfo->tx_data_packets++;
                sinfo->tx_packets++;
            }
            __u32 retrans = BPF_CORE_READ(tcp_sock, total_retrans);
            if (retrans > sinfo->tx_packets_retrans[0])
                sinfo->tx_packets_retrans[1] = retrans - sinfo->tx_packets_retrans[0];
            __u32 dups = BPF_CORE_READ(tcp_sock, dsack_dups);
            if (dups > sinfo->tx_packets_dups[0])
                sinfo->tx_packets_dups[1] = dups - sinfo->tx_packets_dups[0];
            if (data_len)
                sinfo->tx_bytes += data_len;
            __u64 acked = BPF_CORE_READ(tcp_sock, bytes_acked);
            if (acked > sinfo->tx_bytes_acked[0])
                sinfo->tx_bytes_acked[1] = acked - sinfo->tx_bytes_acked[0];
            __u64 retransb = BPF_CORE_READ(tcp_sock, bytes_retrans);
            if (retransb > sinfo->tx_bytes_retrans[0])
                sinfo->tx_bytes_retrans[1] = retransb - sinfo->tx_bytes_retrans[0];

            sinfo->tx_rto = BPF_CORE_READ(tcp_sock, inet_conn.icsk_rto);
            sinfo->rtt = BPF_CORE_READ(tcp_sock, srtt_us) * 1000 / 8;
        }
        
        if (!bpf_map_update_elem(&hash_socks, &key, sinfo, BPF_ANY))
        {
            sq.key = key;
            sq.ts = ts_now;
            if (!bpf_map_push_elem(&queue_socks, &sq, BPF_EXIST))
            {
                s = bpf_map_lookup_elem(&stats, &zero);
                if (s)
                {
                    if (sinfo->rx_ts == sinfo->rx_ts_first || sinfo->tx_ts == sinfo->tx_ts_first)
                    {
                        s->q_push_added++;
                    }
                    else
                    {
                        s->q_push_updated++;
                    }
                }
            }
        }
        else
        {
            bpf_printk("WARNING: Failed to update tcp %s flags of socket %lx for pid %u", isrx ? "rx" : "tx", key,
                       sinfo->pid);
        }
    }

    return 0;
}

SEC("kprobe/tcp_v4_do_rcv")
int BPF_KPROBE(tcp_v4_do_rcv, struct sock *sock, struct sk_buff *skb)
{
    handle_tcp_packet(sock, skb, true);
    return 0;
}

SEC("kprobe/tcp_v6_do_rcv")
int BPF_KPROBE(tcp_v6_do_rcv, struct sock *sock, struct sk_buff *skb)
{
    handle_tcp_packet(sock, skb, true);
    return 0;
}

SEC("kprobe/tcp_data_queue")
int BPF_KPROBE(tcp_data_queue, struct sock *sk, struct sk_buff *skb)
{
    return 0;
}

SEC("kprobe/__ip_local_out")
int BPF_KPROBE(__ip_local_out, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    __u16 proto = BPF_CORE_READ(sk, sk_protocol);
    if (proto != IPPROTO_TCP)
        return 0;
    handle_tcp_packet(sk, skb, false);
    return 0;
}

SEC("kprobe/ip6_xmit")
int BPF_KPROBE(ip6_xmit, struct sock *sock, struct sk_buff *skb, struct flowi6 *fl6)
{
    __u16 proto = BPF_CORE_READ(sock, sk_protocol);
    if (proto != IPPROTO_TCP)
        return 0;
    handle_tcp_packet(sock, skb, false);

    return 0;
}

SEC("socket")
int handle_skb(struct __sk_buff *skb) {
    __u16 eth_proto;
    __u16 family;
    __u32 proto = 0;
    __u16 ip_len;
    __u8 iphdr_len;
    __u16 frag_ofs;
    __u32 tcphdr_ofs;
    __u8 tcphdr_len;
    __u32 udphdr_ofs;
    __u8 udphdr_len;
    __u32 data_ofs;
    __u32 data_len = 0;
    __u8 laddr[16] = {0};
    __u8 raddr[16] = {0};
    __u16 lport;
    __u16 rport;
    __u16 sport;
    __u16 dport;
    struct sock_info *sinfo = NULL;
    struct sock_tuple *stuple;
    __u32 zero = 0;
    __u64 key = 0;
    __u64 *pkey = NULL;
    __u32 cnt;
    __u32 cntp;
    __u32 cnta;
    __u32 cntl = 0;
    __u8 num;
    __u32 seq;
    bool isrx = (skb->ingress_ifindex != skb->ifindex);
    bool found = false;

    bpf_skb_load_bytes(skb, 12, &eth_proto, 2);
    eth_proto = __bpf_ntohs(eth_proto);
    if (eth_proto == ETH_P_IP)
        family = AF_INET;
    else if (eth_proto == ETH_P_IPV6)
        family = AF_INET6;
    else
        return skb->len;
    
    if (family == AF_INET) {
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, frag_off), &frag_ofs, 2);
        frag_ofs = __bpf_ntohs(frag_ofs);
        if (frag_ofs & (IP_MF | IP_OFFMASK))
            return skb->len;

        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), &proto, 1);
        if (proto != IPPROTO_TCP)
            return skb->len;
        
        bpf_skb_load_bytes(skb, ETH_HLEN, &iphdr_len, sizeof(iphdr_len));
        iphdr_len &= 0x0f;
        iphdr_len *= 4;
        if (iphdr_len < sizeof(struct iphdr))
            return skb->len;

        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, tot_len), &ip_len, sizeof(ip_len));
        ip_len = __bpf_ntohs(ip_len);
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), isrx ? laddr : raddr, 4);
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), isrx ? raddr : laddr, 4);
    } else {
        iphdr_len = sizeof(struct ipv6hdr);
        __u8 lenhdr;
        __u8 nexthdr;

        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr), &nexthdr, 2);
        for (cntl = 0; cntl < 8; cntl++) {
            if (nexthdr == IPV6_NH_TCP)
                break;
            else if (nexthdr == IPV6_NH_UDP)
                return skb->len;
            switch (nexthdr) {
                case IPV6_NH_HOP:
                case IPV6_NH_ROUTING:
                case IPV6_NH_AUTH:
                case IPV6_NH_DEST:
                    bpf_skb_load_bytes(skb, ETH_HLEN + iphdr_len, &nexthdr, 1);
                    bpf_skb_load_bytes(skb, ETH_HLEN + iphdr_len + 1, &lenhdr, 1);
                    iphdr_len += (lenhdr + 1) * 8;
                    break;
                case IPV6_NH_FRAGMENT:
                    return skb->len;
                default:
                    return skb->len;
            }
            if (!nexthdr) {
                return skb->len;
            }
        }

        proto = IPPROTO_TCP;
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, payload_len), &ip_len, sizeof(ip_len));
        ip_len = __bpf_ntohs(ip_len) + iphdr_len;
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, saddr), isrx ? laddr : raddr, 16);
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, daddr), isrx ? raddr : laddr, 16);
    }

    tcphdr_ofs = ETH_HLEN + iphdr_len;
    bpf_skb_load_bytes(skb, tcphdr_ofs + offsetof(struct tcphdr, ack_seq) + 4, &tcphdr_len, sizeof(tcphdr_len));
    tcphdr_len &= 0xf0;
    tcphdr_len >>= 4;
    tcphdr_len *= 4;
    bpf_skb_load_bytes(skb, tcphdr_ofs + offsetof(struct tcphdr, source), &sport, sizeof(sport));
    bpf_skb_load_bytes(skb, tcphdr_ofs + offsetof(struct tcphdr, dest), &dport, sizeof(dport));
    data_ofs = ETH_HLEN + iphdr_len + tcphdr_len;
    if (ip_len > iphdr_len + tcphdr_len) {
        data_len = ip_len - iphdr_len - tcphdr_len;
    } else {
        return skb->len;
    }

    lport = bpf_ntohs(isrx ? sport : dport);
    rport = bpf_ntohs(isrx ? dport : sport);
    stuple = bpf_map_lookup_elem(&heap_tuple, &zero);
    if (!stuple) {
        bpf_printk("WARNING: Failed to allocate new tuple for application message\n");
        return skb->len;
    }
    bpf_probe_read_kernel(stuple->laddr, sizeof(stuple->laddr), laddr);
    bpf_probe_read_kernel(stuple->raddr, sizeof(stuple->raddr), raddr);
    stuple->lport = lport;
    stuple->rport = rport;
    pkey = bpf_map_lookup_elem(&hash_tuples, stuple);
    if (pkey) {
        bpf_probe_read_kernel(&key, sizeof(key), pkey);
        sinfo = bpf_map_lookup_elem(&hash_socks, &key);
        if (!sinfo) {
            bpf_printk("WARNING: Failed to find socket for application message\n");
            return skb->len;
        }
    }
    if (!sinfo) {
        if (!isrx)
            return skb->len;
        /* prepare socket for alternate key when tcp server handshake not yet finished */
        sinfo = bpf_map_lookup_elem(&heap_sock, &zero);
        if (!sinfo) {
            bpf_printk("WARNING: Failed to allocate new socket for application message\n");
            return skb->len;
        }
        sinfo->pid = 0;
        sinfo->tid = 0;
        sinfo->ppid = 0;
        sinfo->uid = 0;
        sinfo->gid = 0;
        sinfo->proc[0] = 0;
        sinfo->comm[0] = 0;
        sinfo->comm_parent[0] = 0;
        sinfo->family = family;
        sinfo->role = ROLE_TCP_SERVER;
        sinfo->proto = IPPROTO_TCP;
        bpf_probe_read_kernel(sinfo->laddr, sizeof(stuple->laddr), laddr);
        bpf_probe_read_kernel(sinfo->raddr, sizeof(stuple->raddr), raddr);
        stuple->lport = lport;
        stuple->rport = rport;
        sinfo->rx_ts = bpf_ktime_get_ns();
        sinfo->rx_ts_first = sinfo->rx_ts;
        sinfo->ts_first = sinfo->rx_ts;
        sinfo->tx_ts_first = sinfo->tx_ts = 0;
        sinfo->app_msg.cnt = 0;
        key = crc64(0, (const u8 *)stuple, sizeof(*stuple));
    }
    num = sinfo->app_msg.cnt;
    if (num >= APP_MSG_MAX)
        return skb->len;
        
    bpf_skb_load_bytes(skb, tcphdr_ofs + offsetof(struct tcphdr, seq), &seq, sizeof(seq));
    sinfo->app_msg.seq[num] = bpf_ntohl(seq);
    // duplicate message
    if (num -1 >= 0 && num - 1 < APP_MSG_MAX && sinfo->app_msg.seq[num] == sinfo->app_msg.seq[num - 1])
        return skb->len;

    sinfo->app_msg.ts[num] = bpf_ktime_get_ns();
    sinfo->app_msg.len[num] = data_len;
    sinfo->app_msg.isrx[num] = isrx;
    sinfo->app_msg.cnt++;
    if (data_len >= APP_MSG_LEN_MAX)
        data_len = APP_MSG_LEN_MAX - 1;
    else if (data_len >= APP_MSG_LEN_MIN) {
        bpf_skb_load_bytes(skb, data_ofs, sinfo->app_msg.data[num], data_len);
        sinfo->app_msg.data[num][data_len] = 0;
    } else {
        return skb->len;
    }

    if (bpf_map_update_elem(&hash_socks, &key, sinfo, BPF_ANY)) {
        bpf_printk("WARNING: Failed to capture payload for %s socket %lx and pid %u\n", GET_ROLE_STR(sinfo->role), key,
                   sinfo->pid);
    }

    return skb->len;
}
