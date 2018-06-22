from scapy.all import rdpcap
import numpy as np

# import the dataset, may take a few minutes
packets = rdpcap('../botnet-capture-20110810-neris.pcap')

def to_src_dst(packets):
    ''' Gets the IP addresses from the packets. '''
    srcs = []
    dsts = []
    for i in range(len(packets)):
        srcs.append(packets[i].src)
        dsts.append(packets[i].dst)
    return np.column_stack((np.array(srcs), np.array(dsts)))

def make_C(pairs, ip1, ip2):
    srcbools = pairs[:,0] == ip1
    dstbools = pairs[:,1] == ip2
    return np.column_stack((srcsbools, dstsbools))

def minhash(C, num_perm=128):
    '''
    Implements MIN-WISE hashing.

    Arguments:
    C : [[Bool]] = Input matrix, contains True whenever one of the important IP-addresses appears.

    Returns:
    Double = Approximation of the Jaccard similarity
    '''
    length = len(C)
    firsts = []
    for _ in range(num_perm): # repetition because the process is stochastic
        permutation = np.random.permutation(length)
        m1_seen = False
        m2_seen = False
        first = [0,0]
        for i in permutation: # find row in which C has first True
            if not m1_seen and C[i,0]:
                first[0] = i
                m1_seen = True
            if not m2_seen and C[i,1]:
                first[1] = i
                m2_seen = True
        firsts.append(first)

    firsts = np.array(firsts)
    total = sum(map(any, C))

    return np.sum(firsts[:,0] == firsts[:,1]) / total



src_dsts = to_src_dst(packets)

# Jaccard similarity can be computed by having the sizes of each of the sets as well as their overlap
# list of unique sources and destinations and the amount of times they appear in the dataset
unique_srcs = np.unique(src_dsts[:,0], return_counts=True)
unique_dsts = np.unique(src_dsts[:,1], return_counts=True)

# list of unique source/destination pairs and the amount of times they appear in the dataset
unique_pairs = np.unique(src_dsts, return_counts=True, axis=0)


