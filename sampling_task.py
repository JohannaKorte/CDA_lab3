from scapy.all import rdpcap
import numpy as np
from random import randrange

# import the dataset, may take a few minutes
packets = rdpcap('../botnet-capture-20110810-neris.pcap')

def to_src_dst(packets):
    ''' Gets the source and destination IP addresses from the packets. '''
    srcs = []
    dsts = []
    for i in range(len(packets)):
        srcs.append(packets[i].src)
        dsts.append(packets[i].dst)
    return np.column_stack((np.array(srcs), np.array(dsts)))

def make_C(src_dsts, ip1, ip2):
    srcbools = src_dsts[:,0] == ip1
    dstbools = src_dsts[:,1] == ip2
    return np.column_stack((srcbools, dstbools))

def minhash(C, num_perm=128):
    '''
    Implements MIN-WISE hashing, this approximated the jaccard similarity.

    Arguments:
    C : [[Bool]] = Input matrix, contains True whenever one of the important IP addresses appears.

    Returns:
    Double = Approximation of the Jaccard similarity
    '''
    length = len(C)
    firsts = []
    for _ in range(num_perm): # repetition because the process is stochastic
        m1_seen = False
        m2_seen = False
        first = [0,0]
        j = 0
        while not (m1_seen and m2_seen) and j < length: # find row in which C has first True
            i = randrange(length) # don't judge me
            j += 1
            if not m1_seen and C[i,0]:
                first[0] = i
                m1_seen = True
            if not m2_seen and C[i,1]:
                first[1] = i
                m2_seen = True
        firsts.append(first)

    firsts = np.array(firsts)

    return np.sum(firsts[:,0] == firsts[:,1]) / len(firsts)

def jaccard(C):
    ''' Calculated the Jaccard similarity. '''
    total = sum(sum(C))
    intersect = sum(map(all, C))
    return intersect / (total - intersect)

def similarity(src_dsts, ip1, ip2, num_perm=128):
    '''
    Uses both the Jaccard similarity and the MinHash to calculate the Jaccard similarity, allows for comparing the two.

    Arguments:
    src_dsts : [[String]] = list of pairs of sources and destinations.
    ip1 : String = sender IP address.
    ip2 : String = receiver IP address.
    '''
    C = make_C(src_dsts, ip1, ip2)
    jac = jaccard(C)
    mh = minhash(C, num_perm)
    return (jac, mh)

def all_sim(src_dsts, pairs, num_perm=128):
    ''' Applies similarity() to all pairs of IP addresses. '''
    return map(lambda ips: similarity(src_dsts, ips[0], ips[1], num_perm), pairs)

def squared_error(pqs):
    return sum([(pq[0]-pq[1])**2 for pq in pqs])

def benchmark(src_dsts, pairs):
    sims = []
    # get some similarities
    for i in [3, 10, 30, 100, 300, 1000]:
        print(f"Estimating jaccard with {i} loops")
        sims.append(all_sim(src_dsts, pairs, i))
    # check error
    errors = [squared_error(sim) for sim in sims]
    return errors

src_dsts = to_src_dst(packets)

# Jaccard similarity can be computed by having the sizes of each of the sets as well as their overlap
# list of unique sources and destinations and the amount of times they appear in the dataset
#unique_srcs = np.unique(src_dsts[:,0], return_counts=True)
#unique_dsts = np.unique(src_dsts[:,1], return_counts=True)

# list of unique source/destination pairs and the amount of times they appear in the dataset
unique_pairs = np.unique(src_dsts, return_counts=True, axis=0)


