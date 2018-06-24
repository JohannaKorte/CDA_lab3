import botnet_discretization as bd
import nltk
from tqdm import tqdm
import re


# PARAMETERS
downloaded_file = 'capture20110818.pcap.netflow.labeled'
data_file = 'capture20110818.csv'
infected_host_ip = '147.32.84.165'
all_infected_hosts_regex = ['147\.32\.84\.165.*', '147\.32\.84\.191.*', '147\.32\.84\.191.*', '147\.32\.84\.192.*',
                            '147\.32\.84\.193.*', '147\.32\.84\.204.*', '147\.32\.84\.205.*', '147\.32\.84\.206.*',
                            '147\.32\.84\.207.*', '147\.32\.84\.208.*', '147\.32\.84\.209.*']


def ngrams(infected_data):
    """ Given the infected training data return probabilities for all different bigram events"""
    # Find separate IP addresses
    ip_addresses = {}
    frequency_dist = {}
    frequency_dist_transfer = {}
    for host in infected_data["source_IP"]:
        if host in ip_addresses.keys():
            continue
        else:
            ip_addresses[host] = []
    # For each infected IP address make one sequence
    for index in infected_data.index:
        host = infected_data["source_IP"][index]
        code_feature = infected_data["code"][index]
        ip_addresses[host].append(code_feature)
    # Find all ngrams of length 2 and make frequency distribution
    for host in ip_addresses.keys():
        bigrams = nltk.bigrams(ip_addresses[host])
        prev_b = ''
        for b in bigrams:
            b_key = str(b)
            if b_key in frequency_dist.keys():
                frequency_dist[b_key] += 1
            else:
                frequency_dist[b_key] = 1
            if prev_b != '':
                combination = prev_b + b_key
                if combination in frequency_dist_transfer.keys():
                    frequency_dist_transfer[combination] +=1
                else:
                    frequency_dist_transfer[combination] = 1
            prev_b = b_key
    # Transform frequency distribution to probability
    total_fd = float(sum(frequency_dist.values()))
    total_fdt = float(sum(frequency_dist_transfer.values()))
    for k in frequency_dist.keys():
        frequency_dist[k] /= total_fd
    for k in frequency_dist_transfer.keys():
        frequency_dist_transfer[k] /= total_fdt
    return frequency_dist, frequency_dist_transfer


def probability(sequence, frequency_dist, frequency_dist_transfer):
    """ Given a sequence of the code variable, returns max-likelihood"""
    bigrams = list(nltk.bigrams(sequence))
    prev_b = ''
    prob = 0
    for i in range(len(bigrams)):
        b = bigrams[i]
        if i == 0:                          # calculate e.g. P((a, b))
            if b in frequency_dist.keys():
                prob = frequency_dist[b]
            else:
                return 0
        else:
            combination = prev_b + b        # calculate e.g. P((a,b) | (a, a))
            if combination in frequency_dist_transfer.keys():
                prob *= frequency_dist_transfer[combination]
            else:
                return 0
        prev_b = b
    return prob


def classify(data, fd, fdt, threshold):
    """ Takes test data and returns the amount of TN, FN, TP, FP. """
    tp, fp, tn, fn = 0, 0, 0, 0
    ip_addresses = {}
    # Remove train data from test data
    print ".....removing training data from test data"
    pattern = "147\.32\.84\.165.*"
    f = data['source_IP'].str.contains(pattern)
    data = data[~f]
    # Get separate ip addresses
    print ".....Getting IP addresses (TAKES ABOUT 25 MINUTES)"
    for host in tqdm(data["source_IP"]):
        if host in ip_addresses.keys():
            continue
        else:
            ip_addresses[host] = []
    # Make a sequence for each ip address
    print ".....Getting sequences"
    for index in tqdm(data.index):
        host = data["source_IP"][index]
        code_feature = data["code"][index]
        ip_addresses[host].append(code_feature)
    # Calculate probability for each sequence
    print ".....Calculating Probabilities"
    for i in tqdm(ip_addresses.keys()):
        ip_addresses[i] = probability(ip_addresses[i], fd, fdt)
    print ip_addresses
    # Add count to TN FN TP FP
    print ".... Getting counts"
    for i in tqdm(ip_addresses.keys()):
        if ip_addresses[i] >= threshold:  # classified as positive
            if is_infected(i):
                tp += 1
            else:
                fp += 1
        else: # classified as negative
            if is_infected(i):
                fn += 1
            else:
                tn += 1
    print "True positive:   %i\n" % tp
    print "False positive:  %i\n" % fp
    print "True negative:   %i\n" % tn
    print "False negative:  %i\n" % fn


def is_infected(i):
    """ Takes an IP adres and returns a boolean value representing whether it is infected."""
    for pattern in all_infected_hosts_regex:
        if re.findall(pattern, i) == []:
            return False
    return True


if __name__ == '__main__':
    print "Preprocessing file...."
    bd.preprocess(downloaded_file, data_file)
    print "Loading data..."
    dataframe = bd.load_data(data_file)
    print "Removing background flows..."
    dataframe = bd.remove_background(dataframe)
    print "Getting infected host data..."
    infected_host_data = bd.get_host_data(dataframe, infected_host_ip)
    print "Discretizing all data... (THIS MAY TAKE A FEW MINUTES)"
    discretized_infected_data = bd.discretize(infected_host_data, ["packets", "protocol"])
    discretized_data = bd.discretize(dataframe, ["packets", "protocol"])
    print "Discretization done!"
    print "Finding bigrams..."
    frequency_dict, frequency_dict_transfer = ngrams(discretized_infected_data)
    print "Classifying test data..."
    classify(discretized_data, frequency_dict, frequency_dict_transfer, 0.001)
    #classify(discretized_data[:500000], frequency_dict, frequency_dict_transfer, 0.001)



