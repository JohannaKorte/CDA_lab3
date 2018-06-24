import pandas as pd
import csv
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
import math

# PARAMETERS
downloaded_file = 'capture20110818.pcap.netflow.labeled'
data_file = 'capture20110818.csv'
infected_host_ip = '147.32.84.165'


def preprocess(inputfile, outputfile):
    """ Reads inputfile, removes all excess whitespace and writes to output .csv file. """
    with open(inputfile, 'r') as datafile:
        with open(outputfile, 'wb') as csvfile:
            next(datafile)       # skip header
            for line in datafile:
                csvfile.write(' '.join(line.split()))
                csvfile.write('\n')
    return


def load_data(inputfile):
    """ Loads data into a pandas dataframe. """
    data = pd.read_csv(inputfile, sep=" ", header=None)
    data.columns = ["date", "time", "duration", "protocol", "source_IP", "arrow", "destination_IP", "flags", "tos",
                    "packets", "bytes", "flows", "labels"]
    data.insert(0, "datetime", data["date"] + " " + data["time"])  # append date and time variables in one column
    data.drop(["arrow", "date", "time"], axis=1, inplace=True)     # Remove unnecessary columns
    data["datetime"] = pd.to_datetime(data.datetime, format="%Y-%m-%d %H:%M:%S.%f")
    return data


def remove_background(data):
    """ Removes background flows from data. """
    data.query("labels != 'Background'", inplace=True)
    return data


def get_host_data(data, ip):
    """ Gets all dataframe rows from data with as source_IP the given ip address. """
    host_data = data[data['source_IP'].str.contains(ip)]
    return host_data


def visualize(data):
    """ Visualizes the network protocol and total packets from the data in the given dataframe. """
    # Visualize packets
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.plot(data["datetime"], data["packets"], color='#00A6D6')
    plt.xlabel("Time")
    plt.ylabel("Number of packets")
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
    plt.show()
    # Visualize protocol
    plt.figure()
    pd.value_counts(data["protocol"]).plot.bar(color='#00A6D6')
    plt.xlabel('Protocol')
    plt.ylabel('Occurence in counts')
    plt.show()
    return


def discretize(data, features):
    """ Discretizes the protocol and packets features into one feature using the method presented
    by Pellegrino et al. """
    pd.options.mode.chained_assignment = None       # default='warn'
    data["code"] = 100                              # Create new column for combined code attribute
    m = []
    for feature in features:
        m.append(len(set(data[feature].tolist())))  # Save number of unique attributes per feature to list

    indices = data.index.values
    for j in indices:                               # Row indices
        code = 0
        spacesize = np.prod(m)                      # Calculate spacesize as the product of M list
        for i in range(len(features)):
            feature = features[i]                   # Get feature name
            code += mapping(data, feature, data[feature][j]) * spacesize/m[i]
            spacesize = spacesize / m[i]
        data["code"][j] = code                      # Add new value to dataframe
    return data


def mapping(data, feature, value):
    """ Given the data, the name of the feature and its value, returns a mapping to an integer
    to be used for discretization. """
    if feature == "packets":
        size = len(data["packets"])
        lowp = math.ceil(20/100 * size)
        med1p = math.ceil(40/100 * size)
        med2p = math.ceil(60/100 * size)
        highp = math.ceil(80/100 * size)
        if value <= lowp:
            mapped = 0
        elif value <= med1p:
            mapped = 1
        elif value <= med2p:
            mapped = 2
        elif value <= highp:
            mapped = 3
        else:
            mapped = 4
    elif feature == "protocol":
        if value == 'ICMP':
            mapped = 2
        elif value == 'TCP':
            mapped = 0
        elif value == 'UDP':
            mapped = 1
        else:
            return 1000000
    else:
        return 1000000
    return mapped


if __name__ == '__main__':
    # print "Preprocessing file...."
    # preprocess(downloaded_file, data_file)
    print "Loading data..."
    dataframe = load_data(data_file)
    print "Removing background flows..."
    dataframe = remove_background(dataframe)
    print "Getting infected host data..."
    infected_host_data = get_host_data(dataframe, infected_host_ip)
    print "Visualizing packets and protocol features..."
    visualize(infected_host_data)
    print "Discretizing infected host data..."
    discretize(infected_host_data, ["packets", "protocol"])
    print "Discretizing all data... (THIS MAY TAKE A FEW MINUTES)"
    discretized_data = discretize(dataframe, ["packets", "protocol"])
    print "Discretization done!"
