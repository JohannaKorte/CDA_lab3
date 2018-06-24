import pandas as pd
import csv
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np

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


if __name__ == '__main__':
    #preprocess(downloaded_file, data_file)
    dataframe = load_data(data_file)
    dataframe = remove_background(dataframe)
    infected_host_data = get_host_data(dataframe, infected_host_ip)
    visualize(infected_host_data)

