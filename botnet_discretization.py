import pandas as pd
import csv

downloaded_file = 'capture20110818.pcap.netflow.labeled'
data_file = 'capture20110818.csv'


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
    data.drop(["arrow", "date", "time"], axis=1, inplace=True)     # clean up
    return data


def remove_background(data):
    """ Removes background flows from data. """
    data.query("labels != 'Background'", inplace=True)
    return data

#########

if __name__ == '__main__':
    #preprocess(downloaded_file, data_file)
    dataframe = load_data(data_file)
    dataframe = remove_background(dataframe)

