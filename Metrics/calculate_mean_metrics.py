#!/usr/bin/python

import sys
import os
import os.path
import csv

# Index General
_CIPHER_ = 0
_BLOCK_SIZE_ = 1
_KEY_SIZE_ = 2
_VERSION_ = 3
_LANGUAGE_ = 4
_OPTIMIZATION_ = 5

# Index Code Size
_EKS_SIZE_ = 6
_E_SIZE_ = 7
_DKS_SIZE_ = 8
_D_SIZE_ = 9
_TOTAL_SIZE_ = 10

# Index RAM

# Index Execution Time
_EKS_TIME_ = 21
_E_TIME_ = 22
_DKS_TIME_ = 23
_D_TIME_ = 24

# FUNCTIONS
def writeOptimizationValues(csv_writer, cipher, optimization, metrics):
    csv_writer.writerow(
        [
            cipher,
            metrics[cipher]["info"]["BLOCK_SIZE"],
            metrics[cipher]["info"]["KEY_SIZE"],
            metrics[cipher]["info"]["VERSION"],
            metrics[cipher]["info"]["LANGUAGE"],
            optimization,
            # Size
            getAverage(metrics[cipher][optimization]["EKS_SIZE"]),
            getAverage(metrics[cipher][optimization]["E_SIZE"]),
            getAverage(metrics[cipher][optimization]["DKS_SIZE"]),
            getAverage(metrics[cipher][optimization]["D_SIZE"]),
            getAverage(metrics[cipher][optimization]["TOTAL_SIZE"]),
            # RAM
            "-",
            "-",
            "-",
            "-",
            "-",
            "-",
            "-",
            "-",
            "-",
            "-",
            # Execution Time
            getAverage(metrics[cipher][optimization]["EKS_TIME"]),
            getAverage(metrics[cipher][optimization]["E_TIME"]),
            getAverage(metrics[cipher][optimization]["DKS_TIME"]),
            getAverage(metrics[cipher][optimization]["D_TIME"])
        ]
    )

def getAverage(l):
    return int(round(sum(l)/len(l)))

def main():
    # Read Statistics
    files_list = os.listdir(".")
    metrics = dict()
    headers = list()

    for file_name in files_list:
        if((not os.path.isfile(file_name)) or (".csv" not in file_name) or ("metrics.csv" in file_name)):
            continue

        f = open(file_name, 'rb')

        csv_reader = csv.reader(f, delimiter=',')

        i = 0
        for line in csv_reader:
            if (i < 3): # ESCAPE HEADERS
                if(len(headers) < 3):
                    headers.append(line)
                i = i + 1
                continue
            
            # Cipher Name
            if(int(line[_VERSION_]) < 10):
                index = "%s_%d_%d_v0%d" % (line[_CIPHER_], int(line[_BLOCK_SIZE_]), int(line[_KEY_SIZE_]), int(line[_VERSION_]))
            else:
                index = "%s_%d_%d_v%d" % (line[_CIPHER_], int(line[_BLOCK_SIZE_]), int(line[_KEY_SIZE_]), int(line[_VERSION_]))
            
            # Optimization
            if ("O1" in line[_OPTIMIZATION_]):
                optimization = "O1"
            elif ("O2" in line[_OPTIMIZATION_]):
                optimization = "O2"
            elif ("O3" in line[_OPTIMIZATION_]):
                optimization = "O3"
            else:
                optimization = "Os"

            # Add to Metrics

            if(index in metrics.keys()):
                if(optimization in metrics[index].keys()):
                    # Size
                    metrics[index][optimization]["EKS_SIZE"].append(int(line[_EKS_SIZE_]))
                    metrics[index][optimization]["E_SIZE"].append(int(line[_E_SIZE_]))
                    metrics[index][optimization]["DKS_SIZE"].append(int(line[_DKS_SIZE_]))
                    metrics[index][optimization]["D_SIZE"].append(int(line[_D_SIZE_]))
                    metrics[index][optimization]["TOTAL_SIZE"].append(int(line[_TOTAL_SIZE_]))
                    # Execution Time
                    metrics[index][optimization]["EKS_TIME"].append(int(line[_EKS_TIME_]))
                    metrics[index][optimization]["E_TIME"].append(int(line[_E_TIME_]))
                    metrics[index][optimization]["DKS_TIME"].append(int(line[_DKS_TIME_]))
                    metrics[index][optimization]["D_TIME"].append(int(line[_D_TIME_]))
                else:
                    metrics[index][optimization] =  dict()
                    # Size
                    metrics[index][optimization]["EKS_SIZE"] = [int(line[_EKS_SIZE_])]
                    metrics[index][optimization]["E_SIZE"] = [int(line[_E_SIZE_])]
                    metrics[index][optimization]["DKS_SIZE"] = [int(line[_DKS_SIZE_])]
                    metrics[index][optimization]["D_SIZE"] = [int(line[_D_SIZE_])]
                    metrics[index][optimization]["TOTAL_SIZE"] = [int(line[_TOTAL_SIZE_])]
                    # Execution Time
                    metrics[index][optimization]["EKS_TIME"] = [int(line[_EKS_TIME_])]
                    metrics[index][optimization]["E_TIME"] = [int(line[_E_TIME_])]
                    metrics[index][optimization]["DKS_TIME"] = [int(line[_DKS_TIME_])]
                    metrics[index][optimization]["D_TIME"] = [int(line[_D_TIME_])]
            else:
                metrics[index] = dict()
                metrics[index]["info"] = dict()
                metrics[index]["info"]["NAME"] = line[_CIPHER_]
                metrics[index]["info"]["BLOCK_SIZE"] = int(line[_BLOCK_SIZE_])
                metrics[index]["info"]["KEY_SIZE"] = int(line[_KEY_SIZE_])
                metrics[index]["info"]["VERSION"] = int(line[_VERSION_])
                metrics[index]["info"]["LANGUAGE"] = line[_LANGUAGE_]

                metrics[index][optimization] =  dict()
                # Size
                metrics[index][optimization]["EKS_SIZE"] = [int(line[_EKS_SIZE_])]
                metrics[index][optimization]["E_SIZE"] = [int(line[_E_SIZE_])]
                metrics[index][optimization]["DKS_SIZE"] = [int(line[_DKS_SIZE_])]
                metrics[index][optimization]["D_SIZE"] = [int(line[_D_SIZE_])]
                metrics[index][optimization]["TOTAL_SIZE"] = [int(line[_TOTAL_SIZE_])]
                # Execution Time
                metrics[index][optimization]["EKS_TIME"] = [int(line[_EKS_TIME_])]
                metrics[index][optimization]["E_TIME"] = [int(line[_E_TIME_])]
                metrics[index][optimization]["DKS_TIME"] = [int(line[_DKS_TIME_])]
                metrics[index][optimization]["D_TIME"] = [int(line[_D_TIME_])]


    # Output Mean of Metrics
    new_file = open('metrics.csv', 'wb')
    csv_writer = csv.writer(new_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

    for header in headers:
        csv_writer.writerow(header)

    for cipher in metrics.keys():
        writeOptimizationValues(csv_writer, cipher, "O1", metrics)
        writeOptimizationValues(csv_writer, cipher, "O2", metrics)
        writeOptimizationValues(csv_writer, cipher, "O3", metrics)
        writeOptimizationValues(csv_writer, cipher, "Os", metrics)

if __name__ == "__main__":
    main()