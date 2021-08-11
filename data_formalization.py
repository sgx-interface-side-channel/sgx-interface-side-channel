import pandas as pd


def get_data(filename: str) -> dict:
    """This function convert the result data to dict format.

    :arg filename: path to raw result data file

    :returns: result data in dict format
    {
        coursera.org.pcap:{
            IDS: 0.003605,
            Compression: {
                time: 0.028319,
                input_size:507059,
                output_size:467527,
                press_rate: 467527/507059
            }
        }
    }
    """
    with open(filename, "r") as f:
        result = {}
        for line in f:
            piece = line.strip().split(":")
            if piece[0] == "IDS(Illegal)":
                if piece[1] in result.keys():
                    result[piece[1]]["IDS"] = piece[-1]
                else:
                    result[piece[1]] = {"IDS": piece[-1]}
            elif piece[0] == "Compression":
                if piece[1] in result.keys():
                    result[piece[1]]["Compression"] = {"time": piece[3],
                                                       "input_size": piece[5],
                                                       "output_size": piece[7],
                                                       "press_rate": (float(piece[5]) - float(piece[7])) / float(
                                                           piece[5])
                                                       }
                else:
                    result[piece[1]] = {"Compression":
                                            {"time": piece[3],
                                             "input_size": piece[5],
                                             "output_size": piece[7],
                                             "press_rate": (float(piece[5]) - float(piece[7])) / float(piece[5])
                                             }
                                        }
    return result


def get_overhead(before, after, pure):
    pass


def genarate_xls(before, after, pure):
    """ 生成一个字典，字典的key是数据名称，value是[value1,value2]
    :key ["IDS_time_before","IDS_time_after","IDS_time_pure",
        "Compression_time_before","Compression_time_after",
        "Compression_time_pure","input_size","output_size_before",
        "output_size_after"]
    :var

    {
        "IDS_time_before": {
            "idntimes.com.pcap": 1.22222,
            "wikihow.com.pcap": 1.22222,
        }
    }
    :param before:
    :param after:
    :param pure:
    :return:
    """
    keys = ["IDS_time_before", "IDS_time_after", "IDS_time_pure",
            "Compression_time_before", "Compression_time_after",
            "Compression_time_pure", "input_size", "output_size_before",
            "output_size_after"]
    # index = []
    final_dict = {}
    for key in keys:
        final_dict[key] = {}

    for key, value in before.items():
        final_dict["IDS_time_before"][key] = value['IDS']
        final_dict["Compression_time_before"][key] = value['Compression']['time']
        final_dict["output_size_before"][key] = value['Compression']['output_size']
        final_dict["input_size"][key] = value['Compression']['input_size']

    for key, value in after.items():
        final_dict["IDS_time_after"][key] = value['IDS']
        final_dict["Compression_time_after"][key] = value['Compression']['time']
        final_dict["output_size_after"][key] = value['Compression']['output_size']

    for key, value in pure.items():
        final_dict["IDS_time_pure"][key] = value['IDS']
        final_dict["Compression_time_pure"][key] = value['Compression']['time']

    print(final_dict)

    df = pd.DataFrame(final_dict,index=before_result.keys())
    df.to_excel("result.xlsx")


if __name__ == '__main__':
    before_result = get_data("result_before.txt")
    # print(before_result)
    after_result = get_data("result_after.txt")
    # print(after_result)
    pure_result = get_data("result_pure.txt")
    # print(pure_result)
    genarate_xls(before_result, after_result, pure_result)
