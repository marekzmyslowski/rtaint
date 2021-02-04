#
#
#   Author: Marek Zmysłowski <mzmyslowski@cycura.com>
#   Copyright (c) 2019 Cycura Inc. www.cycura.com
#   Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
#   documentation files (the "Software"), to deal in the Software without restriction, including without limitation
#   the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
#   to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in all copies or substantial
#   portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
#   TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
#   THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
#   CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#   DEALINGS IN THE SOFTWARE.
#
#

import argparse
import hashlib
import sys
import copy

from file_read_backwards import FileReadBackwards
from bitstring import BitArray

from .log import logger
from .version import __version__

logo = '''
     _______                                                                     ________         __              __     
    /       \                                                                   /        |       /  |            /  |    
    $$$$$$$  |  ______   __     __  ______    ______    _______   ______        $$$$$$$$/______  $$/  _______   _$$ |_   
    $$ |__$$ | /      \ /  \   /  |/      \  /      \  /       | /      \          $$ | /      \ /  |/       \ / $$   |  
    $$    $$< /$$$$$$  |$$  \ /$$//$$$$$$  |/$$$$$$  |/$$$$$$$/ /$$$$$$  |         $$ | $$$$$$  |$$ |$$$$$$$  |$$$$$$/   
    $$$$$$$  |$$    $$ | $$  /$$/ $$    $$ |$$ |  $$/ $$      \ $$    $$ |         $$ | /    $$ |$$ |$$ |  $$ |  $$ | __ 
    $$ |  $$ |$$$$$$$$/   $$ $$/  $$$$$$$$/ $$ |       $$$$$$  |$$$$$$$$/          $$ |/$$$$$$$ |$$ |$$ |  $$ |  $$ |/  |
    $$ |  $$ |$$       |   $$$/   $$       |$$ |      /     $$/ $$       |         $$ |$$    $$ |$$ |$$ |  $$ |  $$  $$/ 
    $$/   $$/  $$$$$$$/     $/     $$$$$$$/ $$/       $$$$$$$/   $$$$$$$/          $$/  $$$$$$$/ $$/ $$/   $$/    $$$$/  

    Version %s    
    ''' % __version__


def print_info():
    logger.info(logo)


def get_address(varname):
    """
    The function returns the address of the variable.
    If the variable is temporary (rx_xxxx or tx_xxxx) then the address is 0,
    if the variable is xxxxxx_unknownobj then the address is xxxxxx converted to int
    :param varname: The variable to parse
    :return: Address as int
    """
    if "_unknownobj" in varname:
        return int(varname.split("_unknownobj")[0], 16)
    elif ":" in varname:
        return int(varname.split(":")[1], 16)
    else:
        return 0


def get_next_line(log_file):
    """
    The function reads the line from the file.
    :return: Return one line that matches
    """

    while True:
        line = re.sub(r'\x1B\[(([0-9]{1,2})?(;)?([0-9]{1,2})?)?[m,K,H,f,J]','', log_file.readline())

        if not line:
            return None

        if line.startswith("0x"):
            return line


def parse_line(line):
    """
    Parses a log line and returns its components
    :param line:
    :return: tuple
    """
    addr, insn, insnty, val, flow = "", "", "", "", ""

    parts = line.rstrip().split(" | ")

    if len(parts) == 5:
        addr, insn, insnty, val, flow = parts
    elif len(parts) == 4:
        addr, insnty, val, flow = parts
    elif len(parts) == 2:
        addr, flow = parts
    else:
        raise Exception("Incorrect line format: {}".format(line))

    return addr, insn, insnty, val, flow


def add_new_taint(file_taints, taint):
    """
    The function add tuple to the taint dictionary.
    It perform simple optimization - it checks if the entry exists and what size.
    :param file_taints: Taint dictionary
    :param taint: Data to add.
    :return: None
    """
    key, value = int(taint[0]), int(taint[1])

    if key not in file_taints:
        file_taints[key] = value
    elif value > file_taints[key]:
        file_taints[key] = value


def add_new_state(states, var_name, var_address, taint_size, taint_offset):
    """
    The function add new state to the state dictionary.
    It performs simple optimization - check if the entry exists.
    :param states: State dictionary
    :param var_name: Variable name
    :param var_address: Variable address
    :param taint_size: Taint size
    :param taint_offset: Taint offset
    :return: None
    """

    state = [var_name, var_address, taint_size, taint_offset]

    if state not in states:
        states.append(state)


def add_new_slice(slice_file, line):
    """
    The function add new line to the slice file.
    :param line: Line to be added
    :return: None
    """
    slice_file.write(line)


def print_kaitai(taint_dict, kaitai_dir):
    """
    The function prints the result from taint dictionary. It contains the tuples [offset, size].
    The tuples can be duplicated. Also the function compacts data.
    :param taint_dict: Taint dictionary
    :param kaitai_dir: Directory when the file will be stored
    :return: None
    """
    assert taint_dict

    local_taint_dict = copy.deepcopy(taint_dict)
    kaitai = "meta:\n  id: taint\ninstances:\n"
    index = 0

    sorted_offsets = sorted(local_taint_dict)

    current_offset = sorted_offsets.pop(0)
    current_size = local_taint_dict.pop(current_offset)

    for key in sorted_offsets:
        if key > current_offset + current_size:
            logger.info("Offset: {} Size: {}".format(str(current_offset), str(current_size)))

            kaitai += "  taint" + str(index) + ":\n    pos: " + hex(current_offset) + "\n    size: " + str(
                current_size) + "\n"

            index += 1
            current_offset, current_size = key, local_taint_dict[key]
        elif key >= current_offset and \
                (key + local_taint_dict[key] > current_offset + current_size):
            current_size = key + local_taint_dict[key] - current_offset

    logger.info("Offset: {} Size: {}".format(str(current_offset), str(current_size)))

    kaitai += "  taint" + str(index) + ":\n    pos: " + hex(current_offset) + "\n    size: " + str(current_size) + "\n"

    logger.info("------ Kaitai Struct - CUT HERE -------\n\n {}".format(kaitai))
    logger.info("-------------- END --------------------")

    hash_object = hashlib.sha512(kaitai.encode())
    hex_dig = hash_object.hexdigest()

    logger.info("Kaitai Struct SHA512: {}".format(hex_dig))
    if kaitai_dir:
        kaitai_filename = kaitai_dir + hex_dig + ".ksy"
        with open(kaitai_filename, "w+") as kaitai_file:
            kaitai_file.write(kaitai)


def print_binary_map(taint_dict, binary_map_and_size):
    """
    The function creates and saves the binary map of bytes that are tainted from the source.
    The bit[x] means that byte[x] from input file is tainted.
    :param taint_dict: Taint dictionary
    :param binary_map_and_size: Binary file and size - name:size
    :return: None
    """
    assert taint_dict
    if not binary_map_and_size:
        return

    [file_name, size] = binary_map_and_size.split(':')
    if int(size) < 0:
        logger.warinig("The size value is negative")
        return
    map = BitArray(int(size))
    map.set(0)

    for key in taint_dict:
        for value in range(taint_dict[key]):
            map.set(1, key + value)

    with open(file_name, "wb") as binary_map:
        map.tofile(binary_map)


def print_graph(nodes, edges, graph_file_name):
    """
    The function creates the file with the graph in the dot format.
    :param nodes: List of the nodes
    :param edges: List of the edges
    :param graph_file_name: File name of the graph file
    :return: None
    """
    if not graph_file_name:
        return

    with open(graph_file_name, "w") as graph_file:
        graph_file.write("strict digraph {\n")

        # Print the edges
        for n in nodes:
            graph_file.write("    " + n + "\n")

        # Print the edges
        for e in edges:
            graph_file.write("    " + e + "\n")

        graph_file.write("}")


def run(log_file, graph_file_name, slice_file, kaitai_dir, binary_map_and_size, variable):
    # Currently processed state
    current_states = []
    # State that will be process in the next iteration
    next_states = []
    # Taint that was already found as [offset, size]
    file_taints = {}

    # Data for the dot graph
    edges = []  # Storing the connections
    nodes = []

    line = get_next_line(log_file)
    addr, insn, insnty, val, flow = parse_line(line)

    if variable:
        sink = flow.split(" <- ")
        while variable not in sink[0]:
            line = get_next_line(log_file)
            addr, insn, insnty, val, flow = parse_line(line)
            sink = flow.split(" <- ")

    if insn:
        if variable:
            logger.info("The tainted instruction: {}".format(insn))
        else:
            logger.info("The crashing instruction reason: {}".format(insn))

    # Identify the value to taint
    if " <- " in flow:
        (sink, sources) = flow.split(" <- ")
        sources = sources.replace('(', '').replace(')', '')

        for source in sources.split():
            follow_address = get_address(source)
            tmp_taint_size = -1

            if "Load" in insnty:
                tmp_taint_size = int(insnty.split(":")[1])

            current_states.append([source, follow_address, tmp_taint_size, 0])
    else:
        # Is this possible ? ? ?
        sources = flow
        follow_address = get_address(sources)
        current_states.append([sources, follow_address, -1, 0])

    # FIXME: first, I'm assuming that the sources is crash reason. This needs to be changed depends on the instrcution type
    logger.info("Tainting the value: {}".format(variable if variable else sources))

    if slice_file:
        add_new_slice(slice_file, line)

    while True:
        line = get_next_line(log_file)
        add_line_to_slice = False

        if not line:
            # Everything was parsed.
            break

        addr, insn, insnty, val, flow = parse_line(line)

        # Iterate through all states
        for (var_name, var_address, taint_size, taint_offset) in current_states:
            # Check if this is flow.
            if " <- " in flow:
                (sink, sources) = flow.split(" <- ")
                sink_address = get_address(sink)
                sources = sources.replace('(', '').replace(')', '')

                if sink_address == 0:
                    # The sink is temp variable
                    if sink == var_name:
                        for source in sources.split():
                            tmp_taint_size = taint_size
                            tmp_var_address = get_address(source)

                            if "Load" in insnty:
                                tmp_taint_size = int(insnty.split(":")[1])
                                if taint_size != -1 and tmp_taint_size > taint_size:  # this can be smaller later
                                    tmp_taint_size = taint_size

                            if tmp_var_address == 0:
                                nodes.append("\"" + source + "\"" + " [label=\"\" shape=point]")
                            else:
                                nodes.append("\"" + source + "\"" + " [label=\"%s\"]" % source)

                            edges.append("\"" + source + "\"" + " -> " + "\"" + sink + "\"")

                            # logger.debug("State: " + str([source, tmp_var_address, tmp_taint_size, taint_offset]))
                            add_new_state(next_states, source, tmp_var_address, tmp_taint_size, taint_offset)
                            add_line_to_slice = True
                    else:
                        # logger.debug("State: " + str([var_name, var_address, taint_size, taint_offset]))
                        add_new_state(next_states, var_name, var_address, taint_size, taint_offset)
                        continue
                else:
                    # The sink is address
                    # In that situation we can have only the Store command
                    if "Store" in insnty:
                        sink_size = int(insnty.split(":")[1])

                        if var_address >= sink_address and var_address < sink_address + sink_size:
                            if var_address > sink_address:
                                edges.append("\"" + sink + "\"" + " -> " + "\"" + var_name + "\"")
                                nodes.append("\"" + sink + "\"" + " [label=\"%s\"]" % sink)
                            # TODO: Can store be _unknownobj <- _unknownobj ? ? ?

                            if "_unknownobj" in sources:
                                raise Exception("We shouldn't be here" + line)

                            for source in sources.split():
                                tmp_var_address = 0  # This is not needed i think
                                tmp_taint_size = taint_size
                                nodes.append("\"" + source + "\"" + " [label=\"\" shape=point]")
                                edges.append("\"" + source + "\"" + " -> " + "\"" + sink + "\" [label=\"Store\"]")
                                # logger.debug("State: " + str(
                                #    [source, tmp_var_address, tmp_taint_size, var_address - sink_address]))
                                add_new_state(next_states,
                                              source, tmp_var_address, tmp_taint_size, var_address - sink_address)
                                add_line_to_slice = True
                        else:
                            # logger.debug("State: " + str([var_name, var_address, taint_size, taint_offset]))
                            add_new_state(next_states, var_name, var_address, taint_size, taint_offset)

                    else:
                        # If this is not a Store instruction then there is an issues somewhere
                        # that needs to be fixed
                        raise Exception("We shouldn't be here" + line)

            else:
                # If there is no flow, the Read may occurs
                if "Read" in insnty:
                    if var_address != 0:
                        # Here we check if the address is read from the file
                        buffer_address = get_address(flow)  # int(flow.split("_unknownobj")[0], 16)
                        buffer_size = int(insnty.split(":")[1])

                        if var_address >= buffer_address and var_address < buffer_address + buffer_size:
                            if var_address > buffer_address:
                                edges.append("\"" + flow + "\"" + " -> " + "\"" + var_name + "\"")
                                nodes.append("\"" + flow + "\"" + " [label=\"%s\"]" % flow)

                            file_offset = int(val, 16) + (var_address - buffer_address)
                            edges.append("\"Input file - offset:" + str(
                                file_offset + taint_offset) + "\"" + " -> " + "\"" + flow + "\" [label=\"Read\"]")

                            logger.info("Found the file taint: " + var_name + " Offset: " + str(
                                file_offset + taint_offset) + " Size:" + str(taint_size))

                            add_new_taint(file_taints, [file_offset + taint_offset, taint_size])
                            add_line_to_slice = True
                        else:
                            # logger.debug("State: " + str([var_name, var_address, taint_size, taint_offset]))
                            add_new_state(next_states, var_name, var_address, taint_size, taint_offset)
                    else:
                        # logger.debug("State: " + str([var_name, var_address, taint_size, taint_offset]))
                        add_new_state(next_states, var_name, var_address, taint_size, taint_offset)
                else:
                    # logger.debug("State: " + str([var_name, var_address, taint_size, taint_offset]))
                    add_new_state(next_states, var_name, var_address, taint_size, taint_offset)

        if slice_file and add_line_to_slice:
            add_new_slice(slice_file, line)

        current_states = next_states.copy()
        # logging.debug(next_states)
        next_states.clear()

    print_kaitai(file_taints, kaitai_dir)
    print_binary_map(file_taints, binary_map_and_size)
    print_graph(nodes, edges, graph_file_name)


def main():
    parser = argparse.ArgumentParser(prog='rtaint.py')
    parser.add_argument('-f', type=str, required=True,
                        help='Log file from Taintgrind')
    parser.add_argument('-g', type=str, required=False,
                        help='File name to store dot graph')
    parser.add_argument('-s', type=str, required=False,
                        help="File name for the slice")
    parser.add_argument('-v', type=str, required=False,
                        help="Variable name")
    parser.add_argument('-k', type=str, required=False,
                        help="Directory path where Kaitai Struct will be stored inside the file $SHA512.ksy ")
    parser.add_argument('-b', type=str, required=False,
                        help="File name for the binary map and size separated by colon - name:size")
    args = parser.parse_args(sys.argv[1:])

    print_info()

    if sys.version_info >= (3, 4):
        try:
            with FileReadBackwards(args.f, encoding="utf-8") as log_file:
                if args.s:
                    with open(args.s, "w") as slice_file:
                        run(log_file, args.g, slice_file, args.k, args.b, args.v)
                else:
                    run(log_file, args.g, None, args.k, args.b, args.v)
        except KeyboardInterrupt:
            print('+ Interrupted')
            sys.exit(0)
    else:
        print("- Python version needs to be at least 3.4")


if __name__ == "__main__":
    main()
