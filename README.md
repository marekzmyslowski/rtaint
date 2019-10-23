# Reverse Taint
The purpose of taint analysis is to track information flow between sources and sinks. The reverse taint is a opposite 
process that tracks data from sink to the source.
rtaint is a tool written in Python that uses Taintgrind log file. It is used with the crash analysis.
 After the application is crashed, rtaint tracks data to the input file.

#### Installing Taintgrind
The Taintgrind is the Valgrind tool that also needs to be installed. 
It is available here: https://github.com/wmkhoo/taintgrind
Please install it according to the instructions.

#### Installing rtaint
rtaint is a python package. To install execute following command:
```
python3 setup.py install
```

#### Creating Taint Log
The following info is required:
 - test_app - application that will be run;
 - test_case - the fail that is going to be tainted;
 - test_case_size - size of the file to taint

```
valgrind --tool=taintgrind --file-filter=/full/path/to/file/test_case --taint-start=0 --taint-len=test_case_size --compact=yes ./test_app test_case 2>log.txt
```

#### Creating Reverse Taint
Run the tool:
```
rtaint.py -f log.txt
```

Here is an output example:
```
INFO:root:The crashing instruction reason: mov byte ptr [rax], dl
INFO:root:Tainting the value: t20_13101
INFO:root:Found the file taint: 422a490_unknownobj Offset: 8 Size:1
INFO:root:Offset: 8 Size:1
INFO:root:------ kaitai struct - CUT HERE -------

meta:
  id: taint
instances:
  taint1:
    pos: 8
    size: 1

INFO:root:-------------- END --------------------
INFO:root:Kaitai struct SHA512: f20e91c46fde3980ea0b0d9444f44459d8c545ba98a3750db4c34233f0dba188d84bda8bbe8e8268ab0836038ed04dc3d00b48c6ab43e48fb69957d08e301954
```
The tool creates automatically the kaitai struct file that can be used.
Also the SHA512 is calculated for the kaitai struct. It can be used to compare different crashes.

#### License
rtaint is licensed under MIT