# Reverse Taint
The purpose of taint analysis is to track information flow between sources and sinks. The reverse taint is the opposite 
process that tracks data from sink to the source.
rtaint tool was created to help with the crash analysis. Currently, with multiple features, it can be easily 
used for the binary analysis.
rtaint is written in Python 3 and uses the Taintgraind (Valgrind plugin) log file.

#### Installing Taintgrind
The Taintgrind is the Valgrind tool that also needs to be installed. 
It is available here: https://github.com/wmkhoo/taintgrind
Please install it according to the instructions.

#### Installing rtaint
rtaint is a Python package. To install execute the following command:
```
python3 setup.py install
```
#### Using Dockerfile
To build docker image use simple command:
```
docker build . -t rtaint
```
The number added to the docker file points the valgrind version available through this docker.

#### Creating Taint Log
The following info is required:
 - test_app - application that will be run;
 - test_case - the fail that is going to be tainted;
 - test_case_size - size of the file to taint

```
valgrind --tool=taintgrind --file-filter=/full/path/to/file/test_case --taint-start=0 --taint-len=test_case_size --compact=yes ./test_app test_case 2>log.txt
```
The directory "examples" contains the simple application that can be used to test the rtaint.
```
valgrind --tool=taintgrind --file-filter=/full/path/to/file/crash.input --taint-start=0 --taint-len=25 --compact=yes ./avBranch crash.input 2>log.txt"
```

#### Creating Reverse Taint
Run the tool:
```
rtaint.py -f ./examples/log.txt
```

Here is an output example:
```
     _______                                                                     ________         __              __     
    /       \                                                                   /        |       /  |            /  |    
    $$$$$$$  |  ______   __     __  ______    ______    _______   ______        $$$$$$$$/______  $$/  _______   _$$ |_   
    $$ |__$$ | /      \ /  \   /  |/      \  /      \  /       | /      \          $$ | /      \ /  |/       \ / $$   |  
    $$    $$< /$$$$$$  |$$  \ /$$//$$$$$$  |/$$$$$$  |/$$$$$$$/ /$$$$$$  |         $$ | $$$$$$  |$$ |$$$$$$$  |$$$$$$/   
    $$$$$$$  |$$    $$ | $$  /$$/ $$    $$ |$$ |  $$/ $$      \ $$    $$ |         $$ | /    $$ |$$ |$$ |  $$ |  $$ | __ 
    $$ |  $$ |$$$$$$$$/   $$ $$/  $$$$$$$$/ $$ |       $$$$$$  |$$$$$$$$/          $$ |/$$$$$$$ |$$ |$$ |  $$ |  $$ |/  |
    $$ |  $$ |$$       |   $$$/   $$       |$$ |      /     $$/ $$       |         $$ |$$    $$ |$$ |$$ |  $$ |  $$  $$/ 
    $$/   $$/  $$$$$$$/     $/     $$$$$$$/ $$/       $$$$$$$/   $$$$$$$/          $$/  $$$$$$$/ $$/ $$/   $$/    $$$$/  
   
    Version 0.30    
    
The tainted instruction: movzx eax, byte ptr [rax + 0x15]
Tainting the value: t17_15724
Found the file taint: 422a490_unknownobj Offset: 21 Size:1
Offset: 21 Size: 1
------ Kaitai Struct - CUT HERE -------

 meta:
  id: taint
instances:
  taint0:
    pos: 0x15
    size: 1

-------------- END --------------------
Kaitai Struct SHA512: 18a5ace96a056d8189c292c981a4c3cec196bf2810ca56b547d02bc7c02eb3bf425dd21445dc98ef25649d6c91aed1699507410d17043b76c734b7f911f427af

```
As default rtaint produce the Kaitai struct representing data in the input file. 
Also, the SHA512 is created that can be used for the duplication finding.

#### Using rtaint

The following options are available:
```
usage: rtaint.py [-h] -f F [-g G] [-s S] [-v V] [-k K] [-b B]

optional arguments:
  -h, --help  show this help message and exit
  -f F        Log file from Taintgrind
  -g G        File name to store dot graph
  -s S        File name for the slice
  -v V        Variable name
  -k K        Directory path where Kaitai Struct will be stored inside the
              file $SHA512.ksy
  -b B        File name for the binary map and size separated by a colon -
              name:size
```
By default, rtaint creates taint starting from the last line of the log file unless the "-v" option
is used. Then the taint starts from the line with the variable assignment.

#### Additional Resources
The additional information can be found in my presentation:
https://www.slideshare.net/slideshow/embed_code/key/1jmcKqOhJm8md4

#### License
rtaint is licensed under MIT

