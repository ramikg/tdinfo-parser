# TDInfo Parser for IDA

An IDAPython script which parses Turbo/Borland symbolic debug information (aka TDInfo) and imports it into your IDA database.

Inspired by the pwnable.kr challenge _dos4fun_.  
Written with DOS in mind.

## Requirements

- IDA 7.x & Python 2
- `pip install -Ur requirements.txt`

## Components

- _tdinfo_structs.py_: [_construct_](https://github.com/construct/construct) definitions of the different TDInfo structs.  
This file is independent of IDA, and may be utilized to import the symbols into other programs which support Python.
- _tdinfo_parser.py_: An IDAPython script which parses the executable (using said definitions) and imports its symbols into the IDA database.

## Usage

0. Consider applying FLIRT signatures (see below).
1. Press _Alt+F7_ to load _tdinfo_parser.py_ into IDA.
2. Call `apply_tdinfo_symbols()`. When asked for, choose the relevant executable file.

## Some Turbo Tips

I'm usually not one for documentations going out of scope, but hey, if you're reading this then you're probably already plucking forgotten pieces of information from arcane niches of the Internet; why shouldn't I chip in?

The following pointers may help get you near your goal:

- IDA's entry point analysis may fail to recognize that an executable was compiled with a Turbo/Borland compiler.  
 You can still import IDA's TCC/BCC symbols manually by loading the compiler's signature file (_File_ -> _Load file_ -> _FLIRT signature file..._).

- _TD_ (_Turbo Debugger_ for DOS) – apart from being a decent debugger – automatically parses TDInfo symbols.

- _TDump_ (Turbo Dump) may be used for a more complete parsing of the debug information.
