You must run two commands:
```
$ git submodule init
# to initialize your local configuration file, and
$ git submodule update
# to fetch all the data...

# Or from the beginning
git clone --recursive <repo url>
```

Modified ROPGadget can find LPI gadgets:
```
python ROPgadget.py --binary ~/14850-cfi/ControlFlowIntegrity/nsa-cfi/code/ls --lpi
```
