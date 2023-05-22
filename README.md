# SmartState

The artifact of SmartState.

## Artifact

In the folder `SmartState`.

### Build from source
1. Requirements
- Python 3.8.10
- Java 1.8
- [gigahorse](https://github.com/nevillegrech/gigahorse-toolchain)

```sh
pip install -r requirements.txt
```

2. Run
Run SmartState to detect vulnerabilities.

```sh 
python vulnerability_detection.py
```

And the result is in `demo_profitgain.csv`, containing `contract address, vulnerability location (i.e. vulnerable function), tainted/manipulated state variables`.

### Build from docker

We also provide a docker image [on docker hub](https://hub.docker.com/r/inplus/smartstate/tags). 

See more in the folder.


## Dataset

In the folder `SmartState-dataset`.