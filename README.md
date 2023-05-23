# SmartState

The artifact of SmartState.

## Usage

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

### Build from docker

We also provide a docker image [on docker hub](https://hub.docker.com/r/inplus/smartstate/tags). 

Please pull it first.

```sh
docker pull inplus/smartstate:v1
```

You can run it with the following cmd:
```sh
docker run -it --name smartstate inplus/smartstate

cd smartstate/

python vulnerability_detection.py
```

And the result is in `demo_profitgain.csv`, containing `contract address, vulnerability location (i.e. vulnerable function), tainted/manipulated state variables`.


## Dataset 

The manual-labeled SRV dataset is in [SmartState-dataset](https://github.com/InPlusLab/SmartState-dataset).