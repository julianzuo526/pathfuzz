# PathFuzz

## Requirements

- LLVM/Clang 11 (with `LLVMgold.so` and `libLTO.so`)
- Python 3, CMake, Build Essentials
- Optional: Boost (used in `gen_distance_orig.sh`)

## Installation Prerequisites

### 1. Install LLVMgold and libLTO

```bash
sudo mkdir -p /usr/lib/bfd-plugins
sudo cp /usr/local/lib/libLTO.so /usr/lib/bfd-plugins
sudo cp /usr/local/lib/LLVMgold.so /usr/lib/bfd-plugins
```

### 2. Install Required Dependencies

```bash
sudo apt-get update
sudo apt-get install python3 python3-dev python3-pip
sudo apt-get install pkg-config autoconf automake libtool-bin gawk
sudo apt-get install libboost-all-dev  # Optional if using `gen_distance_orig.sh`
```

### 3. Install Python Packages

```bash
python3 -m pip install networkx
python3 -m pip install pydot
python3 -m pip install pydotplus
```

## Build Components

### 4. Build Fuzzer

```bash
pushd afl-2.57b
make clean all
popd
```

### 5. Build Instrumentation Tool

```bash
pushd instrument
make clean all
popd
```

### 6. Build Distance Calculator

```bash
pushd distance/distance_calculator
cmake .
cmake --build .
popd
```


### 7. Build Taint Analysis Tool

```bash
pushd Taint
mkdir build
cd build
cmake -DDTAINT_DEBUG=ON ..
make
popd
popd
```

## Build Taint Executor
### 8. Set Taint Analysis Tool Compiler Wrappers

```bash
export DTAINT_MODE=1
export CC=DTaint/build/clang-wrapper
export CXX=DTaint/build/clang-wrapper++
```

Then build your **target program** with these compilers.

If compilation gives "undefined reference" errors:

```bash
make 2> error_message
DTaint/tools/gen_udr_abilist.sh error_message gen_abilist.txt
```

Then rebuild with flags:

```bash
-mllvm -dtaint-dfsan-abilist=gen_abilist.txt
```

## Build Target Executor

### 9. Setup Compiler Wrappers

```bash
cd targetdirectory
export SUBJECT=$PWD/target
mkdir temp
export TMP_DIR=$PWD/temp

# Write the target basic blocks to $TMP_DIR/BBtargets.txt manually or via script
```

```bash
export CC=$AFLGO/instrument/afl-clang-fast
export CXX=$AFLGO/instrument/afl-clang-fast++
export COPY_CFLAGS=$CFLAGS
export COPY_CXXFLAGS=$CXXFLAGS

export ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
export CFLAGS="$CFLAGS $ADDITIONAL"
export CXXFLAGS="$CXXFLAGS $ADDITIONAL"
export LDFLAGS=-lpthread
```

Then build your **target program**.


### 10. Distance Calculation

```bash
cat $TMP_DIR/BBnames.txt | grep -v "^$" | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
cat $TMP_DIR/BBcalls.txt | grep -Ev "^[^,]*$|^([^,]*,){2,}[^,]*$" | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt
```

```bash
distance/gen_distance_fast.py $SUBJECT $TMP_DIR target
# If that fails:
distance/gen_distance_orig.sh $SUBJECT $TMP_DIR target
```

### 11. Rebuild Target with Distance Info

```bash
export CFLAGS="$COPY_CFLAGS -distance=$TMP_DIR/distance.cfg.txt"
export CXXFLAGS="$COPY_CXXFLAGS -distance=$TMP_DIR/distance.cfg.txt"
```

Rebuild your **target** again.

## Fuzzing

### 12. Run Fuzzer

```bash
Pathfuzz/afl-2.57b/afl-fuzz -m none -z exp -c 45m -i in -o out target @@
```

## Notes

- Ensure you use **Clang 11** and corresponding `LLVMgold` and `libLTO` versions.
- All builds involving instrumentation must be done with `-flto` and `-fuse-ld=gold`.
- Update paths if LLVM or AFLGo is installed in non-standard directories.
