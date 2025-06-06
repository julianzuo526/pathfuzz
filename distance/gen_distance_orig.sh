#!/bin/bash

if [ $# -lt 2 ]; then
  echo "Usage: $0 <binaries-directory> <temporary-directory> [fuzzer-name]"
  echo ""
  exit 1
fi

BINARIES=$(readlink -e $1)
TMPDIR=$(readlink -e $2)
AFLGO="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../" && pwd )"
fuzzer=""
if [ $# -eq 3 ]; then
  fuzzer=$(find $BINARIES -maxdepth 1 -name "$3.0.0.*.bc" | rev | cut -d. -f5- | rev)
  if [ $(echo "$fuzzer" | wc -l) -ne 1 ]; then
    echo "Couldn't find bytecode for fuzzer $3 in folder $BINARIES."
    exit 1
  fi
fi

SCRIPT=$0
ARGS=$@

# SANITY CHECKS
if [ -z "$BINARIES" ]; then echo "Couldn't find binaries folder ($1)."; exit 1; fi
if ! [ -d "$BINARIES" ]; then echo "No directory: $BINARIES."; exit 1; fi
if [ -z "$TMPDIR" ]; then echo "Couldn't find temporary directory ($2)."; exit 1; fi

binaries=$(find $BINARIES -maxdepth 1 -name "*.0.0.*.bc" | rev | cut -d. -f5- | rev)
if [ -z "$binaries" ]; then echo "Couldn't find any binaries in folder $BINARIES."; exit; fi

if [ -z $(which python) ] && [ -z $(which python3) ]; then echo "Please install Python"; exit 1; fi

FAIL=0
STEP=1

RESUME=$(if [ -f $TMPDIR/state ]; then cat $TMPDIR/state; else echo 0; fi)

function next_step {
  echo $STEP > $TMPDIR/state
  if [ $FAIL -ne 0 ]; then
    tail -n30 $TMPDIR/step${STEP}.log
    echo "-- Problem in Step $STEP of generating distance info!"
    echo "-- You can resume by executing:"
    echo "$ $SCRIPT $ARGS $TMPDIR"
    exit 1
  fi
  STEP=$((STEP + 1))
}

# Load instrumented function whitelist if available
INSTRUMENTED_FUNCS="$TMPDIR/instrumented_funcs.txt"

#-------------------------------------------------------------------------------
# Step 1: Construct control flow graph and call graph
#-------------------------------------------------------------------------------
if [ $RESUME -le $STEP ]; then
  cd $TMPDIR/dot-files

  if [ -z "$fuzzer" ]; then
    for binary in $(echo "$binaries"); do
      echo "($STEP) Constructing CG for $binary.."
      prefix="$TMPDIR/dot-files/$(basename $binary)"
      while ! opt -dot-callgraph $binary.0.0.*.bc -callgraph-dot-filename-prefix $prefix >/dev/null 2> $TMPDIR/step${STEP}.log ; do
        echo -e "\e[93;1m[!]\e[0m Could not generate call graph. Repeating.."
      done
      awk '!a[$0]++' $(basename $binary).callgraph.dot > callgraph.$(basename $binary).dot
      rm $(basename $binary).callgraph.dot
    done
    $AFLGO/distance/distance_calculator/merge_callgraphs.py -o callgraph.dot $(ls callgraph.*)
    echo "($STEP) Integrating several call graphs into one."
  else
    echo "($STEP) Constructing CG for $fuzzer.."
    prefix="$TMPDIR/dot-files/$(basename $fuzzer)"
    while ! opt -dot-callgraph $fuzzer.0.0.*.bc -callgraph-dot-filename-prefix $prefix >/dev/null 2> $TMPDIR/step${STEP}.log ; do
      echo -e "\e[93;1m[!]\e[0m Could not generate call graph. Repeating.."
    done
    awk '!a[$0]++' $(basename $fuzzer).callgraph.dot > callgraph.dot
    rm $(basename $fuzzer).callgraph.dot
  fi
fi
next_step

#-------------------------------------------------------------------------------
# Step 2: Compute call graph distance and filter by instrumented functions
#-------------------------------------------------------------------------------
if [ $RESUME -le $STEP ]; then
  echo "($STEP) Computing distance for call graph .."
  $AFLGO/distance/distance_calculator/distance.py -d $TMPDIR/dot-files/callgraph.dot \
    -t $TMPDIR/Ftargets.txt -n $TMPDIR/Fnames.txt -o $TMPDIR/distance.callgraph.txt \
    > $TMPDIR/step${STEP}.log 2>&1 || FAIL=1

  if [ $(cat $TMPDIR/distance.callgraph.txt | wc -l) -eq 0 ]; then
    FAIL=1
    next_step
  fi

  printf "($STEP) Computing distance for control-flow graphs "
  for f in $(ls -1d $TMPDIR/dot-files/cfg.*.dot); do
    funcname=$(basename $f | cut -d. -f2)

    # Skip if not in instrumented function list
    if [ -f "$INSTRUMENTED_FUNCS" ] && ! grep -x "$funcname" "$INSTRUMENTED_FUNCS" >/dev/null; then
      echo "Skipping $funcname (not in instrumented_funcs.txt)"
      continue
    fi

    awk '!a[$0]++' $f > ${f}.smaller.dot
    mv $f $f.bigger.dot
    mv $f.smaller.dot $f
    sed -i s/\\\"//g $f
    sed -i 's/\[.\"]//g' $f
    sed -i 's/\(^\s*[0-9a-zA-Z_]*\):[a-zA-Z0-9]*\( -> \)/\1\2/g' $f

    echo "Computing distance for $f..."
    $AFLGO/distance/distance_calculator/distance.py -d $f \
      -t $TMPDIR/BBtargets.txt -n $TMPDIR/BBnames.txt -s $TMPDIR/BBcalls.txt \
      -c $TMPDIR/distance.callgraph.txt -o ${f}.distances.txt \
      >> $TMPDIR/step${STEP}.log 2>&1

    if [ $? -ne 0 ]; then
      echo -e "\e[93;1m[!]\e[0m Could not calculate distance for $f."
    fi
  done

  cat $TMPDIR/dot-files/*.distances.txt > $TMPDIR/distance.cfg.txt
fi
next_step

# Final Instructions
echo ""
echo "----------[DONE]----------"
echo ""
echo "Now, you may wish to compile your sources with "
echo "CC=\"$AFLGO/instrument/aflgo-clang\""
echo "CXX=\"$AFLGO/instrument/aflgo-clang++\""
echo "CFLAGS=\"\$CFLAGS -distance=$(readlink -e $TMPDIR/distance.cfg.txt)\""
echo "CXXFLAGS=\"\$CXXFLAGS -distance=$(readlink -e $TMPDIR/distance.cfg.txt)\""
echo ""
echo "--------------------------"