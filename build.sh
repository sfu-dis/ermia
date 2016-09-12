MODE=perf DEBUG=$1 NDEBUG=`expr 1 - $1` make -j20 dbtest
