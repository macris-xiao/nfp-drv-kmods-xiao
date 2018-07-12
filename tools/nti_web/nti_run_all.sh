#!/bin/bash

### Parse inputs

[ -z $NTI_DIR ] && NTI_DIR=./nti
[ -z $CFG_DIR ] && CFG_DIR=./cfg
[ -z $LOG_DIR ] && LOG_DIR=./auto_logs
[ -z $_NTI_CMD ] && _NTI_CMD=run

CFG_DIR=${CFG_DIR}/

### Functions

run_test() {
    local test_id=$1 cfg=$2 log_name=$3 what=$4 opts=$5 log

    [ -n "$opts" ] && opts="-o "${opts}
    log=${log_name}_$(date '+%F_%R')

    if [ -n "$dry" ]; then
	echo -e "\e[1mTEST ${test_id}\t${log_name}\e[0m"
	return
    fi

    echo -e "\e[1m======================================================="
    echo -e " TEST ${test_id}/${n_tests}  starting at $(date '+%F %R')"
    echo -e " NTI -q -c $cfg -l ${log} run tests.${what}\e[0m"
    echo

    ${NTI_DIR}/ti/ticmd -c ${CFG_DIR}$cfg $opts -l ${LOG_DIR}/${log} $_NTI_CMD tests.$what

    echo
}

run_all_cfgs() {
    for cfg in $CFGS; do
	run_test $((++test_id)) $cfg ${what}_${cfg}${name_sfx} $what $opts
    done
}

run_all_tests() {
    opts=$1
    name_sfx=$2

    TESTS='unit netdev'
    CFGS=$(ls $CFG_DIR)
    for t in $TESTS; do
	what=$t
	run_all_cfgs
    done

    TESTS='ebpfdrv'
    CFGS=$(cd ${CFG_DIR}; ls *_bpf *_nic *_abm)
    for t in $TESTS; do
	what=$t
	run_all_cfgs
    done

    TESTS='flower'
    CFGS=$(cd ${CFG_DIR}; ls *_flower)
    for t in $TESTS; do
	what=$t
	run_all_cfgs
    done

    TESTS='ebpf'
    CFGS=$(cd ${CFG_DIR}; ls *_bpf)
    for t in $TESTS; do
	what=$t
	run_all_cfgs
    done

    TESTS='abm'
    CFGS=$(cd ${CFG_DIR}; ls *_abm)
    for t in $TESTS; do
	what=$t
	run_all_cfgs
    done
}

run_all_opts() {
    test_id=

    run_all_tests 'General.installed_drv=True' u
    run_all_tests 'General.installed_drv=False'

    cfg=$(cd ${CFG_DIR}; ls | head -1)
    what='setup'
    run_test $((++test_id)) $cfg ${what}_${cfg}${name_sfx} $what $opts
}

### Code
dry=y
run_all_opts

n_tests=$test_id
dry=
run_all_opts

exit 0
