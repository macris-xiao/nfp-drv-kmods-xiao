#!/bin/bash -e

usage() {
    echo "Usage: $0 { NETDEV | PCIDEV }"
    exit 1
}

[ $# -ne 1 ] && usage

DEV=$1
if ! [ -e /sys/bus/pci/devices/$DEV ]; then
    DEV=$(ethtool -i $1 | grep bus | awk '{print $2}')
fi

[ "a$DEV" == a ] && usage

NODE=$(cat /sys/bus/pci/devices/$DEV/numa_node)
CPUL=$(cat /sys/bus/node/devices/node${NODE}/cpulist | tr ',' ' ')

for c in $CPUL; do
    # Convert "n-m" into "n n+1 n+2 ... m"
    [[ "$c" =~ '-' ]] && c=$(seq $(echo $c | tr '-' ' '))

    CPUS=(${CPUS[@]} $c)
done

echo Device $DEV is on node $NODE with cpus ${CPUS[@]}

IRQBAL=$(ps aux | grep irqbalance | wc -l)

[ $IRQBAL -ne 1 ] && echo Killing irqbalance && killall irqbalance

IRQS=$(ls /sys/bus/pci/devices/$DEV/msi_irqs/)


IRQS=($IRQS)

for i in $(seq 0 $((${#IRQS[@]} - 1)))
do
    ! [ -e /proc/irq/${IRQS[i]} ] && continue

    cpu=${CPUS[i % ${#CPUS[@]}]}
    echo Mapping IRQ ${IRQS[i]} to CPU $cpu
    echo $cpu > /proc/irq/${IRQS[i]}/smp_affinity_list
done
