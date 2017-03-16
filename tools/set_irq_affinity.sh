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
CPUS=$(cat /sys/bus/node/devices/node${NODE}/cpulist | tr ',' ' ')

echo Device $DEV is on node $NODE with cpus $CPUS

IRQBAL=$(ps aux | grep irqbalance | wc -l)

[ $IRQBAL -ne 1 ] && echo Killing irqbalance && killall irqbalance

IRQS=$(ls /sys/bus/pci/devices/$DEV/msi_irqs/)


IRQS=($IRQS)
CPUS=($CPUS)

for i in $(seq 0 $((${#IRQS[@]} - 1)))
do
    cpu=${CPUS[i % ${#CPUS[@]}]}
    echo Mapping IRQ ${IRQS[i]} to CPU $cpu
    echo $cpu > /proc/irq/${IRQS[i]}/smp_affinity_list
done
