#!/bin/bash

# Check and install required packages
install_required_packages() {
    required_packages=("sysbench" "fio")

    for package in "${required_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  ${package} "; then
            echo "Installing ${package}..."
            sudo apt-get install -y "${package}"
        else
            echo "${package} is already installed."
        fi
    done
}

# Function to run CPU benchmark
run_cpu_benchmark() {
    echo "Running CPU Benchmark..."
    sysbench --test=cpu --cpu-max-prime=20000 run | grep "total time"
}

# Function to run RAM benchmark
run_ram_benchmark() {
    echo "Running RAM Benchmark..."
    sysbench --test=memory --memory-block-size=1M --memory-total-size=10G run | grep "Operations performed"
}

# Function to run Storage benchmark
run_storage_benchmark() {
    echo "Running Storage Benchmark..."
    fio --name=random-write --ioengine=libaio --rw=randwrite --bs=4k --direct=1 --size=100M --numjobs=4 --runtime=10 --group_reporting | grep "iops"
}

# Install required packages
install_required_packages

# Run benchmarks
run_cpu_benchmark
run_ram_benchmark
run_storage_benchmark

