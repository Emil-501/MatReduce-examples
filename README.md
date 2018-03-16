# MatReduce Examples

## Introduction

This repository maintains some output P4 programs optimized by MatReduce framework as well as control rules to populate composed MAT. MatReduce is an innovative framework that optimizes P4 program by reducing match factors of MATs. MatReduce first confirms and acquires the program dependencies in control flows and between MATs by means of a modified Table Dependency Graph(TDG). After analyzing input program, MatReduce creates the composed MAT and exploits bitmap variables to modify the control flow of input program for reducing match factors. By interacting with P4 compiler, MatReduce implements the optimized program on target devices. Meanwhile, it provides convenient runtime management to convert user rules to actual rules for maintaining policy consistency as well as avoiding matching ambiguity. 

## Installation

For running MatReduce examples, you are supposed to install [BMv2](https://github.com/p4lang/behavioral-model) and [p4c](https://github.com/p4lang/p4c) in your environment. To save your time, we provide two scripts for installing them: [install_bmv2.sh](https://github.com/Wasdns/p4Installer/blob/master/install_bmv2.sh) and [install_p4c.sh](https://github.com/Wasdns/p4Installer/blob/master/install_p4c.sh). Moreover, mininet is also required to simulate the experiment topologics.

## Use Cases

There are three cases extracted from [switch.p4](https://github.com/p4lang/switch):

| Case | Functions | MAT number | Original match factors | Optimized match factors |
| ---- | ---- | ---- | ---- | ---- | 
| Case1 | ACL + LB | 4 | 8 | 7 |
| Case2 | LB + Firewall + NAT | 5 | 9 | 8 |
| Case3 | IPSG Firewall + ACL + NAT + Router | 6 | 16 | 11 |

The input programs are named with "origin.p4" while the output programs are named with "optimize.p4". For comparing the performance results, you should follow these steps to get start. Note that before executing them, you are supposed to modify the path information stored in "env.sh".

## Hands-on Steps

1.Start the experiment topologic:

a.For original program: 

```
./run.sh p4src/origin.p4
```

b.For optimized program:

```
./run.sh p4src/optimze.p4
```

2.Populate runtime rules:

a.For original program: 

```
./set_switch.sh rules/origin.txt
```

b.For optimized program:

```
./set_switch.sh rules/optimze.txt
```

3.Configure ARP:

```
mininet> h1 arp -s 10.0.0.2 00:00:00:00:00:02
mininet> h2 arp -s 10.0.0.1 00:00:00:00:00:01
```

4.Start host terminals:

```
mininet> xterm h1 h2
```

5.Run experiment traffic using iperf:

a.run iperf server on h2:

```
h2> iperf -s -i 1
```

b.run iperf client on h1:

```
h1> iperf -c 10.0.0.2 -t 10 -i 1
```

## Author

@Wasdns(Xiang Chen): wasdnsxchen@gmail.com
