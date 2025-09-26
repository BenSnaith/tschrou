# Notes

## What is a DHT

A DHT is a distributed data structure that maps keys to nodes that are responsible for storing their corresponding data.

## Chord Ring

A virtual circular identifier space that encompasses all nodes, mapped onto a consistent hash function.

 - **Successor**: The next node in the clockwise direction responsible for a specific key.
 - **Predecessor**: The next node in the anti-clockwise direction responsible for a specific key.
 - **Finger Table**: A locally maintained directory containing the identifiers and network addressed of a few successors
 in the Chord Ring, enabling efficient lookup queries. Each server maintains the detail of m entries in the finger table
 where m is the number of bits of the identifier. The i'th element of the array contains the identity of the server that
 succeeds the current server by `2^i-1` in the chord ring

## What makes chord different from consistent hashing

