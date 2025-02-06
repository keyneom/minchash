# minchash
Multiset Incremental Hash Lib in Rust

A Rust library implementing an order-independent hash function for multisets using elliptic curve cryptography. Supports efficient incremental addition and removal of elements, with the ability to process bulk operations in parallel for improved performance.

## Key features:
- **Incremental Updates:** Supports adding or removing elements individually, updating the hash without recomputing it from scratch.
- **Bulk Operations with Parallel Processing:** Provides methods to add or remove multiple elements at once, leveraging parallel processing for enhanced performance on large datasets.
- **Elliptic Curve Cryptography:** Uses elliptic curve group operations to compute the hash, providing strong cryptographic properties.
- **Ideal for Unordered Collections:** Suited for applications that require hashing or comparing multisets where element order is irrelevant, such as in data synchronization, integrity verification, or cryptographic protocols.

The library currently only accepts string elements but could be modified to handle raw bytearrays, etc.

## Potential Uses
- **Instant Hash Verification of Unordered Data Streams:** Enable immediate hash verification of data received in chunks and in any order, such as torrents or streaming data. With this library, you can compute the hash incrementally as data arrives, without waiting to receive all of the data first. As long as the order of the data isn't critical to your application, this approach allows for faster verification. In many cases, processing data out of order doesn't introduce security vulnerabilities, making this a practical tradeoff for improved performance.
- **Enhancing Efficiency in Combinatorial Algorithms:** Optimize branch search algorithms where the solution space is combinatorial, but your exploration order varies (permutational). By utilizing the order-agnostic multiset hash to keep track of visited states, you can detect and avoid re-exploring equivalent subspaces reached through different paths. This prevents redundant computations and accelerates the search process by pruning the exploration tree of duplicate states.
- **Memory-Efficient Comparison of Large Multisets:** When comparing two large lists (possibly with duplicate elements) in distributed systems, element-by-element comparison is often impractical due to memory and network constraints. By computing the multiset hash of each list using this library, you can efficiently determine if the lists are equivalent in terms of element occurrences, regardless of order. If the hashes match, the lists contain the same elements with the same frequencies. This approach greatly reduces memory usage and network overhead, making it ideal for handling large or distributed datasets.