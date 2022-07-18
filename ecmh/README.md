# ECMH

## Building the Code

```shell
mkdir build
cd build
cmake ..
make
```

## Implementation

This project implement a elliptic curve multiset hash scheme.

- ``init`` method support init from a ``vector<int>`` or a ``vector<string>``.
- ``add`` method and ``operator+=`` support add new element from a single ``int/string`` or a ``vector<int/string>``.
- ``erase`` method and ``operator-=`` are similar as above.

- ``hash2point`` method use **try then increase** apporach. Specifically, we first hash an element $x$ into a hashvalue $h(x)$(by default using sm3). Then $h(x)$ is used as the x coordinate of elliptic curve(by default using sm2). We use openssl function ``EC_POINT_set_compressed_coordinates`` set the elliptic point. If the point is not on the curve, we simply increase x coordinate and try again.

- ``hashValue`` gives the hash value of the multiset, viz the elliptic point hex value.
