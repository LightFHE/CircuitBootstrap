Circuit bootstrapping based OpenFHE
=====================================

The code is modern C++ using OpenFHE, we implemented circuit bootstrapping(WWL+24) scheme for converting high-noise LWE ciphertext into its corresponding RGSW form with low-noise(https://eprint.iacr.org/2024/323).


## Installation

I complie the code on Linux. To run this reposity, you need:
1. Install pre-requisites and external libraries
2. Clone the repo
3. Create a directory where the binaries will be built. Commands are:
    ```
    mkdir build
    cd build
    cmake ..
    ```
4. Build binaries. Commands are:
    ```
    make -j<threads>
    ```

If your operating system is MacOS, please refer to the following:

- [MacOS](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/macos.html)

If your operating system is Windows, please refer to the following:

- [Windows](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/installation/windows.html)


## Code Examples

As circuit bootstrapping, we recommend looking at the code of the following examples:
   1. Circuit bootstrapping:
       1. [Code Example for circuit bootstrapping](src/binfhe/examples/circuitbootstrap-test-rgsw.cpp)

          Test this example you can execute:
          ```
          ./bin/examples/binfhe/circuitbootstrap-test-rgsw
          ```
       1. [Code Example for circuit bootstrapping and leveled computation(external product)](src/binfhe/examples/circuitbootstrap-test-ep.cpp)

            Test this example you can execute:
            ```
            ./bin/examples/binfhe/circuitbootstrap-test-ep
            ```

We provide several parameter sets for circuit bootstrapping, but you need to adjust the parameters according to the circuit computation tasks. Please modify the parameters in [`src/binfhe/lib/cirbtscontext.cpp`](src/binfhe/lib/cirbtscontext.cpp)



## Planned Releases

We will continue to release updates progressively, including multi-value functional bootstrapping based on LMKCDEY methods and their optimized version proposed by [[WWL+24]](https://eprint.iacr.org/2024/323) in Section 4, as well as additional optimizations related to circuit bootstrapping.

If you have any questions or suggestions, please contact shenxuan@iie.ac.cn.






