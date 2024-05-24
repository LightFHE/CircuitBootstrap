# Boolean FHE (BinFHE) documentation

We have added the following files to OpenFHE to support the circuit bootstrapping scheme(https://eprint.iacr.org/2024/323):

[Circuit bootstrapping context](cirbtscontext.h)
- CryptoContext for the circuit bootstrapping scheme

[Circuit bootstrapping base parameters](cirbts-base-params.h)
- The class of circuit bootstrapping parameters, consisting with LWE parameters, RLWE parameters used in homomorphic trace and scheme switching, two RGSW parameters, the first is used in MV-FBS and the second is for the result of circiut bootstrapping.

[Circuit bootstrapping base scheme](cirbts-base-scheme.h)
- The main function of circuit bootstrapping.

[RLWE crypto paramters](rlwe-cryptoparameters.h)
- Class for all RLWE parameters used for circuit bootstrapping

[RLWE private key](rlwe-privatekey.h)
- Class for the private key of the RLWE scheme

[RLWE symmetric encryption](rlwe-ske.h)
- Class for the RLWE symmetric encryption scheme

[CGGI/GINX method for binary secret](rgsw-acc-cggi-binary.h)
- The CGGI/GINX method used in MV-FBS for binary secret

[RLWE homomorphic trace key](/rlwe-homtracekey.h)
- Class for the homomorphic trace key 

[RLWE homomorphic trace](/rlwe-homtrace.h)
- Class for the homomorphic trace

[RLWE scheme switching key](/rlwe-schemeswitchkey.h)
- Class for the scheme switching key 

[RLWE scheme switching](/rlwe-schemeswitch.h)
- Class for the scheme switching