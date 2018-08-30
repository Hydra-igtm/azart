Azart Core staging tree 0.12.4.2
===============================



## Development Resources

###### Resources:
- Official site: https://azartpay.com  
- Block explorer: https://explorer.azartpay.com  
- White paper: [whitepaper_v2.pdf](https://github.com/azartpay/azart/blob/master/azart-docs/whitepaper_v2.pdf)  
- Sentinel: https://github.com/azartpay/azart-sentinel  
- Masternode installer: https://github.com/azartpay/azart-masternode  
- Masternode guide: https://github.com/azartpay/azart-masternode-guide  
- How to setup a Masternode: https://github.com/azartpay/azart/blob/master/MASTERNODE.md

###### Exchanges:  
- Stocks.exchange: https://app.stocks.exchange/en/basic-trade/pair/BTC/AZART/1D
- Crex24.com: https://crex24.com/exchange/AZART-BTC  

###### Nodes:  
- addnode=176.9.70.106:9799
- addnode=5.9.73.81:9799
- addnode=5.9.6.17:9799
- addnode=176.9.121.219:9799
- addnode=5.188.204.38:9799
- addnode=5.188.204.37:9799
- addnode=5.188.204.36:9799
- addnode=5.188.204.35:9799
- addnode=5.188.204.34:9799
- addnode=5.188.204.33:9799
- addnode=5.188.204.32:9799
- addnode=5.188.204.31:9799
- addnode=5.188.204.30:9799
- addnode=5.188.204.29:9799
- addnode=5.188.204.28:9799
- addnode=5.188.204.27:9799
- addnode=5.188.204.6:9799

License
-------

Azart Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is meant to be stable. Development is normally done in separate branches.
[Tags](https://github.com/azartpay/azart/tags) are created to indicate new official,
stable release versions of Azart Core.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](/doc/unit-tests.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: `make check`

There are also [regression and integration tests](/qa) of the RPC interface, written
in Python, that are run automatically on the build server.
These tests can be run (if the [test dependencies](/qa) are installed) with: `qa/pull-tester/rpc-tests.py`

The Travis CI system makes sure that every pull request is built for Windows
and Linux, OS X, and that unit and sanity tests are automatically run.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.

### MacOS SDK

cd depends  
wget https://github.com/phracker/MacOSX-SDKs/releases/download/10.13/MacOSX10.11.sdk.tar.xz  
tar vxf MacOSX10.11.sdk.tar.xz  
make HOST=x86_64-apple-darwin11 SDK_PATH=$PWD -j8  
