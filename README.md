Azart Core staging tree 0.12.4.3
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
- Dexas: https://dex.as/market/DEXAS.AZART_DEXAS.BTC

###### Nodes:  
- addnode=5.9.6.17:9799
- addnode=5.188.63.139:9799
- addnode=5.188.63.138:9799
- addnode=5.188.63.137:9799
- addnode=5.188.63.136:9799
- addnode=5.188.63.135:9799
- addnode=5.188.63.131:9799
- addnode=5.188.63.130:9799
- addnode=5.188.63.129:9799
- addnode=5.188.63.128:9799
- addnode=5.188.63.113:9799
- addnode=5.188.63.104:9799
- addnode=5.188.63.96:9799
- addnode=37.9.52.67:9799
- addnode=37.9.52.66:9799
- addnode=37.9.52.65:9799
- addnode=37.9.52.64:9799
- addnode=37.9.52.63:9799
- addnode=37.9.52.62:9799
- addnode=37.9.52.60:9799
- addnode=37.9.52.59:9799
- addnode=37.9.52.56:9799
- addnode=37.9.52.55:9799
- addnode=37.9.52.54:9799
- addnode=37.9.52.52:9799
- addnode=37.9.52.51:9799
- addnode=37.9.52.50:9799
- addnode=37.9.52.49:9799
- addnode=37.9.52.48:9799
- addnode=37.9.52.47:9799
- addnode=37.9.52.46:9799
- addnode=37.9.52.18:9799
- addnode=5.188.205.240:9799
- addnode=5.188.205.239:9799

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
