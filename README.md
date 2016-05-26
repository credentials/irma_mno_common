# IRMA MNO common

This library contains the java classes used in the communication protocol between the
card emulator application and the MNO server.

## Prerequisites

This library has the following dependencies.  All these dependencies will be automatically downloaded by gradle when building or installing the library (except for cert-cvc, which is included).

Internal dependencies:

 * [irma_api_common](https://github.com/credentials), for the issuing and verification messages

External dependencies:

 * [JMRTD](https://sourceforge.net/projects/jmrtd/), for communicating with passports (Machine Readable Travel Documents)
 * [cert-cvc](https://www.ejbca.org/)

## Building using Gradle (recommended)

When you are using the Gradle build system, just run

    gradle install

to install the library to your local repository. Alternatively, you can run

    gradle build

to just build the library.

## Eclipse development files

You can run

    gradle eclipse

to create the required files for importing the project into Eclipse.
